//! Dispatch Tower services on the host that drives the native HTTP exchange.

use core::fmt;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll, ready};

use bytes::Buf;
pub use bytes::Bytes;
pub use http_body::{Body, Frame, SizeHint};
pub use tower_service::Service;

use super::{Adapter, HeaderMap, Request};
use crate::body::{Outcome, Part, Trailers};
use crate::buffer::Lease;
use crate::drive::{Error, Kind};
use crate::h2::message;
use crate::message::RequestHead;

/// The native input of a Tower request. A pending read registers the task's waker with the host.
pub trait ReadBody {
    /// Polls for a native region or its terminal outcome. A pending read keeps its place until the next poll or drop.
    fn poll_part(&mut self, cx: &mut Context<'_>) -> Poll<Result<Part, Error>>;
}

impl<F: FnMut(&mut Context<'_>) -> Poll<Result<Part, Error>>> ReadBody for F {
    fn poll_part(&mut self, cx: &mut Context<'_>) -> Poll<Result<Part, Error>> {
        self(cx)
    }
}

/// A native request body viewed as HTTP data and trailer frames.
pub struct RequestBody<R> {
    reader: R,
    adapter: Adapter,
    remaining: Option<u64>,
    ended: bool,
}

impl<R> fmt::Debug for RequestBody<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestBody")
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

/// The cause of an interrupted read. A reset keeps the peer's protocol code.
#[derive(Clone, Copy, Debug)]
pub enum BodyError {
    /// The peer reset the stream or connection.
    Reset(Option<u64>),
    /// Input ended before the declared body did.
    Truncated,
    /// The application cancelled the read.
    Cancelled,
    /// The peer broke the framing rules.
    Malformed,
    /// The host or the conversion refused the operation.
    Native(Error),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Reset(_) => "the peer reset the request body",
            Self::Truncated => "the request body ended early",
            Self::Cancelled => "the request body was cancelled",
            Self::Malformed => "the request body has invalid framing",
            Self::Native(error) => return error.fmt(f),
        })
    }
}

impl core::error::Error for BodyError {}

impl<R: ReadBody + Unpin> Body for RequestBody<R> {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let part = ready!(self.reader.poll_part(cx));
        self.ended = !matches!(part, Ok(Part::Data(_)));
        let frame = match part {
            Ok(Part::Data(bytes)) => {
                self.remaining = self.remaining.map(|n| n.saturating_sub(bytes.as_ref().len() as u64));
                Ok(Frame::data(Bytes::from_owner(bytes)))
            }
            Ok(Part::End(Outcome::Complete(None))) => return Poll::Ready(None),
            Ok(Part::End(Outcome::Complete(Some(trailers)))) => {
                let backing = Bytes::from_owner(trailers.lines.clone());
                self.adapter
                    .map(trailers.fields(), 0, Some(&backing))
                    .map(Frame::trailers)
                    .map_err(BodyError::Native)
            }
            Ok(Part::End(Outcome::Reset(code))) => Err(BodyError::Reset(code)),
            Ok(Part::End(Outcome::Truncated)) => Err(BodyError::Truncated),
            Ok(Part::End(Outcome::Cancelled)) => Err(BodyError::Cancelled),
            Ok(Part::End(Outcome::Malformed)) => Err(BodyError::Malformed),
            Err(error) => Err(BodyError::Native(error)),
        };
        Poll::Ready(Some(frame))
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        if self.ended {
            SizeHint::with_exact(0)
        } else {
            self.remaining.map_or_else(SizeHint::new, SizeHint::with_exact)
        }
    }
}

/// Waits for readiness and calls the same service instance exactly once.
/// The host owns the call future and the returned response body.
pub async fn dispatch<S: Service<Request<B>>, B>(service: &mut S, request: Request<B>) -> Result<S::Response, Error> {
    poll_fn(|cx| service.poll_ready(cx))
        .await
        .map_err(|_| Error::new(Kind::Overload, "the service refused readiness"))?;
    service
        .call(request)
        .await
        .map_err(|_| Error::new(Kind::Partial, "the service failed before its response"))
}

const ROOM: Error = Error::new(Kind::Overload, "the response frame exceeds the available memory budget");
const BAD_FRAME: Error = Error::new(Kind::Malformed, "the response body has an invalid frame sequence");
const INTERRUPTED: Error = Error::new(Kind::Partial, "the response producer failed");

/// A pinned Tower response producer viewed as a native streaming body.
pub struct ResponseBody<'a, B> {
    adapter: &'a Adapter,
    source: Pin<&'a mut B>,
    trailers: Option<Trailers>,
}

impl<B> fmt::Debug for ResponseBody<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseBody").finish_non_exhaustive()
    }
}

impl<B: Body> super::Body for ResponseBody<'_, B> {
    fn length(&self) -> Option<u64> {
        self.source.size_hint().exact()
    }

    async fn next(&mut self) -> Result<Part, Error> {
        if self.trailers.is_none() {
            let Some(frame) = poll_fn(|cx| self.source.as_mut().poll_frame(cx)).await else {
                return Ok(Part::End(Outcome::Complete(None)));
            };
            let frame = match frame.map_err(|_| INTERRUPTED)?.into_data() {
                Ok(data) => return Ok(Part::Data(self.adapter.tower_data(data)?)),
                Err(frame) => frame,
            };
            self.trailers = Some(
                self.adapter
                    .tower_trailers(frame.into_trailers().map_err(|_| BAD_FRAME)?)?,
            );
        }
        let last = poll_fn(|cx| self.source.as_mut().poll_frame(cx)).await;
        let trailers = self.trailers.take();
        match last {
            None => Ok(Part::End(Outcome::Complete(trailers))),
            Some(Err(_)) => Err(INTERRUPTED),
            Some(Ok(_)) => Err(BAD_FRAME),
        }
    }
}

impl Adapter {
    /// Converts a received request and attaches its host-driven body reader.
    pub fn tower_request<R: ReadBody>(&self, head: &RequestHead, reader: R) -> Result<Request<RequestBody<R>>, Error> {
        self.request(
            head,
            RequestBody {
                reader,
                adapter: self.clone(),
                remaining: head.length(),
                ended: false,
            },
        )
    }

    /// Adapts the response producer for a native writer. Pin it in the handler that owns the exchange.
    pub fn tower_body<'a, B: Body>(&'a self, source: Pin<&'a mut B>) -> ResponseBody<'a, B> {
        ResponseBody {
            adapter: self,
            source,
            trailers: None,
        }
    }

    fn tower_trailers(&self, trailers: HeaderMap) -> Result<Trailers, Error> {
        let fields = self.fields(&trailers)?;
        let len = fields
            .as_slice()
            .iter()
            .try_fold(0usize, |size, field| {
                size.checked_add(field.name().len())?
                    .checked_add(field.value().len())?
                    .checked_add(4)
            })
            .filter(|&n| n <= self.limits.head_bytes)
            .ok_or(ROOM)?;
        let (mut bytes, charge) = message::region(len, &self.budget).ok_or(ROOM)?;
        for field in fields.as_slice() {
            for part in [field.name(), b": ", field.value(), b"\r\n"] {
                bytes.extend_from_slice(part);
            }
        }
        Ok(Trailers {
            lines: message::charged(bytes, charge),
        })
    }

    fn tower_data(&self, mut data: impl Buf) -> Result<Lease, Error> {
        let len = data.remaining();
        if len == 0 {
            return Ok(Lease::from(&[][..]));
        }
        // A segmented Buf can allocate when it joins its chunks. Admit that storage first.
        let charge = message::lease_charge(len, &self.budget).ok_or(ROOM)?;
        let bytes = data.copy_to_bytes(len);
        drop(data);
        if bytes.is_unique() {
            let vec = Vec::from(bytes);
            if vec.capacity() == len {
                return Ok(message::charged(vec, charge));
            }
            drop(charge);
            if let Some(full) = message::lease_charge(vec.capacity(), &self.budget) {
                return Ok(message::charged(vec, full));
            }
            let (mut owned, charge) = message::region(len, &self.budget).ok_or(ROOM)?;
            owned.extend_from_slice(&vec);
            return Ok(message::charged(owned, charge));
        }
        // A shared slice can pin an allocation of unknown size. Admit only its visible bytes.
        let mut owned = Vec::new();
        owned.try_reserve_exact(len).map_err(|_| ROOM)?;
        owned.extend_from_slice(&bytes);
        Ok(message::charged(owned, charge))
    }
}
