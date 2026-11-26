//! One connection of the core that many handles share: the streams of an HTTP/2 connection, each
//! in a task of its own.
//!
//! Each call of a handle turns the connection under a short lock, which no wait holds. One of the
//! handles that wait, the driver, also waits for the socket and the clock. After each turn, the
//! core gives the streams that changed, and only their handles wake: no task, no channel, and no
//! copy. The call of another handle can give the connection an event that the driver does not
//! wait for, such as an earlier deadline, output for the socket, or a reset after a cancel. Then
//! the driver wakes, and waits again for each event of the connection. A handle that waits for a
//! place of the connection, a new stream or a head region, waits in order, and only the first
//! wakes when the connection moves.

use core::future::poll_fn;
use core::mem::DropGuard;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker, ready};
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rsnetwork::drive::Error;
use rsnetwork::host::{Io, Wait};
use rsnetwork::message::Stream;
use rsnetwork::time::Instant;
use tokio::task::coop;
use tokio::time::Sleep;

use crate::socket::{Interest, Socket, Turn};

/// A connection of the core that tells which streams changed.
pub(crate) trait Streams: Io {
    /// Gives each stream that changed since the last call.
    fn changed(&mut self, each: impl FnMut(Stream));
}

impl Streams for rsnetwork::client::Http2 {
    fn changed(&mut self, each: impl FnMut(Stream)) {
        Self::changed(self, each);
    }
}

impl Streams for rsnetwork::server::Http {
    fn changed(&mut self, each: impl FnMut(Stream)) {
        Self::changed(self, each);
    }
}

/// What the call of a handle waits for when it gives `None`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Waits {
    /// A change of its stream.
    Stream(Stream),
    /// A place that the handles take in their order, such as a new stream, a head region, or
    /// room in the output, or a change of its stream.
    Place(Option<Stream>),
    /// A change of the connection: a new request, a release, or its end.
    Connection,
}

/// One connection of the core on one socket, which many handles share.
#[derive(Debug)]
pub(crate) struct Shared<C: Io> {
    state: Mutex<State<C>>,
}

/// The connection and the handles that wait for it.
#[derive(Debug)]
pub(crate) struct State<C: Io> {
    pub(crate) socket: Socket<C>,
    /// The wait that also waits for the socket and the clock.
    driver: Option<Driver>,
    /// The key of the next wait.
    next: u64,
    /// The waits for a change of their stream, with their keys. One handle has each stream.
    streams: Vec<(Stream, u64, Waker)>,
    /// The waits for a place, in their order.
    places: VecDeque<(u64, Waker)>,
    /// The waits for a change of the connection.
    watchers: Vec<(u64, Waker)>,
    /// The connection ended, and each wait woke.
    ended: bool,
}

/// The wait that also waits for the socket and the clock.
#[derive(Debug)]
struct Driver {
    key: u64,
    waker: Waker,
    /// What its last turn waits for, or `None` after a wake that makes it turn again.
    armed: Option<Interest>,
}

/// What one turn of a wait did.
enum Step<T> {
    Ready(Result<Option<T>, Error>),
    /// Turn again after the cooperative budget of the task.
    Now,
    /// Turn again at once: the socket or the clock is ready.
    Again,
    Pending,
}

impl<C: Streams> Shared<C> {
    pub(crate) fn new(socket: Socket<C>) -> Self {
        Self {
            state: Mutex::new(State {
                socket,
                driver: None,
                next: 0,
                streams: Vec::new(),
                places: VecDeque::new(),
                watchers: Vec::new(),
                ended: false,
            }),
        }
    }

    /// The connection and its waits, for a call that does not wait. Release the lock before a
    /// wait.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State<C>> {
        // A panic is a defect. The other handles go on from the state that it left, as the next
        // call of one handle would.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `change`, a call that changes more than one stream, such as a cancel, a close, or a
    /// shutdown, and then wakes each handle that waits for a place or for the connection.
    pub(crate) fn change<T>(&self, change: impl FnOnce(&mut C) -> T) -> T {
        let mut wakes = Vec::new();
        let result = {
            let mut state = self.lock();
            let result = change(state.socket.connection_mut());
            // No wait has the key 0.
            state.changes(0, &mut wakes);
            state.moved(None, &mut wakes);
            state.vacate(&mut wakes);
            // The change can leave work for a drive, for example a reset to send.
            state.rearm(None, &mut wakes);
            result
        };
        wakes.into_iter().for_each(Waker::wake);
        result
    }

    /// Calls `call` with the time now until it gives a value, as [`Socket::until`] does, for one
    /// of the handles of the connection. When it gives `None`, the handle waits for `waits`.
    pub(crate) async fn until<T>(
        &self,
        waits: Waits,
        mut call: impl FnMut(&mut C, Instant) -> Result<Option<T>, Error>,
    ) -> Result<Option<T>, Error> {
        let key = {
            let mut state = self.lock();
            state.next = state.next.wrapping_add(1);
            state.next
        };
        // A wait that drops, also in a cancel, leaves its place, and gives its drive on.
        let _leave = DropGuard::new((), |()| {
            let mut wakes = Vec::new();
            self.lock().leave(key, &mut wakes);
            wakes.into_iter().for_each(Waker::wake);
        });
        let mut sleep = pin!(None);
        let mut queued = false;
        poll_fn(|cx| {
            loop {
                let mut wakes = Vec::new();
                let step = self
                    .lock()
                    .turn(cx, (key, waits, &mut queued), &mut call, sleep.as_mut(), &mut wakes);
                // Each handle wakes after the lock, so no waker runs inside the connection.
                wakes.into_iter().for_each(Waker::wake);
                match step {
                    Step::Ready(result) => return Poll::Ready(result),
                    Step::Pending => return Poll::Pending,
                    Step::Now => ready!(coop::poll_proceed(cx)).made_progress(),
                    Step::Again => {}
                }
            }
        })
        .await
    }
}

impl<C: Streams> State<C> {
    /// One turn of the wait `key`.
    fn turn<T>(
        &mut self,
        cx: &mut Context<'_>,
        (key, waits, queued): (u64, Waits, &mut bool),
        call: &mut impl FnMut(&mut C, Instant) -> Result<Option<T>, Error>,
        sleep: Pin<&mut Option<Sleep>>,
        wakes: &mut Vec<Waker>,
    ) -> Step<T> {
        let turn = self.socket.turn(call);
        let changed = self.changes(key, wakes);
        match turn {
            Err(error) => {
                self.leave(key, wakes);
                Step::Ready(Err(error))
            }
            Ok(Turn::Done(value, after)) => {
                // A place that a handle took can leave room for the next, and a stream that
                // ended can free a place.
                if value.is_some() && !matches!(waits, Waits::Connection) {
                    self.wake_place(key, wakes);
                }
                self.leave(key, wakes);
                self.rearm(after, wakes);
                Step::Ready(Ok(value))
            }
            Ok(Turn::Now) => {
                self.moved(Some(key), wakes);
                Step::Now
            }
            Ok(Turn::Wait(interest)) => {
                if changed {
                    self.moved(Some(key), wakes);
                }
                self.enter(key, waits, queued, cx.waker());
                if self.driver.as_ref().is_some_and(|driver| driver.key != key) {
                    self.rearm(Some(interest), wakes);
                    return Step::Pending;
                }
                self.driver = Some(Driver {
                    key,
                    waker: cx.waker().clone(),
                    armed: Some(interest),
                });
                if self.socket.ready(cx, interest, sleep) {
                    return Step::Again;
                }
                Step::Pending
            }
        }
    }

    /// Wakes the handle of each stream that changed, other than `key`, and each handle at the end
    /// of the connection. Gives whether a stream changed.
    fn changes(&mut self, key: u64, wakes: &mut Vec<Waker>) -> bool {
        let mut changed = false;
        let streams = &mut self.streams;
        self.socket.connection_mut().changed(|stream| {
            changed = true;
            if let Some(index) = streams.iter().position(|&(waiting, ..)| waiting == stream) {
                let (_, waiter, waker) = streams.swap_remove(index);
                if waiter != key {
                    wakes.push(waker);
                }
            }
        });
        let end = matches!(self.socket.connection().wait(), Wait::Ended(_) | Wait::Linger { .. });
        if end && !self.ended {
            self.ended = true;
            wakes.extend(self.streams.drain(..).map(|(.., waker)| waker));
            wakes.extend(self.places.drain(..).map(|(_, waker)| waker));
            wakes.extend(self.watchers.drain(..).map(|(_, waker)| waker));
            changed = true;
        }
        changed
    }

    /// The connection moved: wakes each handle that waits for the connection, and the first that
    /// waits for a place, other than `key`.
    fn moved(&mut self, key: Option<u64>, wakes: &mut Vec<Waker>) {
        let others = |&(waiter, _): &(u64, Waker)| Some(waiter) != key;
        wakes.extend(
            self.watchers
                .extract_if(.., |watcher| others(watcher))
                .map(|(_, waker)| waker),
        );
        if let Some(index) = self.places.iter().position(others)
            && let Some((_, waker)) = self.places.remove(index)
        {
            wakes.push(waker);
        }
    }

    /// Wakes the first handle that waits for a place, other than `key`.
    fn wake_place(&mut self, key: u64, wakes: &mut Vec<Waker>) {
        if let Some(index) = self.places.iter().position(|&(waiter, _)| waiter != key)
            && let Some((_, waker)) = self.places.remove(index)
        {
            wakes.push(waker);
        }
    }

    /// Records that the wait `key` waits for `waits`, with `waker`. A wait for a place that woke
    /// keeps its turn: it goes first again.
    fn enter(&mut self, key: u64, waits: Waits, queued: &mut bool, waker: &Waker) {
        let stream = match waits {
            Waits::Stream(stream) => Some(stream),
            Waits::Place(stream) => {
                match self.places.iter_mut().find(|(waiter, _)| *waiter == key) {
                    Some((_, known)) => known.clone_from(waker),
                    None if *queued => self.places.push_front((key, waker.clone())),
                    None => {
                        *queued = true;
                        self.places.push_back((key, waker.clone()));
                    }
                }
                stream
            }
            Waits::Connection => {
                match self.watchers.iter_mut().find(|(waiter, _)| *waiter == key) {
                    Some((_, known)) => known.clone_from(waker),
                    None => self.watchers.push((key, waker.clone())),
                }
                None
            }
        };
        if let Some(stream) = stream {
            match self.streams.iter_mut().find(|(waiting, ..)| *waiting == stream) {
                Some((_, waiter, known)) => {
                    *waiter = key;
                    known.clone_from(waker);
                }
                None => self.streams.push((stream, key, waker.clone())),
            }
        }
    }

    /// The wait `key` ends: it leaves each list, and its drive. When it was in a list or drove
    /// the connection, and no wait drives it then, the next wait wakes to drive it.
    fn leave(&mut self, key: u64, wakes: &mut Vec<Waker>) {
        let waits = self.streams.len() + self.places.len() + self.watchers.len();
        self.streams.retain(|&(_, waiter, _)| waiter != key);
        self.places.retain(|&(waiter, _)| waiter != key);
        self.watchers.retain(|&(waiter, _)| waiter != key);
        let had = waits != self.streams.len() + self.places.len() + self.watchers.len();
        let drove = self.driver.as_ref().is_some_and(|driver| driver.key == key);
        if drove {
            self.driver = None;
        }
        if had || drove {
            self.vacate(wakes);
        }
    }

    /// Wakes the driver when the connection waits for an event that its last turn does not wait
    /// for, or has more work now (`None`). Its next turn waits for each event again.
    fn rearm(&mut self, interest: Option<Interest>, wakes: &mut Vec<Waker>) {
        if let Some(driver) = &mut self.driver
            && let Some(armed) = driver.armed
            && interest.is_none_or(|interest| !armed.covers(interest))
        {
            driver.armed = None;
            wakes.push(driver.waker.clone());
        }
    }

    /// Wakes one wait to drive the connection, when none drives it. The wait keeps its place, so
    /// a wait that drops before it drives wakes the next.
    fn vacate(&self, wakes: &mut Vec<Waker>) {
        if self.driver.is_some() {
            return;
        }
        let next = self
            .streams
            .last()
            .map(|(.., waker)| waker)
            .or_else(|| self.watchers.last().map(|(_, waker)| waker))
            .or_else(|| self.places.front().map(|(_, waker)| waker));
        wakes.extend(next.cloned());
    }
}
