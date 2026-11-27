//! Allocation and byte contracts of the optional HTTP boundary.
#![cfg(feature = "http")]

mod counting;

use core::num::NonZeroU64;
use rsnetwork::capacity::Budget;
use rsnetwork::drive::Kind;
use rsnetwork::h1::Limits;
use rsnetwork::http::{Adapter, HeaderMap, Method, Request, Response, StatusCode, Uri, Version, header};
use rsnetwork::value::{self, Field, Status, Target};

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(4096).unwrap())
}

#[test]
fn http_conversion_charges_descriptors_and_borrows_the_original_field_bytes() {
    let memory = budget();
    let adapter = Adapter::new(LIMITS, &memory);
    let method = value::Method::new(b"mIx-Verb").unwrap();
    let (external, allocs) = counting::allocations(|| Method::try_from(method).unwrap());
    assert_eq!((external.as_str(), allocs), ("mIx-Verb", 0));
    let (method, allocs) = counting::allocations(|| value::Method::try_from(&external).unwrap());
    assert_eq!((method.as_bytes(), allocs), (&b"mIx-Verb"[..], 0));
    let long = value::Method::new(b"Long-Extension-Method").unwrap();
    let (converted, allocs) = counting::allocations(|| Method::try_from(long).unwrap());
    assert_eq!((converted.as_str(), allocs), ("Long-Extension-Method", 1));
    let (code, allocs) = counting::allocations(|| StatusCode::try_from(Status::new(418).unwrap()).unwrap());
    assert_eq!((Status::try_from(code).unwrap().code(), allocs), (418, 0));
    Status::try_from(StatusCode::from_u16(601).unwrap()).unwrap_err();

    let fields = [
        Field::new(b"Accept", b"text/plain").unwrap(),
        Field::new(b"accept", &[0x80]).unwrap(),
    ];
    let (headers, copies) = counting::allocations(|| adapter.headers(&fields).unwrap());
    assert_eq!(
        headers
            .get_all(header::ACCEPT)
            .iter()
            .map(header::HeaderValue::as_bytes)
            .collect::<Vec<_>>(),
        [b"text/plain".as_slice(), &[0x80]]
    );
    assert_ne!(headers[header::ACCEPT].as_bytes().as_ptr(), fields[0].value().as_ptr());
    let (view, allocs) = counting::allocations(|| adapter.fields(&headers).unwrap());
    assert_eq!(allocs, 1);
    assert_eq!(
        view.as_slice()[0].value().as_ptr(),
        headers[header::ACCEPT].as_bytes().as_ptr()
    );
    assert_eq!(
        memory.bound() - memory.available(),
        (fields.len() * size_of::<Field<'_>>()) as u64
    );
    drop(view);
    assert_eq!(memory.available(), memory.bound());
    assert_eq!(copies, 5, "two map arrays, an extra-value array, and two value copies");

    for raw in ["/p%2f//?", "*", "[::1]:443", "https://Example.test/x%2Fy?q=&q="] {
        let target = Target::new(raw.as_bytes()).unwrap();
        let (uri, forward) = counting::allocations(|| Uri::try_from(target).unwrap());
        assert_eq!(forward, if uri.scheme().is_some() { 2 } else { 1 }, "{raw}");
        let (native, allocs) = counting::allocations(|| adapter.target(&uri).unwrap());
        assert_eq!(native.target().as_bytes(), raw.as_bytes());
        assert_eq!(allocs, u64::from(uri.scheme().is_some()));
    }
    Uri::try_from(Target::new(b"HTTP://Example.test").unwrap()).unwrap_err();
}

#[test]
fn http_conversion_refuses_ambiguous_framing_and_unrepresentable_values_before_send() {
    let memory = budget();
    let adapter = Adapter::new(LIMITS, &memory);
    let mut request = Request::builder()
        .method("pAtCh")
        .uri("/a%2fb?")
        .header("host", "a.test")
        .header("content-length", "3")
        .header("content-length", "3")
        .body(())
        .unwrap();
    let (view, allocs) = counting::allocations(|| adapter.native_request(&request, None).unwrap());
    assert_eq!(allocs, 1);
    assert_eq!(view.head().length, Some(3));
    assert_eq!(view.head().method.as_bytes(), b"pAtCh");
    assert_eq!(view.head().target.as_bytes(), b"/a%2fb?");
    assert!(view.head().fields.is_empty());
    drop(view);
    request
        .headers_mut()
        .append(header::CONTENT_LENGTH, header::HeaderValue::from_static("2"));
    assert_eq!(adapter.native_request(&request, None).unwrap_err().kind(), Kind::Misuse);
    request.headers_mut().remove(header::CONTENT_LENGTH);
    request
        .headers_mut()
        .insert(header::TRANSFER_ENCODING, header::HeaderValue::from_static("chunked"));
    request
        .headers_mut()
        .insert(header::CONTENT_LENGTH, header::HeaderValue::from_static("3"));
    assert_eq!(adapter.native_request(&request, None).unwrap_err().kind(), Kind::Misuse);
    request.headers_mut().remove(header::CONTENT_LENGTH);
    *request.version_mut() = Version::HTTP_2;
    assert_eq!(adapter.native_request(&request, None).unwrap_err().kind(), Kind::Misuse);
    request.headers_mut().remove(header::TRANSFER_ENCODING);
    *request.uri_mut() = Uri::from_static("https://other.test/resource");
    assert_eq!(adapter.native_request(&request, None).unwrap_err().kind(), Kind::Misuse);

    let mut response = Response::builder()
        .status(201)
        .header("set-cookie", "a=1")
        .header("set-cookie", "b=2")
        .body(())
        .unwrap();
    let (view, allocs) = counting::allocations(|| adapter.native_response(&response, Some(0)).unwrap());
    assert_eq!(allocs, 1);
    assert_eq!(view.head().status.code(), 201);
    assert_eq!(
        view.head().fields.iter().map(Field::value).collect::<Vec<_>>(),
        [b"a=1", b"b=2"]
    );
    drop(view);
    response
        .headers_mut()
        .insert("x-secret", header::HeaderValue::from_static("private"));
    response.headers_mut().get_mut("x-secret").unwrap().set_sensitive(true);
    assert_eq!(
        adapter.native_response(&response, None).unwrap_err().kind(),
        Kind::Unsupported
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-header", header::HeaderValue::from_static(" leading"));
    assert_eq!(adapter.fields(&headers).unwrap_err().kind(), Kind::Misuse);
    let limited = Adapter::new(Limits { fields: 1, ..LIMITS }, &memory);
    assert_eq!(limited.fields(response.headers()).unwrap_err().kind(), Kind::Overload);
    let tiny = Adapter::new(LIMITS, &Budget::new(NonZeroU64::MIN));
    assert_eq!(tiny.fields(&headers).unwrap_err().kind(), Kind::Overload);
    assert_eq!(memory.available(), memory.bound());
}
