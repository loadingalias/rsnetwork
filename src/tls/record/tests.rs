//! The records of RFC 8448, section 3, that use the application traffic keys: the
//! NewSessionTicket and the application data of the server, the application data of the client,
//! and the `close_notify` of each end. Each opens and seals byte for byte at its sequence number.

use rustls::ConnectionTrafficSecrets;
use rustls::crypto::cipher::{AeadKey, Iv};

use super::{Content, Protection, length};

/// The application traffic keys of each end (TLS_AES_128_GCM_SHA256).
const SERVER_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
const SERVER_IV: &str = "cf782b88dd83549aadf1e984";
const CLIENT_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
const CLIENT_IV: &str = "5b78923dee08579033e523d9";

const TICKET: &str = "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400";
const TICKET_RECORD: &str = "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e09c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f";
/// The application data of each end: the bytes 0 to 49.
const CLIENT_DATA_RECORD: &str = "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4";
const SERVER_DATA_RECORD: &str = "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d";
/// The `close_notify` alert of each end: level warning, description 0.
const CLIENT_ALERT_RECORD: &str = "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3";
const SERVER_ALERT_RECORD: &str = "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9";
const CLOSE_NOTIFY: [u8; 2] = [1, 0];

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn protection(key: &str, iv: &str) -> Protection {
    let key: [u8; 16] = hex(key).try_into().unwrap();
    let iv: [u8; 12] = hex(iv).try_into().unwrap();
    let secrets = ConnectionTrafficSecrets::Aes128Gcm {
        key: AeadKey::from(key),
        iv: Iv::from(iv),
    };
    Protection::new(&secrets, 0).unwrap()
}

/// The application traffic keys of one end, and its records in their order from sequence number
/// 0: the content type, the content, and the complete record.
struct End {
    key: &'static str,
    iv: &'static str,
    records: Vec<(Content, Vec<u8>, &'static str)>,
}

fn ends() -> [End; 2] {
    let data: Vec<u8> = (0..50).collect();
    [
        End {
            key: SERVER_KEY,
            iv: SERVER_IV,
            records: vec![
                (Content::Handshake, hex(TICKET), TICKET_RECORD),
                (Content::Data, data.clone(), SERVER_DATA_RECORD),
                (Content::Alert, CLOSE_NOTIFY.to_vec(), SERVER_ALERT_RECORD),
            ],
        },
        End {
            key: CLIENT_KEY,
            iv: CLIENT_IV,
            records: vec![
                (Content::Data, data, CLIENT_DATA_RECORD),
                (Content::Alert, CLOSE_NOTIFY.to_vec(), CLIENT_ALERT_RECORD),
            ],
        },
    ]
}

#[test]
fn the_rfc_8448_application_records_open_at_their_sequence_numbers() {
    for end in ends() {
        let mut protection = protection(end.key, end.iv);
        for (content, plaintext, record) in end.records {
            let mut record = hex(record);
            assert_eq!(length(&record).unwrap(), Some(record.len()));
            let opened = protection.open(&mut record).unwrap();
            assert_eq!(opened.content, content);
            assert_eq!(&record[opened.range], &plaintext[..]);
        }
    }
}

#[test]
fn the_rfc_8448_application_records_seal_byte_for_byte() {
    for end in ends() {
        let mut protection = protection(end.key, end.iv);
        for (content, plaintext, record) in end.records {
            let record = hex(record);
            let mut out = vec![0xaa];
            out.reserve_exact(record.len());
            let capacity = out.capacity();
            // Two parts seal as one record: the parts do not change the bytes.
            let (first, second) = plaintext.split_at(plaintext.len() / 2);
            protection.seal(content, &[first, second], &mut out).unwrap();
            assert_eq!(out[0], 0xaa, "the seal keeps the bytes before the record");
            assert_eq!(&out[1..], &record[..]);
            assert_eq!(out.capacity(), capacity, "the seal writes into the reserved capacity");
        }
    }
}
