use cog::git::pack::*;
use std::io::Write;

#[test]
fn empty_pack_finishes_after_its_trailer() {
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    bytes.extend_from_slice(&[0; 20]);
    let mut parser = ReceivePackBoundary::default();
    assert!(parser.push(&bytes).unwrap());
}

#[test]
fn detects_a_streamed_pack_without_buffering_it() {
    let mut compressed = Vec::new();
    {
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::fast());
        encoder.write_all(b"hello").unwrap();
        encoder.finish().unwrap();
    }
    let mut bytes = b"0000PACK\0\0\0\x02\0\0\0\x01".to_vec();
    bytes.push(0x35);
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&[0; 20]);
    let mut parser = ReceivePackBoundary::default();
    for chunk in bytes.chunks(3) {
        let complete = parser.push(chunk).unwrap();
        if chunk.as_ptr_range().end == bytes.as_ptr_range().end {
            assert!(complete);
        }
    }
}

#[test]
fn accepts_zlib_progress_that_only_produces_output() {
    let payload = vec![b'x'; 128 * 1024];
    let mut compressed = Vec::new();
    {
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        encoder.finish().unwrap();
    }
    let mut bytes = b"0000PACK\0\0\0\x02\0\0\0\x01".to_vec();
    let mut size = payload.len();
    bytes.push(0x30 | ((size & 0x0f) as u8) | 0x80);
    size >>= 4;
    while size >= 0x80 {
        bytes.push((size as u8 & 0x7f) | 0x80);
        size >>= 7;
    }
    bytes.push(size as u8);
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&[0; 20]);

    let mut parser = ReceivePackBoundary::default();
    assert!(parser.push(&bytes).unwrap());
}

#[test]
fn ref_delta_base_object_id_precedes_zlib_stream() {
    let mut compressed = Vec::new();
    {
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::fast());
        encoder.write_all(b"delta").unwrap();
        encoder.finish().unwrap();
    }
    let mut bytes = b"0000PACK\0\0\0\x02\0\0\0\x01".to_vec();
    bytes.push(0x75); // REF_DELTA, uncompressed size 5.
    bytes.extend_from_slice(&[0x42; 20]);
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&[0; 20]);

    let mut parser = ReceivePackBoundary::default();
    for chunk in bytes.chunks(3) {
        let complete = parser.push(chunk).unwrap();
        if chunk.as_ptr_range().end == bytes.as_ptr_range().end {
            assert!(complete);
        }
    }
}
