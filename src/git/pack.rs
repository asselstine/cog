//! Incremental, bounded Git PACK boundary detection for receive-pack.

use flate2::{Decompress, FlushDecompress, Status};

const MAX_PREFIX: usize = 64 * 1024;

#[derive(Default)]
pub struct ReceivePackBoundary {
    prefix: Vec<u8>,
    pack: Option<PackParser>,
}

impl ReceivePackBoundary {
    pub fn push(&mut self, bytes: &[u8]) -> anyhow::Result<bool> {
        if let Some(pack) = &mut self.pack {
            return pack.push(bytes);
        }
        self.prefix.extend_from_slice(bytes);
        anyhow::ensure!(
            self.prefix.len() <= MAX_PREFIX,
            "receive-pack command prefix is too large"
        );
        if let Some(offset) = self.prefix.windows(4).position(|window| window == b"PACK") {
            let pack_bytes = self.prefix.split_off(offset);
            self.prefix.clear();
            let mut pack = PackParser::default();
            let complete = pack.push(&pack_bytes)?;
            self.pack = Some(pack);
            Ok(complete)
        } else {
            Ok(false)
        }
    }
}

#[derive(Default)]
struct PackParser {
    header: Vec<u8>,
    remaining_objects: u32,
    object_header: Vec<u8>,
    object_header_complete: bool,
    delta_bytes_remaining: usize,
    offset_delta: bool,
    inflater: Option<Decompress>,
    trailer_remaining: usize,
    done: bool,
}

impl PackParser {
    fn push(&mut self, bytes: &[u8]) -> anyhow::Result<bool> {
        anyhow::ensure!(
            !self.done || bytes.is_empty(),
            "data follows the Git PACK trailer"
        );
        let mut offset = 0;
        while offset < bytes.len() && !self.done {
            if self.header.len() < 12 {
                let take = (12 - self.header.len()).min(bytes.len() - offset);
                self.header.extend_from_slice(&bytes[offset..offset + take]);
                offset += take;
                if self.header.len() == 12 {
                    anyhow::ensure!(&self.header[..4] == b"PACK", "invalid Git PACK signature");
                    let version = u32::from_be_bytes(self.header[4..8].try_into()?);
                    anyhow::ensure!(matches!(version, 2 | 3), "unsupported Git PACK version");
                    self.remaining_objects = u32::from_be_bytes(self.header[8..12].try_into()?);
                    if self.remaining_objects == 0 {
                        self.trailer_remaining = 20;
                    }
                }
                continue;
            }
            if self.trailer_remaining > 0 {
                let take = self.trailer_remaining.min(bytes.len() - offset);
                self.trailer_remaining -= take;
                offset += take;
                if self.trailer_remaining == 0 {
                    self.done = true;
                }
                continue;
            }
            if self.inflater.is_none() {
                while offset < bytes.len()
                    && self.inflater.is_none()
                    && !self.object_header_complete
                {
                    let byte = bytes[offset];
                    offset += 1;
                    if self.object_header.is_empty() {
                        let object_type = (byte >> 4) & 7;
                        anyhow::ensure!(
                            object_type != 0 && object_type != 5,
                            "invalid Git PACK object type"
                        );
                        self.offset_delta = object_type == 6;
                        self.delta_bytes_remaining = if object_type == 7 { 20 } else { 0 };
                    }
                    self.object_header.push(byte);
                    anyhow::ensure!(
                        self.object_header.len() <= 64,
                        "Git PACK object header is too large"
                    );
                    self.object_header_complete = byte & 0x80 == 0;
                }
                if !self.object_header_complete {
                    continue;
                }
                if self.delta_bytes_remaining > 0 {
                    while offset < bytes.len() && self.delta_bytes_remaining > 0 {
                        offset += 1;
                        self.delta_bytes_remaining -= 1;
                    }
                    if self.delta_bytes_remaining == 0 {
                        self.inflater = Some(Decompress::new(true));
                    }
                } else if self.offset_delta {
                    while offset < bytes.len() && self.inflater.is_none() {
                        let byte = bytes[offset];
                        offset += 1;
                        if byte & 0x80 == 0 {
                            self.inflater = Some(Decompress::new(true));
                        }
                    }
                } else {
                    self.inflater = Some(Decompress::new(true));
                }
                continue;
            }
            let inflater = self.inflater.as_mut().expect("checked above");
            let before_in = inflater.total_in();
            let before_out = inflater.total_out();
            let mut discarded = [0_u8; 8192];
            let status =
                inflater.decompress(&bytes[offset..], &mut discarded, FlushDecompress::None)?;
            let consumed = (inflater.total_in() - before_in) as usize;
            let produced = (inflater.total_out() - before_out) as usize;
            anyhow::ensure!(
                consumed > 0 || produced > 0 || status == Status::StreamEnd,
                "invalid Git PACK zlib stream"
            );
            offset += consumed;
            if status == Status::StreamEnd {
                self.inflater = None;
                self.object_header.clear();
                self.object_header_complete = false;
                self.offset_delta = false;
                self.remaining_objects = self.remaining_objects.saturating_sub(1);
                if self.remaining_objects == 0 {
                    self.trailer_remaining = 20;
                }
            }
        }
        anyhow::ensure!(offset == bytes.len(), "data follows the Git PACK trailer");
        Ok(self.done)
    }
}
