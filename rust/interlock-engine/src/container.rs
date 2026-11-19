// SPDX-License-Identifier: Apache-2.0

//! Bounded, in-memory archive inspection. The shared vectors cover truncated
//! ZIP, ZIP data descriptors, encrypted members, gzip multistream and trailer
//! handling, zlib trailer handling, and byte cutoffs. ZIP64 and trailing ZIP
//! bytes depend on the zip crate's central directory parser. The tar crate
//! stops at the first zero block, while Go checks the next block if present.
//! Compressed readers can disagree with Go about whether EOF or corruption
//! coincides with the last bytes when a read fills the byte budget.

use flate2::{bufread::MultiGzDecoder, Decompress, FlushDecompress, Status};
use std::{
    io::{Cursor, Read},
    time::{Duration, Instant},
};
use zip::{result::ZipError, CompressionMethod, ZipArchive};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerLimits {
    pub enabled: bool,
    pub max_decompressed_bytes: isize,
    pub max_descent_depth: isize,
    pub max_parts: isize,
    pub max_inspect: Duration,
}

pub fn default_container_limits() -> ContainerLimits {
    ContainerLimits {
        enabled: true,
        max_decompressed_bytes: 10 * 1024 * 1024,
        max_descent_depth: 2,
        max_parts: 100,
        max_inspect: Duration::from_millis(50),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ContainerAbortReason {
    #[default]
    None,
    MaxDecompressedBytes,
    MaxDescentDepth,
    MaxParts,
    MaxInspectMs,
    Encrypted,
    Corrupt,
}

impl ContainerAbortReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::MaxDecompressedBytes => "max_decompressed_bytes",
            Self::MaxDescentDepth => "max_descent_depth",
            Self::MaxParts => "max_parts",
            Self::MaxInspectMs => "max_inspect_ms",
            Self::Encrypted => "encrypted",
            Self::Corrupt => "corrupt",
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ContainerInspectResult {
    pub parts: Vec<Vec<u8>>,
    pub abort: ContainerAbortReason,
    pub bytes: usize,
    pub parts_n: usize,
}

enum Kind {
    Zip,
    Gzip,
    Zlib,
    Tar,
}

fn detect(raw: &[u8]) -> Option<Kind> {
    match raw {
        [b'P', b'K', 3, 4, ..] => Some(Kind::Zip),
        [0x1f, 0x8b, ..] => Some(Kind::Gzip),
        [0x78, 0x01 | 0x9c | 0xda, ..] => Some(Kind::Zlib),
        _ if raw.len() >= 512 && &raw[257..262] == b"ustar" => Some(Kind::Tar),
        _ => None,
    }
}

pub fn looks_like_container(raw: &[u8]) -> bool {
    detect(raw).is_some()
}

pub fn inspect_container(raw: &[u8], limits: &ContainerLimits) -> ContainerInspectResult {
    if !limits.enabled || !looks_like_container(raw) {
        return ContainerInspectResult::default();
    }
    let defaults = default_container_limits();
    let positive_or = |value, default| if value > 0 { value } else { default } as usize;
    let mut walker = Walker {
        result: ContainerInspectResult::default(),
        max_bytes: positive_or(
            limits.max_decompressed_bytes,
            defaults.max_decompressed_bytes,
        ),
        max_depth: positive_or(limits.max_descent_depth, defaults.max_descent_depth),
        max_parts: positive_or(limits.max_parts, defaults.max_parts),
        started: Instant::now(),
        max_inspect: if limits.max_inspect.is_zero() {
            defaults.max_inspect
        } else {
            limits.max_inspect
        },
    };
    let _ = walker.walk(raw, 0);
    walker.result
}

use ContainerAbortReason as Abort;

struct Walker {
    result: ContainerInspectResult,
    max_bytes: usize,
    max_depth: usize,
    max_parts: usize,
    started: Instant,
    max_inspect: Duration,
}

impl Walker {
    fn abort<T>(&mut self, reason: Abort) -> Result<T, Abort> {
        self.result.abort = reason;
        Err(reason)
    }

    fn check_time(&mut self) -> Result<(), Abort> {
        if self.started.elapsed() > self.max_inspect {
            return self.abort(Abort::MaxInspectMs);
        }
        Ok(())
    }

    fn walk(&mut self, raw: &[u8], depth: usize) -> Result<(), Abort> {
        self.check_time()?;
        if depth > self.max_depth {
            return self.abort(Abort::MaxDescentDepth);
        }
        match detect(raw) {
            Some(Kind::Zip) => self.walk_zip(raw, depth),
            Some(Kind::Gzip) => {
                let data = self.read_capped(MultiGzDecoder::new(raw), None, false)?;
                self.consider_member(data, depth)
            }
            Some(Kind::Zlib) => {
                let data = self.read_zlib(raw)?;
                self.consider_member(data, depth)
            }
            Some(Kind::Tar) => self.walk_tar(raw, depth),
            None => {
                self.add_bytes(raw.len())?;
                self.keep_text(raw.to_vec());
                Ok(())
            }
        }
    }

    fn add_bytes(&mut self, bytes: usize) -> Result<(), Abort> {
        self.result.bytes += bytes;
        if self.result.bytes > self.max_bytes {
            return self.abort(Abort::MaxDecompressedBytes);
        }
        Ok(())
    }

    fn consider_member(&mut self, data: Vec<u8>, depth: usize) -> Result<(), Abort> {
        if data.is_empty() {
            return Ok(());
        }
        self.add_bytes(data.len())?;
        self.result.parts_n += 1;
        if self.result.parts_n > self.max_parts {
            return self.abort(Abort::MaxParts);
        }
        self.check_time()?;
        if looks_like_container(&data) {
            if depth == self.max_depth {
                return self.abort(Abort::MaxDescentDepth);
            }
            return self.walk(&data, depth + 1);
        }
        self.keep_text(data);
        Ok(())
    }

    fn keep_text(&mut self, data: Vec<u8>) {
        let Ok(text) = std::str::from_utf8(&data) else {
            return;
        };
        let printable = text
            .chars()
            .filter(|&c| matches!(c, '\n' | '\r' | '\t') || (c >= ' ' && c != '\x7f'))
            .count();
        if printable as u128 * 10 >= text.chars().count() as u128 * 8 && !text.trim().is_empty() {
            self.result.parts.push(data);
        }
    }

    fn remain_budget(&self) -> usize {
        self.max_bytes - self.result.bytes + 1
    }

    fn read_capped(
        &mut self,
        mut reader: impl Read,
        expected_size: Option<u64>,
        eof_with_data: bool,
    ) -> Result<Vec<u8>, Abort> {
        let remain = self.remain_budget();
        let mut chunk = [0; 32 << 10];
        let mut data = Vec::with_capacity(remain.min(chunk.len()));
        while data.len() < remain {
            self.check_time()?;
            let want = (remain - data.len()).min(chunk.len());
            match reader.read(&mut chunk[..want]) {
                Ok(0) if expected_size.is_none_or(|size| size == data.len() as u64) => {
                    return Ok(data);
                }
                Ok(0) | Err(_) => return self.abort(Abort::Corrupt),
                Ok(n) => data.extend_from_slice(&chunk[..n]),
            }
            if let Some(size) = expected_size {
                if data.len() as u64 > size {
                    return self.abort(Abort::Corrupt);
                }
                if eof_with_data && data.len() == remain && data.len() as u64 == size {
                    // Go can report EOF alongside the final bytes. Drive the
                    // reader through EOF to validate a deflated member's CRC.
                    return match reader.read(&mut chunk[..1]) {
                        Ok(0) => Ok(data),
                        _ => self.abort(Abort::Corrupt),
                    };
                }
            }
        }
        self.abort(Abort::MaxDecompressedBytes)
    }

    fn read_zlib(&mut self, raw: &[u8]) -> Result<Vec<u8>, Abort> {
        let remain = self.remain_budget();
        let mut chunk = [0; 32 << 10];
        let mut data = Vec::with_capacity(remain.min(chunk.len()));
        let mut decoder = Decompress::new(true);
        while data.len() < remain {
            self.check_time()?;
            let want = (remain - data.len()).min(chunk.len());
            let offset = decoder.total_in() as usize;
            let status =
                decoder.decompress(&raw[offset..], &mut chunk[..want], FlushDecompress::None);
            let n = decoder.total_out() as usize - data.len();
            match status {
                Ok(Status::StreamEnd) => {
                    data.extend_from_slice(&chunk[..n]);
                    return Ok(data);
                }
                Ok(_) if n > 0 => data.extend_from_slice(&chunk[..n]),
                _ => return self.abort(Abort::Corrupt),
            }
        }
        self.abort(Abort::MaxDecompressedBytes)
    }

    fn walk_zip(&mut self, raw: &[u8], depth: usize) -> Result<(), Abort> {
        let Ok(mut archive) = ZipArchive::new(Cursor::new(raw)) else {
            return self.abort(Abort::Corrupt);
        };
        for index in 0..archive.len() {
            self.check_time()?;
            // Read central directory flags and mode before opening the decoder.
            let Ok(member) = archive.by_index_raw(index) else {
                return match archive.by_index(index) {
                    Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => {
                        self.abort(Abort::Encrypted)
                    }
                    _ => self.abort(Abort::Corrupt),
                };
            };
            let flags = member.central_header_start().checked_add(8);
            let Some(&flags) = flags
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| raw.get(offset))
            else {
                return self.abort(Abort::Corrupt);
            };
            if flags & 1 != 0 {
                return self.abort(Abort::Encrypted);
            }
            if member.name_raw().ends_with(b"/")
                || member
                    .unix_mode()
                    .is_some_and(|mode| mode & 0o170000 == 0o040000)
            {
                continue;
            }
            let size = member.size();
            let deflated = member.compression() == CompressionMethod::Deflated;
            let descriptor = member.data_start().checked_add(member.compressed_size());
            let crc = member.crc32();
            drop(member);
            let Ok(member) = archive.by_index(index) else {
                return self.abort(Abort::Corrupt);
            };
            let data = self.read_capped(member, Some(size), deflated)?;
            if flags & 8 != 0 && !valid_zip_descriptor(raw, descriptor, crc) {
                return self.abort(Abort::Corrupt);
            }
            self.consider_member(data, depth)?;
        }
        Ok(())
    }

    fn walk_tar(&mut self, raw: &[u8], depth: usize) -> Result<(), Abort> {
        let mut archive = tar::Archive::new(raw);
        let Ok(mut entries) = archive.entries() else {
            return self.abort(Abort::Corrupt);
        };
        loop {
            self.check_time()?;
            match entries.next() {
                None => return Ok(()),
                Some(Err(_)) => return self.abort(Abort::Corrupt),
                Some(Ok(entry)) => {
                    // Tar maps both NUL and ASCII zero to EntryType::Regular.
                    // Go treats a NUL type with a trailing slash as a directory.
                    let kind = entry.header().as_bytes()[156];
                    if !matches!(kind, 0 | b'0')
                        || (kind == 0 && entry.path_bytes().ends_with(b"/"))
                    {
                        continue;
                    }
                    let size = entry.size();
                    let data = self.read_capped(entry, Some(size), true)?;
                    self.consider_member(data, depth)?;
                }
            }
        }
    }
}

fn valid_zip_descriptor(raw: &[u8], offset: Option<u64>, crc: u32) -> bool {
    let Some(raw) = offset
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| raw.get(n..))
    else {
        return false;
    };
    let descriptor = raw.strip_prefix(b"PK\x07\x08").unwrap_or(raw);
    // Go checks the CRC and requires both size fields, but uses the sizes
    // from the central directory (including for ZIP64 members).
    descriptor.len() >= 12 && descriptor.starts_with(&crc.to_le_bytes())
}
