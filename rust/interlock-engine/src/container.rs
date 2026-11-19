// SPDX-License-Identifier: Apache-2.0

//! Bounded, in-memory archive inspection. The shared vectors cover truncated
//! ZIP, ZIP data descriptors, encrypted members, gzip multistream and trailer
//! handling, zlib trailer handling, and byte cutoffs. ZIP64 and trailing ZIP
//! bytes depend on the zip crate's central directory parser.
//! Compressed readers can disagree with Go about whether EOF or corruption
//! coincides with the last bytes when a read fills the byte budget.

use flate2::{bufread::MultiGzDecoder, Decompress, FlushDecompress, Status};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    time::{Duration, Instant},
};
use zip::{result::ZipError, CompressionMethod, ZipArchive};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerLimits {
    pub enabled: bool,
    pub max_decompressed_bytes: isize,
    /// Maximum recursive descent. Callers should keep this within their stack budget.
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

    fn read_tar_sparse(
        &mut self,
        entry: &mut impl Read,
        stored_size: u64,
        logical_size: u64,
    ) -> Result<Vec<u8>, Abort> {
        let mut map = Vec::new();
        let mut lines = 0;
        let mut needed = 1;
        while lines < needed {
            self.check_time()?;
            if map.len() == 1 << 20 {
                return self.abort(Abort::Corrupt);
            }
            let mut block = [0; 512];
            if entry.read_exact(&mut block).is_err() {
                return self.abort(Abort::Corrupt);
            }
            lines += block.iter().filter(|&&b| b == b'\n').count();
            map.extend_from_slice(&block);
            if needed == 1 && lines != 0 {
                let count = map.split(|&b| b == b'\n').next().and_then(decimal);
                let Some(count) = count.filter(|&count| count < (1 << 19)) else {
                    return self.abort(Abort::Corrupt);
                };
                needed = 1 + 2 * count as usize;
                // A zero-entry map still occupies one block.
                if needed == 1 {
                    break;
                }
            }
        }
        let mut fields = map.split(|&b| b == b'\n').skip(1);
        let mut end = 0;
        let mut dense_size = 0;
        let mut extents = Vec::new();
        for _ in 0..needed / 2 {
            let (Some(offset), Some(length)) = (
                fields.next().and_then(decimal),
                fields.next().and_then(decimal),
            ) else {
                return self.abort(Abort::Corrupt);
            };
            let Some(next) = offset.checked_add(length) else {
                return self.abort(Abort::Corrupt);
            };
            if offset < end || next > logical_size {
                return self.abort(Abort::Corrupt);
            }
            end = next;
            dense_size += length;
            extents.push((offset, next));
        }

        let limit = logical_size.min(self.remain_budget() as u64);
        let mut data = Vec::new();
        for (offset, end) in extents {
            if offset >= limit {
                break;
            }
            data.resize(offset as usize, 0);
            let end = end.min(limit) as usize;
            while data.len() < end {
                self.check_time()?;
                let start = data.len();
                data.resize(end.min(start + (32 << 10)), 0);
                if entry.read_exact(&mut data[start..]).is_err() {
                    return self.abort(Abort::Corrupt);
                }
            }
        }
        if limit < logical_size {
            return self.abort(Abort::MaxDecompressedBytes);
        }
        if stored_size.checked_sub(map.len() as u64) != Some(dense_size) {
            return self.abort(Abort::Corrupt);
        }
        while data.len() < limit as usize {
            self.check_time()?;
            data.resize((limit as usize).min(data.len() + (32 << 10)), 0);
        }
        Ok(data)
    }

    fn walk_tar(&mut self, raw: &[u8], depth: usize) -> Result<(), Abort> {
        let mut reader = TarReader {
            cursor: Cursor::new(raw),
            header: false,
        };
        let mut archive = tar::Archive::new(&mut reader);
        let Ok(mut entries) = archive.entries_with_seek() else {
            return self.abort(Abort::Corrupt);
        };
        loop {
            self.check_time()?;
            match entries.next() {
                None => break,
                Some(Err(_)) => return self.abort(Abort::Corrupt),
                Some(Ok(mut entry)) => {
                    // Tar maps both NUL and ASCII zero to EntryType::Regular.
                    // Go treats a NUL type with a trailing slash as a directory.
                    let kind = entry.header().as_bytes()[156];
                    if !matches!(kind, 0 | b'0')
                        || (kind == 0 && entry.path_bytes().ends_with(b"/"))
                    {
                        continue;
                    }
                    let size = entry.size();
                    let sparse_size = match pax_sparse_size(&mut entry) {
                        Ok(size) => size,
                        Err(()) => return self.abort(Abort::Corrupt),
                    };
                    let data = if let Some(logical_size) = sparse_size {
                        self.read_tar_sparse(&mut entry, size, logical_size)?
                    } else {
                        self.read_capped(entry, Some(size), true)?
                    };
                    self.consider_member(data, depth)?;
                }
            }
        }
        // The iterator consumes the first zero block. Go accepts EOF here
        // or a second complete zero block, after which it ignores the tail.
        let remaining = &raw[reader.cursor.position() as usize..];
        if remaining.is_empty() || remaining.starts_with(&[0; 512]) {
            Ok(())
        } else {
            self.abort(Abort::Corrupt)
        }
    }
}

struct TarReader<'a> {
    cursor: Cursor<&'a [u8]>,
    header: bool,
}

impl Seek for TarReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let offset = self.cursor.seek(position)?;
        if offset > self.cursor.get_ref().len() as u64 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        // The tar iterator seeks before reading each header, even for a
        // zero-length skip. Payload reads do not seek.
        self.header = true;
        Ok(offset)
    }
}

impl Read for TarReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let n = self.cursor.read(output)?;
        if std::mem::take(&mut self.header) && n == 512 {
            normalize_signed_tar_checksum(&mut output[..n]);
        }
        Ok(n)
    }
}

fn normalize_signed_tar_checksum(header: &mut [u8]) {
    let field = std::str::from_utf8(&header[148..156]).ok().map(|field| {
        field
            .trim_matches([' ', '\0'])
            .split('\0')
            .next()
            .unwrap_or_default()
    });
    let Some(stored) = field.and_then(|field| u32::from_str_radix(field, 8).ok()) else {
        return;
    };
    let mut signed = 8 * 32;
    let mut unsigned = signed;
    for &byte in header[..148].iter().chain(&header[156..]) {
        signed += i32::from(byte as i8);
        unsigned += i32::from(byte);
    }
    if i32::try_from(stored) == Ok(signed) && signed != unsigned {
        header[148..156].copy_from_slice(format!("{unsigned:06o}\0 ").as_bytes());
    }
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    u64::try_from(std::str::from_utf8(bytes).ok()?.parse::<i64>().ok()?).ok()
}

fn pax_sparse_size(entry: &mut tar::Entry<'_, impl Read>) -> Result<Option<u64>, ()> {
    let stored_size = entry.size();
    let Some(fields) = entry.pax_extensions().map_err(|_| ())? else {
        return Ok(None);
    };
    let (mut major, mut minor, mut size, mut real_size) = (&b""[..], &b""[..], &b""[..], &b""[..]);
    for field in fields {
        let field = field.map_err(|_| ())?;
        match field.key_bytes() {
            b"GNU.sparse.major" => major = field.value_bytes(),
            b"GNU.sparse.minor" => minor = field.value_bytes(),
            b"GNU.sparse.size" => size = field.value_bytes(),
            b"GNU.sparse.realsize" => real_size = field.value_bytes(),
            _ => {}
        }
    }
    if (major, minor) != (b"1", b"0") {
        return Ok(None);
    }
    let size = if size.is_empty() { real_size } else { size };
    if size.is_empty() {
        Ok(Some(stored_size))
    } else {
        decimal(size).map(Some).ok_or(())
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
