// SPDX-License-Identifier: Apache-2.0

//! Go-compatible JSON candidate extraction. Parsing and leaf traversal use
//! explicit stacks and a flat node store, so Go's 10,000-container limit also
//! bounds nesting here without relying on the call stack. String decoding
//! replaces each invalid UTF-8 byte and each unpaired surrogate with U+FFFD.
//! Invalid JSON, including float64 overflow, yields no leaves so callers fall
//! back to the original bytes.

use std::collections::BTreeMap;

const MAX_DEPTH: usize = 10_000;

enum Node {
    String(Vec<u8>),
    Array(Vec<usize>),
    Object(BTreeMap<Vec<u8>, usize>),
    Scalar,
}

enum Frame {
    Array(Vec<usize>),
    Object(BTreeMap<Vec<u8>, usize>, Vec<u8>),
}

pub fn json_string_leaves(input: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut nodes = Parser(input).parse()?;
    let mut pending = vec![nodes.len() - 1];
    let mut leaves = Vec::new();
    while let Some(index) = pending.pop() {
        match std::mem::replace(&mut nodes[index], Node::Scalar) {
            Node::String(text) => leaves.push(text),
            Node::Array(items) => pending.extend(items.into_iter().rev()),
            Node::Object(entries) => pending.extend(entries.into_values().rev()),
            Node::Scalar => {}
        }
    }
    (!leaves.is_empty()).then_some(leaves)
}

struct Parser<'a>(&'a [u8]);

impl Parser<'_> {
    fn parse(mut self) -> Option<Vec<Node>> {
        let mut nodes = Vec::new();
        let mut stack = Vec::new();
        loop {
            self.space();
            let mut node = match self.peek()? {
                open @ (b'[' | b'{') => {
                    if stack.len() >= MAX_DEPTH {
                        return None;
                    }
                    self.0 = &self.0[1..];
                    self.space();
                    if open == b'[' {
                        if !self.take(b']') {
                            stack.push(Frame::Array(Vec::new()));
                            continue;
                        }
                        Node::Array(Vec::new())
                    } else {
                        if !self.take(b'}') {
                            let key = self.key()?;
                            stack.push(Frame::Object(BTreeMap::new(), key));
                            continue;
                        }
                        Node::Object(BTreeMap::new())
                    }
                }
                b'"' => Node::String(self.string()?),
                b'n' => {
                    self.0 = self.0.strip_prefix(b"null")?;
                    Node::Scalar
                }
                b't' => {
                    self.0 = self.0.strip_prefix(b"true")?;
                    Node::Scalar
                }
                b'f' => {
                    self.0 = self.0.strip_prefix(b"false")?;
                    Node::Scalar
                }
                b'-' | b'0'..=b'9' => {
                    self.number()?;
                    Node::Scalar
                }
                _ => return None,
            };

            loop {
                let index = nodes.len();
                nodes.push(node);
                self.space();
                let Some(frame) = stack.pop() else {
                    return self.0.is_empty().then_some(nodes);
                };
                match frame {
                    Frame::Array(mut items) => {
                        items.push(index);
                        if self.take(b',') {
                            stack.push(Frame::Array(items));
                            break;
                        }
                        self.take(b']').then_some(())?;
                        node = Node::Array(items);
                    }
                    Frame::Object(mut entries, key) => {
                        entries.insert(key, index);
                        if self.take(b',') {
                            let key = self.key()?;
                            stack.push(Frame::Object(entries, key));
                            break;
                        }
                        self.take(b'}').then_some(())?;
                        node = Node::Object(entries);
                    }
                }
            }
        }
    }

    fn key(&mut self) -> Option<Vec<u8>> {
        self.space();
        let key = self.string()?;
        self.space();
        self.take(b':').then_some(key)
    }

    fn string(&mut self) -> Option<Vec<u8>> {
        const REPLACEMENT: &str = "\u{fffd}";

        self.take(b'"').then_some(())?;
        let mut text = Vec::new();
        loop {
            let end = self
                .0
                .iter()
                .position(|&byte| matches!(byte, b'"' | b'\\' | 0..=0x1f))?;
            for chunk in self.0[..end].utf8_chunks() {
                text.extend_from_slice(chunk.valid().as_bytes());
                for _ in chunk.invalid() {
                    text.extend_from_slice(REPLACEMENT.as_bytes());
                }
            }
            self.0 = &self.0[end..];
            if self.take(b'"') {
                return Some(text);
            }
            self.take(b'\\').then_some(())?;
            let (&escape, rest) = self.0.split_first()?;
            self.0 = rest;
            text.push(match escape {
                b'"' | b'\\' | b'/' => escape,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'u' => {
                    let high = hex_unit(self.0)?;
                    self.0 = &self.0[4..];
                    let mut code = u32::from(high);
                    if (0xd800..=0xdbff).contains(&high) {
                        if let Some(low @ 0xdc00..=0xdfff) =
                            self.0.strip_prefix(b"\\u").and_then(hex_unit)
                        {
                            self.0 = &self.0[6..];
                            code = 0x10000 + ((code - 0xd800) << 10) + u32::from(low - 0xdc00);
                        }
                    }
                    let mut encoded = [0; 4];
                    let ch = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
                    text.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
                    continue;
                }
                _ => return None,
            });
        }
    }

    fn number(&mut self) -> Option<()> {
        let start = self.0;
        self.take(b'-');
        if !self.take(b'0') {
            self.digits()?;
        }
        if self.take(b'.') {
            self.digits()?;
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            self.digits()?;
        }

        let token = std::str::from_utf8(&start[..start.len() - self.0.len()]).ok()?;
        token.parse::<f64>().ok()?.is_finite().then_some(())
    }

    fn digits(&mut self) -> Option<()> {
        let end = self
            .0
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        self.0 = &self.0[end..];
        (end > 0).then_some(())
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.0 = &self.0[1..];
        }
    }

    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() != Some(byte) {
            return false;
        }
        self.0 = &self.0[1..];
        true
    }
}

fn hex_unit(input: &[u8]) -> Option<u16> {
    input.get(..4)?.iter().try_fold(0, |unit, &byte| {
        let digit = char::from(byte).to_digit(16)?;
        Some((unit << 4) | digit as u16)
    })
}
