//! Rust port of the engine (ROADMAP section 76).

pub mod chunk;
mod encoding;
pub mod overlap;
pub mod evidence;
pub mod taint;

pub use chunk::{contiguous_chunks, shannon_entropy, Chunk};
pub use encoding::{canonical_encodings, Form, Variant};
pub use overlap::{check_overlap_string, match_tainted_value, OverlapHit};
pub use taint::{extract_tainted_values, TaintedValue};
