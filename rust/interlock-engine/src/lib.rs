//! Rust port of the engine (ROADMAP section 76).

mod encoding;
pub mod taint;

pub use encoding::{canonical_encodings, Form, Variant};
pub use taint::{extract_tainted_values, TaintedValue};
