//! Rust port of the engine (ROADMAP section 76).

pub mod bind;
pub mod chunk;
pub mod container;
pub mod decode;
mod encoding;
pub mod evidence;
pub mod legs;
pub mod overlap;
pub mod taint;
pub mod verdict;

pub use chunk::{contiguous_chunks, shannon_entropy, Chunk};
pub use container::{
    default_container_limits, inspect_container, looks_like_container, ContainerAbortReason,
    ContainerInspectResult, ContainerLimits,
};
pub use encoding::{canonical_encodings, Form, Variant};
pub use overlap::{check_overlap_string, match_tainted_value, OverlapHit};
pub use taint::{extract_tainted_values, TaintedValue};
