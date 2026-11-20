//! Rust port of the engine (ROADMAP section 76).

pub mod bind;
pub mod chunk;
pub mod container;
pub mod decode;
mod encoding;
pub mod evidence;
pub mod legs;
pub mod overlap;
pub mod path_taint;
pub mod tagger;
pub mod taint;
pub mod verdict;

pub use chunk::{contiguous_chunks, shannon_entropy, Chunk};
pub use container::{
    default_container_limits, inspect_container, looks_like_container, ContainerAbortReason,
    ContainerInspectResult, ContainerLimits,
};
pub use encoding::{canonical_encodings, Form, Variant};
pub use overlap::{
    check_overlap_limited, check_overlap_payload_limited, check_overlap_string,
    current_max_decode_depth, match_tainted_value, set_max_decode_depth, OverlapHit,
    DEFAULT_MAX_DECODE_DEPTH,
};
pub use taint::{extract_tainted_values, TaintedValue};
