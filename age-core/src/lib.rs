#![forbid(unsafe_code)]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

pub mod format;
pub mod primitives;

#[cfg(feature = "plugin")]
pub mod plugin;
