// Catch documentation errors caused by code changes.
#![deny(broken_intra_doc_links)]

pub mod format;
pub mod primitives;

#[cfg(feature = "plugin")]
pub mod plugin;
