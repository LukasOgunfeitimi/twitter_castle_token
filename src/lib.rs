//! Standalone, localhost-only X web login implementation.
//!
//! The HTTP client, transaction-ID generator, and protection-token generator
//! are all implemented in this package.

mod client;
pub mod protection;
pub mod transaction;

pub use client::*;
