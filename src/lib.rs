//! polinrider-hunter, as a library.
//!
//! The binary is a thin CLI over these modules. They are public so the
//! end-to-end suite in `tests/` can plant real payload shapes on disk and check
//! that removal actually works, rather than only unit-testing the matcher.

pub mod agent;
pub mod config;
pub mod daemon;
pub mod gemini;
pub mod gitconfig;
pub mod gitscan;
pub mod healer;
pub mod json;
pub mod jsonbeacon;
pub mod monitor;
pub mod notify;
pub mod persist;
pub mod procscan;
pub mod report;
pub mod scanner;
pub mod service;
pub mod sha256;
pub mod signatures;
pub mod util;
pub mod winpersist;
