//! Reverse engineering primitives — byte pattern scanning, C++ demangling, and utilities.
//!
//! `rekit` provides low-level building blocks for reverse engineering tools. All algorithms
//! operate on `&[u8]` or `&str` without OS dependencies, making them suitable for use in
//! any context from CLI tools to game modding frameworks.
//!
//! # Feature flags
//!
//! | Feature    | Default | Description |
//! |------------|---------|-------------|
//! | `pattern`  | yes     | IDA-style byte pattern matching |
//! | `demangle` | yes     | C++ name demangling (Itanium + MSVC) |
//! | `flags`    | no      | Bitflag name helpers (requires `bitflags` crate) |

#[cfg(feature = "pattern")]
pub mod pattern;

#[cfg(feature = "demangle")]
pub mod demangle;

#[cfg(feature = "flags")]
pub mod flags;
