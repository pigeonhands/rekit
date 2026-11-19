//! Bitflag name helpers for `bitflags` types.
//!
//! Requires the `flags` feature.
//!
//! # Examples
//!
//! ```
//! use bitflags::bitflags;
//! use rekit::flags::{flag_names, flags_from_names};
//!
//! bitflags! {
//!     #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//!     struct Perms: u32 {
//!         const READ = 0b001;
//!         const WRITE = 0b010;
//!         const EXEC = 0b100;
//!     }
//! }
//!
//! let names = flag_names(Perms::READ | Perms::EXEC);
//! assert!(names.contains(&"READ"));
//! assert!(names.contains(&"EXEC"));
//! assert!(!names.contains(&"WRITE"));
//!
//! let bits = flags_from_names::<Perms>(&["READ", "WRITE"]).unwrap();
//! assert_eq!(bits, 0b011);
//! ```

use bitflags::Flags;

/// Returns the names of all individual flags set in `flags`.
///
/// Only named single-bit (or explicitly defined) flags are returned; unnamed
/// bits are ignored.
pub fn flag_names<F: Flags + Copy>(flags: F) -> Vec<&'static str> {
    F::FLAGS
        .iter()
        .filter(|f| flags.contains(*f.value()))
        .map(|f| f.name())
        .collect()
}

/// Combines named flags into a raw bits value.
///
/// Returns `Err` naming the first unrecognized flag.
pub fn flags_from_names<F: Flags>(names: &[&str]) -> Result<F::Bits, String>
where
    F::Bits: Default + std::ops::BitOr<Output = F::Bits>,
{
    let mut bits = F::Bits::default();
    for &name in names {
        let flag = F::FLAGS
            .iter()
            .find(|f| f.name() == name)
            .ok_or_else(|| format!("unknown flag: {:?}", name))?;
        bits = bits | flag.value().bits();
    }
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitflags::bitflags;

    bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct TestFlags: u32 {
            const A = 0b0001;
            const B = 0b0010;
            const C = 0b0100;
            const AB = 0b0011;
        }
    }

    #[test]
    fn names_single_flags() {
        let names = flag_names(TestFlags::A | TestFlags::C);
        assert!(names.contains(&"A"));
        assert!(names.contains(&"C"));
        assert!(!names.contains(&"B"));
    }

    #[test]
    fn names_includes_composite() {
        // AB is a composite flag; it should appear when both A and B are set.
        let names = flag_names(TestFlags::A | TestFlags::B);
        assert!(names.contains(&"A"));
        assert!(names.contains(&"B"));
        assert!(names.contains(&"AB"));
    }

    #[test]
    fn names_empty() {
        let names = flag_names(TestFlags::empty());
        assert!(names.is_empty());
    }

    #[test]
    fn from_names_valid() {
        let bits = flags_from_names::<TestFlags>(&["A", "C"]).unwrap();
        assert_eq!(bits, 0b0101);
    }

    #[test]
    fn from_names_invalid() {
        let result = flags_from_names::<TestFlags>(&["A", "NOPE"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("NOPE"));
    }

    #[test]
    fn from_names_empty() {
        let bits = flags_from_names::<TestFlags>(&[]).unwrap();
        assert_eq!(bits, 0);
    }
}
