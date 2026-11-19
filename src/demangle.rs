//! C++ name demangling for Itanium (GCC/Clang) and MSVC mangling schemes.
//!
//! Requires the `demangle` feature (enabled by default).
//!
//! # Examples
//!
//! ```
//! use rekit::demangle;
//!
//! assert!(demangle::demangle("_ZN3foo3barEv").unwrap().contains("foo::bar"));
//! assert!(demangle::demangle("?bar@foo@@YAXXZ").unwrap().contains("foo::bar"));
//! assert!(demangle::demangle("not_mangled").is_none());
//! ```

/// Auto-detect mangling scheme and demangle.
///
/// Tries Itanium first (names starting with `_Z`), then MSVC (names starting with `?`).
/// Returns `None` if the name does not appear to be mangled or cannot be demangled.
pub fn demangle(name: &str) -> Option<String> {
    demangle_itanium(name).or_else(|| demangle_msvc(name))
}

/// Demangle an Itanium (GCC/Clang) mangled name.
///
/// Expects names starting with `_Z` or `_ZN`. Returns `None` if the name is not
/// a valid Itanium-mangled symbol.
pub fn demangle_itanium(name: &str) -> Option<String> {
    let sym = cpp_demangle::Symbol::new(name).ok()?;
    Some(sym.to_string())
}

/// Demangle an MSVC mangled name.
///
/// Expects names starting with `?`. Returns `None` if the name is not a valid
/// MSVC-mangled symbol.
pub fn demangle_msvc(name: &str) -> Option<String> {
    if !name.starts_with('?') {
        return None;
    }
    msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::llvm()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itanium_basic() {
        let result = demangle_itanium("_ZN3foo3barEv").unwrap();
        assert!(
            result.contains("foo::bar"),
            "expected 'foo::bar' in {:?}",
            result
        );
    }

    #[test]
    fn itanium_non_mangled() {
        assert!(demangle_itanium("printf").is_none());
    }

    #[test]
    fn msvc_basic() {
        let result = demangle_msvc("?bar@foo@@YAXXZ").unwrap();
        assert!(
            result.contains("foo::bar"),
            "expected 'foo::bar' in {:?}",
            result
        );
    }

    #[test]
    fn msvc_non_mangled() {
        assert!(demangle_msvc("printf").is_none());
    }

    #[test]
    fn auto_detect_itanium() {
        let result = demangle("_ZN3foo3barEv").unwrap();
        assert!(result.contains("foo::bar"));
    }

    #[test]
    fn auto_detect_msvc() {
        let result = demangle("?bar@foo@@YAXXZ").unwrap();
        assert!(result.contains("foo::bar"));
    }

    #[test]
    fn auto_detect_non_mangled() {
        assert!(demangle("not_mangled").is_none());
    }

    #[test]
    fn auto_detect_plain_c() {
        assert!(demangle("printf").is_none());
    }
}
