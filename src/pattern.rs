//! IDA-style byte pattern matching.
//!
//! Supports patterns like `"48 8B ?? 05"` (spaced) or `"488b??05"` (compact).
//! Wildcard bytes (`??`) match any value.
//!
//! # Examples
//!
//! ```
//! use rekit::pattern::Pattern;
//!
//! let pat: Pattern = "48 8B ?? 05".parse().unwrap();
//! let data = b"\x00\x48\x8B\xFF\x05\x00";
//! assert_eq!(pat.find_first(data), Some(1));
//! ```

use std::fmt;
use std::str::FromStr;

/// A byte pattern with optional wildcards for matching binary data.
///
/// Supports IDA-style syntax: `"48 8B ?? 05"` or compact `"488b??05"`.
/// Wildcard positions are represented as `None` and match any byte value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

/// Error returned when parsing an invalid pattern string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePatternError {
    msg: String,
}

impl fmt::Display for ParsePatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid pattern: {}", self.msg)
    }
}

impl std::error::Error for ParsePatternError {}

impl Pattern {
    /// Create a pattern that matches exact bytes (no wildcards).
    pub fn exact(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.iter().map(|&b| Some(b)).collect(),
        }
    }

    /// Number of bytes in the pattern.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Test if `haystack` starts with this pattern.
    ///
    /// A wildcard byte (`??`) matches any value. Returns `false` if the haystack
    /// is shorter than the pattern.
    pub fn matches(&self, haystack: &[u8]) -> bool {
        if haystack.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(haystack.iter())
            .all(|(pat, &hay)| pat.is_none_or(|p| p == hay))
    }

    /// Find all occurrences of this pattern in `haystack`.
    ///
    /// Stops after `limit` matches (0 = unlimited). Appends byte offsets to `out`.
    ///
    /// Uses the first non-wildcard byte as an anchor for fast scanning. If the
    /// entire pattern is wildcards, falls back to checking every position.
    pub fn find_in(&self, haystack: &[u8], limit: usize, out: &mut Vec<usize>) {
        if self.bytes.is_empty() {
            // Empty pattern matches every position.
            let count = if limit == 0 {
                haystack.len() + 1
            } else {
                limit.min(haystack.len() + 1)
            };
            out.extend(0..count);
            return;
        }

        let pat_len = self.bytes.len();
        if haystack.len() < pat_len {
            return;
        }
        let last_start = haystack.len() - pat_len;

        // Find the first non-wildcard byte to use as an anchor for fast scanning.
        let anchor = self
            .bytes
            .iter()
            .enumerate()
            .find_map(|(i, b)| b.map(|v| (i, v)));

        match anchor {
            Some((anchor_idx, anchor_byte)) => {
                // Scan for the anchor byte, then verify the full pattern.
                let search_start = anchor_idx;
                let search_end = last_start + anchor_idx + 1;

                let mut pos = search_start;
                while pos < search_end {
                    // Simple byte scan for the anchor.
                    match haystack[pos..search_end]
                        .iter()
                        .position(|&b| b == anchor_byte)
                    {
                        Some(offset) => {
                            let candidate = pos + offset - anchor_idx;
                            if candidate <= last_start && self.matches(&haystack[candidate..]) {
                                out.push(candidate);
                                if limit > 0 && out.len() >= limit {
                                    return;
                                }
                            }
                            pos = pos + offset + 1;
                        }
                        None => break,
                    }
                }
            }
            None => {
                // All wildcards — every position matches.
                for i in 0..=last_start {
                    out.push(i);
                    if limit > 0 && out.len() >= limit {
                        return;
                    }
                }
            }
        }
    }

    /// Find the first occurrence of this pattern in `haystack`.
    pub fn find_first(&self, haystack: &[u8]) -> Option<usize> {
        let mut out = Vec::with_capacity(1);
        self.find_in(haystack, 1, &mut out);
        out.into_iter().next()
    }

    /// Find all occurrences of this pattern in `haystack`.
    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        self.find_in(haystack, 0, &mut out);
        out
    }
}

impl FromStr for Pattern {
    type Err = ParsePatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Pattern { bytes: Vec::new() });
        }

        let bytes = if s.contains(' ') {
            // Spaced format: "48 8B ?? 05"
            s.split_whitespace()
                .map(parse_token)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            // Compact format: "488b??05"
            if !s.len().is_multiple_of(2) {
                return Err(ParsePatternError {
                    msg: format!("compact pattern has odd length: {:?}", s),
                });
            }
            s.as_bytes()
                .chunks(2)
                .map(|chunk| {
                    let tok = std::str::from_utf8(chunk).unwrap();
                    parse_token(tok)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Pattern { bytes })
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            match b {
                Some(v) => write!(f, "{:02X}", v)?,
                None => write!(f, "??")?,
            }
        }
        Ok(())
    }
}

/// Parse a single two-character hex token or wildcard.
fn parse_token(tok: &str) -> Result<Option<u8>, ParsePatternError> {
    if tok == "??" || tok == "?" {
        Ok(None)
    } else {
        u8::from_str_radix(tok, 16)
            .map(Some)
            .map_err(|_| ParsePatternError {
                msg: format!("invalid hex byte: {:?}", tok),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spaced_hex() {
        let pat: Pattern = "48 8B ?? 05".parse().unwrap();
        assert_eq!(pat.len(), 4);
        assert_eq!(pat.bytes[0], Some(0x48));
        assert_eq!(pat.bytes[1], Some(0x8B));
        assert_eq!(pat.bytes[2], None);
        assert_eq!(pat.bytes[3], Some(0x05));
    }

    #[test]
    fn parse_compact_hex() {
        let pat: Pattern = "488b??05".parse().unwrap();
        assert_eq!(pat.len(), 4);
        assert_eq!(pat.bytes[0], Some(0x48));
        assert_eq!(pat.bytes[1], Some(0x8b));
        assert_eq!(pat.bytes[2], None);
        assert_eq!(pat.bytes[3], Some(0x05));
    }

    #[test]
    fn parse_error_on_invalid() {
        let result = "GG".parse::<Pattern>();
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_on_odd_compact() {
        let result = "48F".parse::<Pattern>();
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty() {
        let pat: Pattern = "".parse().unwrap();
        assert!(pat.is_empty());
    }

    #[test]
    fn matches_exact() {
        let pat = Pattern::exact(&[0x48, 0x8B, 0x05]);
        assert!(pat.matches(&[0x48, 0x8B, 0x05, 0x00]));
        assert!(!pat.matches(&[0x48, 0x8B, 0x06]));
    }

    #[test]
    fn matches_with_wildcards() {
        let pat: Pattern = "48 ?? 05".parse().unwrap();
        assert!(pat.matches(&[0x48, 0xFF, 0x05]));
        assert!(pat.matches(&[0x48, 0x00, 0x05]));
        assert!(!pat.matches(&[0x48, 0xFF, 0x06]));
    }

    #[test]
    fn matches_too_short() {
        let pat: Pattern = "48 8B 05".parse().unwrap();
        assert!(!pat.matches(&[0x48, 0x8B]));
    }

    #[test]
    fn find_first_found() {
        let pat: Pattern = "48 8B ?? 05".parse().unwrap();
        let data = b"\x00\x48\x8B\xFF\x05\x00";
        assert_eq!(pat.find_first(data), Some(1));
    }

    #[test]
    fn find_first_not_found() {
        let pat: Pattern = "48 8B ?? 06".parse().unwrap();
        let data = b"\x00\x48\x8B\xFF\x05\x00";
        assert_eq!(pat.find_first(data), None);
    }

    #[test]
    fn find_all_multiple() {
        let pat = Pattern::exact(&[0xAA]);
        let data = b"\xAA\x00\xAA\x00\xAA";
        let results = pat.find_all(data);
        assert_eq!(results, vec![0, 2, 4]);
    }

    #[test]
    fn find_in_with_limit() {
        let pat = Pattern::exact(&[0xAA]);
        let data = b"\xAA\x00\xAA\x00\xAA";
        let mut out = Vec::new();
        pat.find_in(data, 2, &mut out);
        assert_eq!(out, vec![0, 2]);
    }

    #[test]
    fn empty_pattern_matches_everything() {
        let pat: Pattern = "".parse().unwrap();
        assert!(pat.matches(&[0x00, 0x01]));
        assert!(pat.matches(&[]));
    }

    #[test]
    fn empty_pattern_find_all() {
        let pat: Pattern = "".parse().unwrap();
        let data = b"\x00\x01";
        // Empty pattern matches at every position (0, 1, 2 for 2-byte data).
        let results = pat.find_all(data);
        assert_eq!(results, vec![0, 1, 2]);
    }

    #[test]
    fn pattern_longer_than_haystack() {
        let pat: Pattern = "48 8B 05 06".parse().unwrap();
        assert_eq!(pat.find_first(&[0x48, 0x8B]), None);
    }

    #[test]
    fn display_round_trip() {
        let original = "48 8B ?? 05";
        let pat: Pattern = original.parse().unwrap();
        let displayed = pat.to_string();
        let reparsed: Pattern = displayed.parse().unwrap();
        assert_eq!(pat, reparsed);
    }

    #[test]
    fn display_format() {
        let pat: Pattern = "0a ff ?? 00".parse().unwrap();
        assert_eq!(pat.to_string(), "0A FF ?? 00");
    }

    #[test]
    fn all_wildcards_pattern() {
        let pat: Pattern = "?? ??".parse().unwrap();
        let data = b"\x00\x01\x02";
        let results = pat.find_all(data);
        assert_eq!(results, vec![0, 1]);
    }

    #[test]
    fn wildcard_first_byte_anchor() {
        // Pattern starts with wildcard — the anchor should be a later byte.
        let pat: Pattern = "?? 8B 05".parse().unwrap();
        let data = b"\xFF\x8B\x05\x00";
        assert_eq!(pat.find_first(data), Some(0));
    }

    #[test]
    fn find_at_end_of_haystack() {
        let pat: Pattern = "AA BB".parse().unwrap();
        let data = b"\x00\xAA\xBB";
        assert_eq!(pat.find_first(data), Some(1));
    }
}
