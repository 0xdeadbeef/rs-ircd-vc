//! `MARK:` annotations: grammar, scanning and validation.
//!
//! A marker is a single line comment of the form
//!
//! ```text
//! // MARK: security: high: SEC-PARSE-001: text, never empty
//! ```
//!
//! The four fields are separated by `: `. Text keeps any further colons, so
//! prose is not constrained by the separator. The scanner walks `.rs` files
//! under `src`, `tests` and `benches`, skips build output, and reports a line
//! that looks like a marker but does not parse instead of guessing at it.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Categories a marker may belong to.
pub const CATEGORIES: &[&str] = &["security", "safety", "speed", "protocol", "policy"];

/// Severities, ordered from most to least urgent.
pub const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

/// Directories that never contain source worth scanning.
const SKIPPED: &[&str] = &["target", ".git", "reports", "node_modules"];

/// One validated annotation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Marker {
    /// Stable identifier such as `SEC-PARSE-001`.
    pub id: String,
    /// One of [`CATEGORIES`].
    pub category: &'static str,
    /// One of [`SEVERITIES`].
    pub severity: &'static str,
    /// Free-form explanation, never empty.
    pub text: String,
    /// Repository-relative path with `/` separators.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
}

impl Marker {
    /// Sort key: category order, then severity, then id.
    fn sort_key(&self) -> (usize, usize, &str) {
        let category = CATEGORIES
            .iter()
            .position(|known| *known == self.category)
            .unwrap_or(usize::MAX);
        let severity = severity_rank(self.severity);
        (category, severity, self.id.as_str())
    }
}

/// A malformed or duplicate marker.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Problem {
    /// Repository-relative file.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// What is wrong with it.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}: {}", self.file, self.line, self.message)
    }
}

/// Everything the scanner found.
#[derive(Debug, Default, Clone)]
pub struct Markers {
    /// Valid markers, sorted for stable output.
    pub markers: Vec<Marker>,
    /// Malformed lines and duplicate identifiers.
    pub problems: Vec<Problem>,
}

impl Markers {
    /// Scan `root` for markers.
    ///
    /// Unreadable trees are skipped rather than reported as clean: a missing
    /// directory means there was nothing to annotate, while an unreadable file
    /// is recorded as a problem.
    pub fn scan(root: &Path) -> Self {
        scan_tree(root)
    }

    /// Number of markers per severity, most urgent first.
    pub fn severity_counts(&self) -> Vec<(&'static str, usize)> {
        SEVERITIES
            .iter()
            .map(|severity| {
                let count = self
                    .markers
                    .iter()
                    .filter(|marker| marker.severity == *severity)
                    .count();
                (*severity, count)
            })
            .collect()
    }

    /// Number of markers per category.
    pub fn category_counts(&self) -> Vec<(&'static str, usize)> {
        CATEGORIES
            .iter()
            .map(|category| {
                let count = self
                    .markers
                    .iter()
                    .filter(|marker| marker.category == *category)
                    .count();
                (*category, count)
            })
            .collect()
    }

    /// Markers whose category is one of `wanted`, in report order.
    pub fn in_categories(&self, wanted: &[&str]) -> Vec<&Marker> {
        self.markers
            .iter()
            .filter(|marker| wanted.contains(&marker.category))
            .collect()
    }

    /// Files carrying at least one marker, for coverage reporting.
    pub fn annotated_files(&self) -> Vec<&str> {
        let mut files: Vec<&str> = self
            .markers
            .iter()
            .map(|marker| marker.file.as_str())
            .collect();
        files.sort_unstable();
        files.dedup();
        files
    }
}

/// Position of `severity` in [`SEVERITIES`]; unknown severities sort last.
fn severity_rank(severity: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|known| *known == severity)
        .unwrap_or(usize::MAX)
}

/// Walk the source trees below `root` and parse every annotation.
///
/// A file that cannot be read becomes a problem rather than being skipped
/// silently, so a permission fault cannot produce a clean-looking report.
fn scan_tree(root: &Path) -> Markers {
    let mut files = Vec::new();
    for directory in ["src", "tests", "benches"] {
        collect(&root.join(directory), &mut files);
    }
    files.sort();

    let mut found = Markers::default();
    let mut seen: BTreeMap<String, (String, usize)> = BTreeMap::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(contents) = fs::read_to_string(&path) else {
            found.problems.push(Problem {
                file: relative,
                line: 0,
                message: "cannot read file".to_owned(),
            });
            continue;
        };
        for (index, line) in contents.lines().enumerate() {
            let number = index + 1;
            let Some(body) = marker_body(line) else {
                if looks_like_marker(line) {
                    found.problems.push(Problem {
                        file: relative.clone(),
                        line: number,
                        message: "marker must start with `// MARK: `".to_owned(),
                    });
                }
                continue;
            };
            match parse(body, &relative, number) {
                Ok(marker) => {
                    if let Some((first_file, first_line)) =
                        seen.insert(marker.id.clone(), (relative.clone(), number))
                    {
                        found.problems.push(Problem {
                            file: relative.clone(),
                            line: number,
                            message: format!(
                                "duplicate id {} (first seen at {first_file}:{first_line})",
                                marker.id
                            ),
                        });
                        continue;
                    }
                    found.markers.push(marker);
                }
                Err(message) => found.problems.push(Problem {
                    file: relative.clone(),
                    line: number,
                    message,
                }),
            }
        }
    }

    found
        .markers
        .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    found.problems.sort_by(|left, right| {
        (&left.file, left.line, &left.message).cmp(&(&right.file, right.line, &right.message))
    });
    found
}

/// The comment text of `line`, without its slashes.
///
/// `///` and `//!` are accepted so a marker can sit on a documented item.
fn comment(line: &str) -> Option<&str> {
    let comment = line.trim_start().strip_prefix("//")?;
    Some(comment.trim_start_matches(['/', '!']).trim_start())
}

/// The part of `line` after `// MARK: `, when the line is a marker.
fn marker_body(line: &str) -> Option<&str> {
    comment(line)?.strip_prefix("MARK:").map(str::trim)
}

/// True when a comment opens with `MARK` but is not a marker.
///
/// Only the first word counts, so documentation that mentions the token in
/// running text (```MARK:``` in a sentence) is not reported as a mistake.
fn looks_like_marker(line: &str) -> bool {
    comment(line).is_some_and(|comment| comment.starts_with("MARK"))
}

/// Parse `category: severity: id: text`.
fn parse(body: &str, file: &str, line: usize) -> Result<Marker, String> {
    let mut fields = body.splitn(4, ':');
    let (Some(category), Some(severity), Some(id), Some(text)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err("expected `category: severity: id: text`".to_owned());
    };
    let (category, severity, id, text) = (category.trim(), severity.trim(), id.trim(), text.trim());

    let Some(category) = CATEGORIES.iter().find(|known| **known == category) else {
        return Err(format!(
            "unknown category {category:?} (expected one of {})",
            CATEGORIES.join(", ")
        ));
    };
    let Some(severity) = SEVERITIES.iter().find(|known| **known == severity) else {
        return Err(format!(
            "unknown severity {severity:?} (expected one of {})",
            SEVERITIES.join(", ")
        ));
    };
    if !valid_id(id) {
        return Err(format!(
            "invalid id {id:?} (expected PREFIX-NNN, uppercase, three digits)"
        ));
    }
    if text.is_empty() {
        return Err("marker text is empty".to_owned());
    }

    Ok(Marker {
        id: id.to_owned(),
        category,
        severity,
        text: text.to_owned(),
        file: file.to_owned(),
        line,
    })
}

/// `PREFIX-NNN`: uppercase alphanumeric segments joined by hyphens, then
/// exactly three digits. `SEC-CONTROL-001` and `A-001` are both valid; the
/// shape stays strict enough to be greppable and stable across renames.
fn valid_id(id: &str) -> bool {
    let Some((prefix, suffix)) = id.rsplit_once('-') else {
        return false;
    };
    if prefix.is_empty() || prefix.len() > 16 {
        return false;
    }
    let starts_upper = prefix.as_bytes()[0].is_ascii_uppercase();
    let segments_ok = prefix.split('-').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    });
    starts_upper && segments_ok && suffix.len() == 3 && suffix.bytes().all(|b| b.is_ascii_digit())
}

/// Collect `.rs` files below `directory`, skipping build output.
fn collect(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !SKIPPED.contains(&name.as_str()) {
                collect(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_marker() {
        let body = "security: high: SEC-PARSE-001: rejects control characters: even here";
        let marker = parse(body, "src/x.rs", 7).expect("valid marker");
        assert_eq!(marker.category, "security");
        assert_eq!(marker.severity, "high");
        assert_eq!(marker.id, "SEC-PARSE-001");
        assert_eq!(
            marker.text, "rejects control characters: even here",
            "text keeps later colons"
        );
    }

    #[test]
    fn rejects_bad_fields() {
        assert!(parse("nonsense: high: SEC-001: text", "a", 1).is_err());
        assert!(parse("security: loud: SEC-001: text", "a", 1).is_err());
        assert!(parse("security: high: sec-001: text", "a", 1).is_err());
        assert!(parse("security: high: SEC-1: text", "a", 1).is_err());
        assert!(parse("security: high: SEC-001:", "a", 1).is_err());
        assert!(parse("security: high: SEC-001", "a", 1).is_err());
    }

    #[test]
    fn accepts_all_doc_comment_styles() {
        assert_eq!(
            marker_body("// MARK: security: low: A-001: x"),
            Some("security: low: A-001: x")
        );
        assert_eq!(
            marker_body("  /// MARK: speed: low: A-001: x"),
            Some("speed: low: A-001: x")
        );
        assert_eq!(
            marker_body("//! MARK: policy: low: A-001: x"),
            Some("policy: low: A-001: x")
        );
        assert_eq!(marker_body("let text = \"MARK: nope\";"), None);
        assert_eq!(marker_body("// MARK:nospace"), Some("nospace"));
    }

    #[test]
    fn ids_are_strict() {
        assert!(valid_id("SEC-PARSE-001"));
        assert!(valid_id("SEC-CONTROL-001"));
        assert!(valid_id("A-001"));
        assert!(!valid_id("SEC-PARSE-1"));
        assert!(!valid_id("SEC-PARSE-0001"));
        assert!(!valid_id("sec-001"));
        assert!(!valid_id("SEC_001"));
        assert!(!valid_id("-001"));
        assert!(!valid_id("SEC--001"));
        assert!(!valid_id("TOOLONGPREFIXTHATISTOOLONG-001"));
    }

    #[test]
    fn prose_mentioning_the_token_is_not_a_problem() {
        assert!(!looks_like_marker(
            "//! The `MARK:` annotation is documented here"
        ));
        assert!(!looks_like_marker("let pattern = \"// MARK: x\";"));
        assert!(looks_like_marker("// MARK: security: low: A-001: x"));
        assert!(looks_like_marker("//MARK: security: low: A-001: x"));
        assert!(looks_like_marker("// MARK : security: low: A-001: x"));
    }

    #[test]
    fn severities_have_a_total_order() {
        assert!(severity_rank("critical") < severity_rank("info"));
        assert_eq!(severity_rank("bogus"), usize::MAX);
    }
}
