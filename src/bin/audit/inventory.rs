//! Static inventory of the source tree.
//!
//! This is a textual census, not an analysis: it counts the constructs whose
//! presence or absence a reviewer needs to know about, and the report labels
//! the counts as heuristic. Anything that needs to be precise (which `unsafe`
//! block is sound, whether a `panic!` is reachable) is a marker instead.
//!
//! `src/bin` is reported separately from the library. The audit tool itself is
//! a binary that prints to stdout by design, so folding its `println!` calls
//! into the daemon's count would misrepresent both.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Counts for one file.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FileStats {
    /// Repository-relative path with `/` separators.
    pub path: String,
    /// Total lines.
    pub lines: usize,
    /// Non-blank lines that are not whole-line comments.
    pub code_lines: usize,
    /// `unsafe {` and `unsafe fn` occurrences.
    pub unsafe_blocks: usize,
    /// `.unwrap()` occurrences.
    pub unwraps: usize,
    /// `.expect(` occurrences.
    pub expects: usize,
    /// `panic!` occurrences.
    pub panics: usize,
    /// `#[allow(` attributes.
    pub allows: usize,
    /// `println!` and `dbg!` occurrences.
    pub debug_prints: usize,
    /// `todo!` and `unimplemented!` occurrences.
    pub stubs: usize,
}

impl FileStats {
    fn account(&mut self, line: &str) {
        self.lines += 1;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with("/*") {
            self.code_lines += 1;
        }
        self.unsafe_blocks += occurrences(line, "unsafe {") + occurrences(line, "unsafe fn");
        self.unwraps += occurrences(line, ".unwrap()");
        self.expects += occurrences(line, ".expect(");
        self.panics += occurrences(line, "panic!(");
        self.allows += occurrences(line, "#[allow(");
        self.debug_prints += occurrences(line, "println!(") + occurrences(line, "dbg!(");
        self.stubs += occurrences(line, "todo!(") + occurrences(line, "unimplemented!(");
    }
}

/// Totals over a set of files.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    /// Files scanned.
    pub files: usize,
    /// Lines across the files.
    pub lines: usize,
    /// Code lines across the files.
    pub code_lines: usize,
    /// Unsafe blocks and functions.
    pub unsafe_blocks: usize,
    /// Unwrap calls.
    pub unwraps: usize,
    /// Expect calls.
    pub expects: usize,
    /// Panic calls.
    pub panics: usize,
    /// Allow attributes.
    pub allows: usize,
    /// Debug prints.
    pub debug_prints: usize,
    /// Stub macros.
    pub stubs: usize,
}

impl Totals {
    /// Add one file's counts.
    fn add(&mut self, stats: &FileStats) {
        self.files += 1;
        self.lines += stats.lines;
        self.code_lines += stats.code_lines;
        self.unsafe_blocks += stats.unsafe_blocks;
        self.unwraps += stats.unwraps;
        self.expects += stats.expects;
        self.panics += stats.panics;
        self.allows += stats.allows;
        self.debug_prints += stats.debug_prints;
        self.stubs += stats.stubs;
    }
}

/// A tree that was measured, plus its totals.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Tree {
    /// Directory the files came from (`src`, `src/bin`, `tests`, `benches`).
    pub name: String,
    /// Per-file counts, sorted by path.
    pub files: Vec<FileStats>,
    /// Sum of the per-file counts.
    pub totals: Totals,
}

impl Tree {
    /// Build a tree and its totals from measured files.
    fn from_files(name: &str, files: Vec<FileStats>) -> Self {
        let mut totals = Totals::default();
        for stats in &files {
            totals.add(stats);
        }
        Self {
            name: name.to_owned(),
            files,
            totals,
        }
    }
}

/// Everything measured for the library, the tools and the tests.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceInventory {
    /// The daemon and library sources, excluding `src/bin`.
    pub library: Tree,
    /// Helper binaries under `src/bin`.
    pub tools: Tree,
    /// Integration tests.
    pub tests: Tree,
    /// Benchmarks.
    pub benches: Tree,
}

impl SourceInventory {
    /// Measure the source trees below `root`.
    pub fn scan(root: &Path) -> Self {
        let source = measure(root, "src");
        let (tools, library): (Vec<FileStats>, Vec<FileStats>) = source
            .files
            .into_iter()
            .partition(|stats| stats.path.starts_with("src/bin/"));
        Self {
            library: Tree::from_files("src", library),
            tools: Tree::from_files("src/bin", tools),
            tests: measure(root, "tests"),
            benches: measure(root, "benches"),
        }
    }

    /// All trees, in report order.
    pub fn trees(&self) -> [&Tree; 4] {
        [&self.library, &self.tools, &self.tests, &self.benches]
    }

    /// Files in `src` that carry no marker and are long enough to matter.
    ///
    /// The threshold keeps tiny modules out of the list: a 30-line module with
    /// no annotation is not an audit gap.
    pub fn unannotated(&self, annotated: &[&str], minimum_lines: usize) -> Vec<&FileStats> {
        let mut files: Vec<&FileStats> = self
            .library
            .files
            .iter()
            .filter(|file| file.lines >= minimum_lines)
            .filter(|file| !annotated.contains(&file.path.as_str()))
            .collect();
        files.sort_by_key(|file| std::cmp::Reverse(file.code_lines));
        files
    }
}

/// Measure every `.rs` file in `root/name`.
fn measure(root: &Path, name: &str) -> Tree {
    let mut paths = Vec::new();
    collect(&root.join(name), &mut paths);
    paths.sort();

    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let mut stats = FileStats {
            path: relative,
            ..FileStats::default()
        };
        for line in contents.lines() {
            stats.account(line);
        }
        files.push(stats);
    }
    Tree::from_files(name, files)
}

/// Non-overlapping occurrences of a fixed needle.
pub fn occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.match_indices(needle).count()
}

/// Collect `.rs` files below `directory`.
fn collect(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "target" && !name.starts_with('.') {
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
    fn occurrence_counting_does_not_overlap() {
        assert_eq!(occurrences("aaa", "aa"), 1);
        assert_eq!(occurrences(".unwrap().unwrap()", ".unwrap()"), 2);
        assert_eq!(occurrences("anything", ""), 0);
        assert_eq!(occurrences("nothing", "x"), 0);
    }

    #[test]
    fn comment_lines_are_not_code() {
        let mut stats = FileStats::default();
        for line in ["// a comment", "", "   ", "let x = 1;", "//! doc"] {
            stats.account(line);
        }
        assert_eq!(stats.lines, 5);
        assert_eq!(stats.code_lines, 1);
    }

    #[test]
    fn constructs_are_counted_per_line() {
        let mut stats = FileStats::default();
        stats.account("let value = unsafe { read() };");
        stats.account("something.unwrap();");
        stats.account("dbg!(1); println!(\"x\");");
        assert_eq!(stats.unsafe_blocks, 1);
        assert_eq!(stats.unwraps, 1);
        assert_eq!(stats.debug_prints, 2);
    }

    #[test]
    fn totals_sum_their_files() {
        let mut first = FileStats {
            path: "src/a.rs".to_owned(),
            lines: 10,
            code_lines: 4,
            unsafe_blocks: 1,
            ..FileStats::default()
        };
        first.panics = 2;
        let second = FileStats {
            path: "src/b.rs".to_owned(),
            lines: 5,
            code_lines: 3,
            expects: 1,
            ..FileStats::default()
        };
        let tree = Tree::from_files("src", vec![first, second]);
        assert_eq!(tree.totals.files, 2);
        assert_eq!(tree.totals.lines, 15);
        assert_eq!(tree.totals.code_lines, 7);
        assert_eq!(tree.totals.unsafe_blocks, 1);
        assert_eq!(tree.totals.panics, 2);
        assert_eq!(tree.totals.expects, 1);
    }

    #[test]
    fn tools_are_reported_apart_from_the_library() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let inventory = SourceInventory::scan(root);
        assert!(
            inventory.tools.totals.files > 0,
            "the audit tool should be measured"
        );
        assert!(
            inventory
                .library
                .files
                .iter()
                .all(|file| !file.path.starts_with("src/bin/")),
            "library counts must not include src/bin"
        );
        assert!(inventory.library.totals.files > inventory.tools.totals.files);
    }
}
