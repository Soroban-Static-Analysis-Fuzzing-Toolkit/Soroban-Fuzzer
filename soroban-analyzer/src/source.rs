//! A parsed source file, and the mapping from syntax-tree spans to file positions.
//!
//! Every finding has to point at a line and column a reviewer can click, and the
//! syntax tree only knows byte offsets. [`SourceFile`] carries the text alongside the
//! tree so the two can be reconciled once, here, instead of in every detector.

use std::path::{Path, PathBuf};

use proc_macro2::Span;
use serde::Serialize;

/// A byte offset, a 1-based line and a 1-based column, all within one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Position {
    /// Byte offset from the start of the file.
    pub offset: usize,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column, counted in characters rather than bytes.
    pub column: usize,
}

/// Byte range covered by a finding, plus where it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Location {
    /// First byte of the span.
    pub start: Position,
    /// One past the last byte of the span.
    pub end_offset: usize,
}

impl Location {
    /// The span length in bytes.
    pub fn len(&self) -> usize {
        self.end_offset.saturating_sub(self.start.offset)
    }

    /// True when the span covers no bytes, which happens for nodes a parser
    /// synthesised rather than read from the source.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Renders a parse failure with a line and column when the parser could supply one.
///
/// `syn`'s own `Display` prints only the message, which leaves a reader of a broken
/// file with no idea where to look. A synthesised span — as a lexing failure produces,
/// since there is no token to point at — has an empty byte range, and a location
/// invented for it would be actively misleading, so that case reports the message
/// alone.
fn describe_parse_error(err: &syn::Error) -> String {
    let span = err.span();
    if span.byte_range().is_empty() {
        return err.to_string();
    }
    let start = span.start();
    format!("line {}, column {}: {err}", start.line, start.column + 1)
}

/// How many characters of source a message quotes before truncating.
///
/// Chosen so that a quoted expression fits beside a message on an 80-column terminal
/// line rather than wrapping onto three.
const SNIPPET_LIMIT: usize = 64;

/// Byte offsets at which each line starts, so a byte offset can be located in `O(log n)`.
#[derive(Debug)]
struct LineIndex {
    /// Offset of the first character of each line. Always starts with 0.
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0usize];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(offset + 1);
            }
        }
        Self { starts }
    }

    /// Maps a byte offset to a line and a character column.
    ///
    /// Offsets past the end of the file are clamped to the end, so a synthesised span
    /// cannot produce a nonsensical position: the worst case is pointing at the last
    /// line rather than pointing nowhere.
    fn locate(&self, text: &str, offset: usize) -> Position {
        let offset = offset.min(text.len());
        let line_ix = match self.starts.binary_search(&offset) {
            Ok(ix) => ix,
            Err(ix) => ix.saturating_sub(1),
        };
        let line_start = self.starts[line_ix];
        // Count characters, not bytes: a column that is wrong by the width of every
        // multi-byte character on the line is worse than useless for a human.
        let column = text[line_start..offset].chars().count() + 1;
        Position {
            offset,
            line: line_ix + 1,
            column,
        }
    }
}

/// One parsed Rust file.
///
/// `Debug` is written by hand rather than derived: `syn::File` only implements it
/// behind `extra-traits`, and a whole syntax tree in a debug string is not something
/// anyone wants to read. What is useful is the path and the size.
pub struct SourceFile {
    /// The path as it was given, which is what a finding reports.
    pub path: PathBuf,
    /// The file's contents.
    pub text: String,
    /// The parsed syntax tree.
    pub ast: syn::File,
    lines: LineIndex,
}

impl core::fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceFile")
            .field("path", &self.path)
            .field("bytes", &self.text.len())
            .field("items", &self.ast.items.len())
            .finish_non_exhaustive()
    }
}

impl SourceFile {
    /// Parses `text` as a Rust file.
    ///
    /// Returns the parser's own error rather than a summary of it: a static analyser
    /// that cannot say *where* a file failed to parse is not much use on a file that
    /// did.
    pub fn parse(path: impl Into<PathBuf>, text: String) -> Result<Self, String> {
        let ast = syn::parse_file(&text).map_err(|err| describe_parse_error(&err))?;
        let lines = LineIndex::new(&text);
        Ok(Self {
            path: path.into(),
            text,
            ast,
            lines,
        })
    }

    /// Reads and parses a file from disk.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("could not read `{}`: {err}", path.display()))?;
        Self::parse(path.to_path_buf(), text)
    }

    /// The file path as a string, for reports.
    ///
    /// A leading `./` is stripped, because a report is consumed as a path *relative to the
    /// repository* — that is what a code-scanning view resolves an artefact URI against,
    /// and what a baseline records — and `./src/lib.rs` and `src/lib.rs` are the same
    /// file. Analysing `.` is the common case, and without this every finding in every
    /// run would carry a prefix that no other tool's output has.
    pub fn display_path(&self) -> String {
        let displayed = self.path.display().to_string();
        displayed
            .strip_prefix("./")
            .unwrap_or(&displayed)
            .to_owned()
    }

    /// The text of a 1-based line, without its terminator.
    ///
    /// Out-of-range lines yield an empty string rather than panicking: a report is
    /// being built when this is called, and failing to render one line of context must
    /// not lose the finding.
    pub fn line_text(&self, line: usize) -> &str {
        if line == 0 {
            return "";
        }
        let start = match self.lines.starts.get(line - 1) {
            Some(start) => *start,
            None => return "",
        };
        let end = self
            .lines
            .starts
            .get(line)
            .copied()
            .unwrap_or(self.text.len());
        self.text[start..end].trim_end_matches(['\n', '\r'])
    }

    /// How many lines the file has.
    pub fn line_count(&self) -> usize {
        self.lines.starts.len()
    }

    /// The contiguous comment lines at the top of the file, before any code.
    ///
    /// Used for file-scoped `allow-file` markers. Scanning stops at the first line that
    /// is neither a comment nor blank, so a marker competes with a licence header for
    /// the same block; that is acceptable, since a licence header is not code and the
    /// marker simply has to appear before the first item.
    pub fn leading_comment_lines(&self) -> Vec<&str> {
        let mut lines = Vec::new();
        for line in 1..=self.line_count() {
            let text = self.line_text(line).trim();
            if text.is_empty() {
                continue;
            }
            if !text.starts_with("//") {
                break;
            }
            lines.push(text);
        }
        lines
    }

    /// The location a byte offset points at.
    pub fn location_at(&self, offset: usize) -> Location {
        let offset = if self.text.is_char_boundary(offset) {
            offset
        } else {
            (0..offset)
                .rev()
                .find(|candidate| self.text.is_char_boundary(*candidate))
                .unwrap_or(0)
        };
        Location {
            start: self.lines.locate(&self.text, offset),
            end_offset: offset,
        }
    }

    /// The source text a span covers, collapsed onto one line and truncated.
    ///
    /// For messages that quote the offending code back — a loop's header, a storage
    /// write — because a message naming the expression is checkable against the file
    /// and one that names only a line number is not. Newlines become single spaces and
    /// a long expression is cut at [`SNIPPET_LIMIT`], so a message stays one line in a
    /// terminal and in a SARIF annotation.
    pub fn snippet_inline(&self, span: Span) -> String {
        let range = span.byte_range();
        if range.is_empty() || range.end > self.text.len() {
            return String::new();
        }
        let raw =
            if self.text.is_char_boundary(range.start) && self.text.is_char_boundary(range.end) {
                &self.text[range]
            } else {
                return String::new();
            };
        let mut collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.chars().count() > SNIPPET_LIMIT {
            collapsed = collapsed.chars().take(SNIPPET_LIMIT).collect::<String>();
            collapsed.push('\u{2026}');
        }
        collapsed
    }

    /// The location a syntax-tree span points at.
    ///
    /// `Span::byte_range` is the only stable way to get a position out of a parsed
    /// tree, and it is empty for spans the parser synthesised rather than read. An
    /// empty span is widened to the whole line so that a finding still lands
    /// somewhere a reader can look, which is better than reporting offset 0.
    pub fn location(&self, span: Span) -> Location {
        let range = span.byte_range();
        if range.end > range.start {
            return Location {
                start: self.lines.locate(&self.text, range.start),
                end_offset: range.end,
            };
        }

        let start = self.lines.locate(&self.text, range.start);
        let line_end = self.text[start.offset..]
            .find('\n')
            .map_or(self.text.len(), |ix| start.offset + ix);
        Location {
            start,
            end_offset: line_end,
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::spanned::Spanned as _;

    use super::*;

    fn file(text: &str) -> SourceFile {
        SourceFile::parse("test.rs", text.to_owned()).expect("the fixture must parse")
    }

    #[test]
    fn a_path_is_reported_relative_to_the_repository() {
        let file = SourceFile::parse("./src/lib.rs", "fn f() {}\n".to_owned()).unwrap();
        assert_eq!(
            file.display_path(),
            "src/lib.rs",
            "a code-scanning view and a baseline both need the repository-relative path"
        );
        // A path that is not relative to anything is left alone, including one that only
        // looks like it starts with a dot.
        assert_eq!(
            SourceFile::parse(".gitignore", "fn f() {}\n".to_owned())
                .unwrap()
                .display_path(),
            ".gitignore"
        );
        assert_eq!(
            SourceFile::parse("/tmp/absolute.rs", "fn f() {}\n".to_owned())
                .unwrap()
                .display_path(),
            "/tmp/absolute.rs"
        );
    }

    #[test]
    fn positions_are_one_based_and_count_characters() {
        let f = file("// ünicode\nfn a() {}\n");
        // The `fn` keyword is on line 2, column 1.
        let item = &f.ast.items[0];
        let loc = f.location(item.span());
        assert_eq!(loc.start.line, 2, "{loc:?}");
        assert_eq!(loc.start.column, 1, "{loc:?}");
        assert!(!loc.is_empty(), "a finding has to cover something");
    }

    #[test]
    fn a_multibyte_line_does_not_shift_the_column() {
        // `ü` is two bytes but one character, so byte-counted columns on the second
        // line would read one too high from that point on: the binding below lands at
        // column 16 when columns count characters, and would be 17 if they counted
        // bytes. That difference is the whole point of the assertion.
        let f = file("fn f() {\n    let ü = 1; let b = 2;\n}\n");
        let mut found = None;
        for item in &f.ast.items {
            if let syn::Item::Fn(func) = item {
                for stmt in &func.block.stmts {
                    if let syn::Stmt::Local(local) = stmt {
                        if let syn::Pat::Ident(ident) = &local.pat {
                            if ident.ident == "b" {
                                found = Some(f.location(local.span()));
                            }
                        }
                    }
                }
            }
        }
        let loc = found.expect("the second binding should be found");
        assert_eq!(loc.start.line, 2);
        assert_eq!(loc.start.column, 16, "{loc:?}");
    }

    #[test]
    fn a_snippet_is_collapsed_and_truncated() {
        let f = file("fn f() {\n    let x = 1;\n}\n");
        let item = &f.ast.items[0];
        let snippet = f.snippet_inline(item.span());
        assert_eq!(snippet, "fn f() { let x = 1; }", "{snippet}");

        let long = format!("fn f() {{ {} }}\n", "let x = 1; ".repeat(20));
        let f = file(&long);
        let snippet = f.snippet_inline(f.ast.items[0].span());
        assert!(snippet.chars().count() <= SNIPPET_LIMIT + 1, "{snippet}");
        assert!(snippet.ends_with('\u{2026}'), "{snippet}");
    }

    #[test]
    fn a_parse_error_names_the_line_and_column() {
        // This lexes and fails to parse, so the parser can point at the problem.
        let err =
            SourceFile::parse("broken.rs", "fn f() {\n    let x = ;\n}\n".to_owned()).unwrap_err();
        assert!(err.starts_with("line 2, column "), "{err}");
    }

    #[test]
    fn a_lexing_failure_reports_no_invented_location() {
        // An unterminated delimiter has no token to point at, so the parser hands back
        // a synthesised span. Reporting "line 1, column 1" for it would be a guess.
        let err = SourceFile::parse("broken.rs", "fn f( {".to_owned()).unwrap_err();
        assert!(!err.starts_with("line "), "{err}");
        assert!(!err.is_empty(), "a failure must say something");
    }
}
