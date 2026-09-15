//! Finding the Rust files to analyse.
//!
//! A contract is usually a crate, and the interesting files are the ones a human wrote:
//! `src/*.rs`, including `src/test.rs`, because a fixture that plants a bug is worth
//! checking too. Build output is not source, so `target/` and friends are skipped — a
//! run over a workspace with a warm target directory would otherwise spend its time
//! parsing generated code.
//!
//! Nothing is skipped because of its *name*. A former version of this module only
//! collected files called `lib.rs` or `contract.rs`, which is exactly the kind of
//! assumption that makes a tool report "clean" on a contract it never read.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories that never hold source this project wrote.
const SKIPPED_DIRS: [&str; 5] = ["target", ".git", "node_modules", ".cargo", "vendor"];

/// Collects the `.rs` files under `path`, plus anything that stopped the walk.
///
/// A file is taken as given, whatever it is called: naming one explicitly is a
/// statement that it is the thing to check. A directory is walked recursively.
///
/// The result is sorted, so two runs over the same tree report findings in the same
/// order and a diff of two runs is about the code rather than about the filesystem.
/// Symlinks are not followed, because a link back up the tree turns a walk into a
/// hang, and the second problem in that list is unreadable directories rather than
/// silence about them.
pub fn collect(path: impl AsRef<Path>) -> (Vec<PathBuf>, Vec<String>) {
    let path = path.as_ref();
    let mut files = Vec::new();
    let mut problems = Vec::new();

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            problems.push(format!("{}: {err}", path.display()));
            return (files, problems);
        }
    };

    if metadata.is_file() {
        files.push(path.to_path_buf());
        return (files, problems);
    }

    if !metadata.is_dir() {
        problems.push(format!(
            "{}: not a file or a directory, so there is nothing to analyse",
            path.display()
        ));
        return (files, problems);
    }

    walk_directory(path, &mut files, &mut problems);
    files.sort();
    (files, problems)
}

fn walk_directory(dir: &Path, files: &mut Vec<PathBuf>, problems: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            // A directory that cannot be read is a hole in the analysis, so it is
            // reported rather than passed over: a clean result over half a tree is worse
            // than a result that says which half it saw.
            problems.push(format!("{}: {err}", dir.display()));
            return;
        }
    };

    let mut subdirectories = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                problems.push(format!("{}: {err}", dir.display()));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                problems.push(format!("{}: {err}", path.display()));
                continue;
            }
        };
        // `symlink_metadata` equivalents: a symlinked directory is not descended into.
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if is_skipped_dir(&path) {
                continue;
            }
            subdirectories.push(path);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }

    subdirectories.sort();
    for subdirectory in subdirectories {
        walk_directory(&subdirectory, files, problems);
    }
}

fn is_skipped_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| SKIPPED_DIRS.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a throwaway tree of empty files, and returns its root.
    ///
    /// One shared directory per test, named after the test, so two tests running at the
    /// same time cannot collide and a failure leaves the tree behind to inspect.
    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("soroban-analyzer-walk-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the scratch directory can be created");
        root
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("the parent can be created");
        }
        fs::write(path, "fn f() {}\n").expect("the file can be written");
    }

    #[test]
    fn a_directory_is_walked_for_rust_files_only() {
        let root = scratch("basic");
        touch(&root.join("src/lib.rs"));
        touch(&root.join("src/deep/nested/thing.rs"));
        touch(&root.join("src/notes.md"));
        touch(&root.join("README.md"));

        let (files, problems) = collect(&root);
        assert!(problems.is_empty(), "{problems:?}");
        let names = files
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["thing.rs", "lib.rs"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn build_output_is_skipped() {
        let root = scratch("target");
        touch(&root.join("src/lib.rs"));
        touch(&root.join("target/debug/build/generated.rs"));

        let (files, _) = collect(&root);
        assert_eq!(files.len(), 1, "{files:?}");
        assert!(files[0].ends_with("src/lib.rs"), "{files:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_is_taken_whatever_it_is_called() {
        let root = scratch("explicit");
        let file = root.join("weird-name.rs");
        touch(&file);
        let (files, problems) = collect(&file);
        assert_eq!(files, vec![file]);
        assert!(problems.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_path_is_a_problem_rather_than_an_empty_result() {
        let (files, problems) = collect("/nonexistent/soroban-analyzer/nope");
        assert!(files.is_empty());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("nope"), "{problems:?}");
    }

    #[test]
    fn the_order_does_not_depend_on_the_filesystem() {
        let root = scratch("order");
        for name in ["zeta", "alpha", "mid"] {
            touch(&root.join("src").join(format!("{name}.rs")));
        }
        let first = collect(&root).0;
        let second = collect(&root).0;
        assert_eq!(first, second);
        assert!(first[0].ends_with("alpha.rs"), "{first:?}");
        let _ = fs::remove_dir_all(&root);
    }
}
