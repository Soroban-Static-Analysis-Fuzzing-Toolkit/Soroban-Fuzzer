//! Fixtures: Wasm modules the tests assemble, and the real compiled contract they run
//! against when a toolchain can produce it.
//!
//! # Why both
//!
//! An assembled module is a fixture written to be measured: every count in it is known,
//! which is what makes an estimator's arithmetic testable. It is also code this project
//! wrote, and a tool that only agrees with its author's fixtures has not been checked.
//! So the arithmetic is tested against assembled modules, and the *reading* is tested
//! against an artefact the real compiler produced from upstream's contract — the same
//! split the analyser and the fuzzer use.
//!
//! Building that artefact needs the `wasm32v1-none` target and a copy of the vendored
//! source outside the repository (upstream's tree is not ours to add a `Cargo.lock` to).
//! A run without the target skips those tests and says so, unless
//! `SOROBAN_REQUIRE_WASM_FIXTURE=1` is set — which CI sets, because a skip in CI is a
//! green build that measured nothing.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Encodes unsigned LEB128, which is how Wasm writes every length and index.
fn leb(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A section: its id, its length, its contents.
fn section(id: u8, contents: Vec<u8>, out: &mut Vec<u8>) {
    out.push(id);
    leb(contents.len() as u32, out);
    out.extend(contents);
}

/// A name: a length and its bytes.
fn write_name(value: &str, out: &mut Vec<u8>) {
    leb(value.len() as u32, out);
    out.extend(value.as_bytes());
}

/// Opcodes this assembler emits, so a fixture body reads as what it does.
pub mod op {
    /// `nop`, the cheapest thing that is still an operation.
    pub const NOP: u8 = 0x01;
    /// `loop`, opening a block a branch can return to.
    pub const LOOP: u8 = 0x03;
    /// The empty block type.
    pub const EMPTY_BLOCK: u8 = 0x40;
    /// `call`, then the callee's index.
    pub const CALL: u8 = 0x10;
    /// `call_indirect`, then the type index and the table index.
    pub const CALL_INDIRECT: u8 = 0x11;
    /// `br`, then the relative depth.
    pub const BR: u8 = 0x0C;
    /// `br_if`, then the relative depth. Needs an i32 on the stack, so fixtures that use
    /// it push one with `I32_CONST`.
    pub const BR_IF: u8 = 0x0D;
    /// `end`, closing a block or the body.
    pub const END: u8 = 0x0B;
    /// `i32.const`, then a signed LEB128 value.
    pub const I32_CONST: u8 = 0x41;
    /// `drop`, discarding the top of the stack.
    pub const DROP: u8 = 0x1A;
}

/// A module under construction.
#[derive(Default)]
pub struct ModuleBuilder {
    imports: Vec<(String, String)>,
    functions: Vec<Vec<u8>>,
    exports: Vec<(String, usize)>,
}

impl ModuleBuilder {
    /// Starts an empty module.
    pub fn new() -> Self {
        Self::default()
    }

    /// Imports a host function, which occupies the next function index; returns it.
    pub fn import_host(&mut self, module: &str, name: &str) -> usize {
        self.imports.push((module.to_owned(), name.to_owned()));
        self.imports.len() - 1
    }

    /// Defines a function whose body is the given operators, and returns its index.
    pub fn function(&mut self, body: &[u8]) -> usize {
        self.functions.push(body.to_vec());
        self.imports.len() + self.functions.len() - 1
    }

    /// Exports a function under a name.
    pub fn export(&mut self, name: &str, index: usize) -> &mut Self {
        self.exports.push((name.to_owned(), index));
        self
    }

    /// Assembles the module.
    pub fn build(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

        // One type, shared by every function: no parameters, no results.
        let mut types = vec![0x01, 0x60, 0x00, 0x00];
        section(1, core::mem::take(&mut types), &mut out);

        if !self.imports.is_empty() {
            let mut contents = Vec::new();
            leb(self.imports.len() as u32, &mut contents);
            for (module, field) in &self.imports {
                write_name(module, &mut contents);
                write_name(field, &mut contents);
                contents.push(0x00); // function
                contents.push(0x00); // type index 0
            }
            section(2, contents, &mut out);
        }

        // One type index per defined function; the type itself is type 0.
        let mut functions = Vec::new();
        leb(self.functions.len() as u32, &mut functions);
        functions.extend(std::iter::repeat_n(0x00, self.functions.len()));
        section(3, functions, &mut out);

        if !self.exports.is_empty() {
            let mut contents = Vec::new();
            leb(self.exports.len() as u32, &mut contents);
            for (export_name, index) in &self.exports {
                write_name(export_name, &mut contents);
                contents.push(0x00); // function
                leb(*index as u32, &mut contents);
            }
            section(7, contents, &mut out);
        }

        let mut code = Vec::new();
        leb(self.functions.len() as u32, &mut code);
        for body in &self.functions {
            let mut encoded = vec![0x00]; // no locals
            encoded.extend(body);
            encoded.push(op::END);
            leb(encoded.len() as u32, &mut code);
            code.extend(encoded);
        }
        section(10, code, &mut out);

        out
    }
}

/// A body of `count` `nop`s, so a fixture's instruction count is known by construction.
pub fn nops(count: usize) -> Vec<u8> {
    vec![op::NOP; count]
}

/// A body that calls `callee`.
pub fn call(callee: usize) -> Vec<u8> {
    let mut body = vec![op::CALL];
    leb(callee as u32, &mut body);
    body
}

/// A body with one loop that branches back to itself, which makes the enclosing estimate
/// a lower bound.
pub fn loop_forever() -> Vec<u8> {
    vec![
        op::LOOP,
        op::EMPTY_BLOCK,
        op::BR,
        0x00, // back to the top of the loop
        op::END,
    ]
}

/// A body with one `call_indirect`.
pub fn call_indirect() -> Vec<u8> {
    vec![op::CALL_INDIRECT, 0x00, 0x00]
}

/// Loads the real compiled token, building it if it is not already cached.
///
/// Returns `None` when there is no toolchain that can produce it and CI has not demanded
/// that there be one.
pub fn compiled_token() -> Option<PathBuf> {
    let cached = cache_dir().join("soroban_token_contract.wasm");
    if cached.is_file() {
        return Some(cached);
    }

    if let Ok(path) = std::env::var("SOROBAN_BUDGET_WASM") {
        return Some(PathBuf::from(path));
    }

    // Two tests in one binary ask for this at the same time, and both would otherwise
    // copy the source and build it. One lock, held across the build, so the second finds
    // the artefact the first produced.
    let lock = LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if cached.is_file() {
        return Some(cached);
    }

    let vendor = repository_root().join("third-party/soroban-token-example");
    if !vendor.is_dir() {
        return unavailable("the vendored contract is not in this checkout");
    }

    // Copied out of the tree for two reasons. Upstream's vendored directory is
    // byte-identical to its revision, and a build there would leave a lockfile that made
    // it not so; and a manifest inside this repository but outside its workspace members
    // is a cargo error, because a package under a workspace root has to be in it or
    // excluded from it explicitly. A temporary directory is neither.
    let source = std::env::temp_dir().join("soroban-budget-fixture-source");
    let _ = std::fs::remove_dir_all(&source);
    copy_tree(&vendor, &source).expect("the vendored source can be copied out of the tree");

    let built = Command::new("cargo")
        .args([
            "build",
            "--target",
            "wasm32v1-none",
            "--release",
            "--manifest-path",
        ])
        .arg(source.join("Cargo.toml"))
        .current_dir(&source)
        .env("CARGO_TARGET_DIR", cache_dir().join("target"))
        .output()
        .expect("cargo runs");

    if !built.status.success() {
        let stderr = String::from_utf8_lossy(&built.stderr);
        return unavailable(&format!(
            "the vendored contract did not build for wasm32v1-none (does `rustup target add \
             wasm32v1-none` need running?):\n{stderr}"
        ));
    }

    let wasm = cache_dir().join("target/wasm32v1-none/release/soroban_token_contract.wasm");
    if !wasm.is_file() {
        return unavailable("the build reported success but produced no .wasm");
    }
    std::fs::copy(&wasm, &cached).expect("the artefact can be cached");
    Some(cached)
}

/// Serialises the one-time build across the tests that need it.
static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Where build products for the fixtures live: inside `target/`, so a clean removes them.
fn cache_dir() -> PathBuf {
    repository_root().join("target/wasm-budget-fixture")
}

/// The repository root, found from this crate's manifest directory.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives in the repository")
        .to_path_buf()
}

/// Reports a fixture that could not be produced, unless CI has demanded one.
fn unavailable(reason: &str) -> Option<PathBuf> {
    if std::env::var("SOROBAN_REQUIRE_WASM_FIXTURE").is_ok() {
        panic!(
            "SOROBAN_REQUIRE_WASM_FIXTURE is set, so a real compiled contract is required \
             and could not be produced: {reason}"
        );
    }
    eprintln!("skipping the compiled-contract test: {reason}");
    None
}

/// Copies a directory tree, which is all the fixture needs.
fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            // `target` is build output, not source.
            if entry.file_name() == "target" {
                continue;
            }
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
