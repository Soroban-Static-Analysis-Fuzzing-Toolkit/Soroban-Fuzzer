//! Reading a compiled contract: what it imports, what it exports, and what is in each
//! function body.
//!
//! This module is deliberately the only place that knows the Wasm binary format. It
//! turns a module into the facts the estimator reasons about — function indices, call
//! sites, loops, host imports — and reports nothing about cost, so that the reading and
//! the estimating can be argued about separately.
//!
//! The parser is `wasmparser`, the same crate `soroban-env-host` links. A second
//! implementation of a binary format is a second opinion, and the resource a contract
//! consumes is measured by the network's parser, not by ours.

use core::fmt;

use wasmparser::{ExternalKind, Operator, Parser, Payload, TypeRef};

/// Why a module could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmError(String);

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WasmError {}

/// One host function a contract imports.
///
/// Nothing here interprets the name. On a real contract compiled by `soroban-sdk` the
/// module and field names are deliberately unhelpful — the token artefact this crate is
/// tested against imports from `l`, `m`, `i`, `a` and `x` — so a tool that guessed
/// "this one is a storage read" from the name would be guessing. The import is reported
/// as it is written, and the count of calls to it is what the estimate uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostImport {
    /// The function index this import occupies.
    pub index: usize,
    /// The import's module name, as compiled.
    pub module: String,
    /// The import's field name, as compiled.
    pub name: String,
}

impl HostImport {
    /// The import's full name, `module.name`.
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }
}

/// What one function body contains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionFacts {
    /// Operations in the body.
    ///
    /// Every operator counts except `end`, which terminates the body and any block
    /// inside it: a structural terminator is not work. This is a count of operations, not
    /// of metered CPU — Soroban charges each instruction differently and charges host
    /// calls at their own rates — so it is a proxy for "how much work is written here"
    /// rather than a prediction of the bill.
    pub instructions: usize,
    /// Absolute indices of the functions this one calls directly.
    pub calls: Vec<usize>,
    /// Absolute indices of the *host* functions this one calls.
    ///
    /// Separated from `calls` because an imported function's cost is not in this module:
    /// it is in the host, and the network meters it separately.
    pub host_calls: Vec<usize>,
    /// How many `call_indirect` sites the body has.
    pub indirect_calls: usize,
    /// How many `loop` blocks the body opens — each is a site a path can re-enter.
    pub loops: usize,
    /// How many branches the body has, for a reader who wants to see the shape.
    pub branches: usize,
}

/// A compiled contract, as far as this crate needs to know it.
#[derive(Clone, Debug)]
pub struct Module {
    /// The path the module was read from.
    pub path: String,
    /// The module's size on disk, in bytes.
    pub bytes: usize,
    /// Functions the module imports, in index order.
    pub imports: Vec<HostImport>,
    /// Functions the module defines, in index order; `functions[i]` has index
    /// `imports.len() + i`.
    pub functions: Vec<FunctionFacts>,
    /// The functions the module exports, by exported name.
    pub exports: Vec<(String, usize)>,
    /// Exported things that are not functions — memory, tables, globals.
    pub other_exports: Vec<String>,
}

impl Module {
    /// Reads a Wasm module from a file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, WasmError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|error| WasmError(format!("{}: {error}", path.display())))?;
        Self::parse(&bytes, &path.display().to_string())
    }

    /// Reads a Wasm module from memory.
    ///
    /// `path` is only used in messages and in the report, so a test can name the shape
    /// of module it assembled.
    pub fn parse(bytes: &[u8], path: &str) -> Result<Self, WasmError> {
        let mut imports = Vec::new();
        let mut functions_by_type: Vec<u32> = Vec::new();
        let mut bodies: Vec<FunctionFacts> = Vec::new();
        let mut exports = Vec::new();
        let mut other_exports = Vec::new();

        for payload in Parser::new(0).parse_all(bytes) {
            match payload.map_err(|error| WasmError(format!("{path}: {error}")))? {
                Payload::ImportSection(reader) => {
                    for import in reader {
                        let import =
                            import.map_err(|error| WasmError(format!("{path}: {error}")))?;
                        // Only function imports occupy a function index. A memory or
                        // global import shifts nothing in the index space this crate
                        // reasons about.
                        if let TypeRef::Func(_) = import.ty {
                            imports.push(HostImport {
                                index: imports.len(),
                                module: import.module.to_owned(),
                                name: import.name.to_owned(),
                            });
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for type_index in reader {
                        functions_by_type.push(
                            type_index.map_err(|error| WasmError(format!("{path}: {error}")))?,
                        );
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export =
                            export.map_err(|error| WasmError(format!("{path}: {error}")))?;
                        match export.kind {
                            ExternalKind::Func => {
                                exports.push((export.name.to_owned(), export.index as usize));
                            }
                            _ => other_exports.push(export.name.to_owned()),
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => {
                    bodies.push(read_body(&body, path)?);
                }
                _ => {}
            }
        }

        if bodies.is_empty() && functions_by_type.is_empty() {
            return Err(WasmError(format!(
                "{path}: no function bodies and no function declarations, so this is not a \
                 compiled contract (a module with neither is usually a stub)"
            )));
        }
        if bodies.len() != functions_by_type.len() {
            return Err(WasmError(format!(
                "{path}: the function section declares {} functions and the code section \
                 holds {}, which cannot both be true",
                functions_by_type.len(),
                bodies.len()
            )));
        }

        // Split each body's call sites into calls to functions defined here and calls to
        // host imports. It happens here, once the import count is known, rather than in
        // the body reader: an imported function's cost lives in the host and is metered
        // by the network, so it must not be added to a cost computed from this module.
        let base = imports.len();
        for facts in &mut bodies {
            let (host, internal) = facts.calls.drain(..).partition(|index| *index < base);
            facts.host_calls = host;
            facts.calls = internal;
        }

        // A contract's entrypoints come from the export section, but a Wasm module
        // exported from an index that nobody defines is a broken artefact rather than a
        // finding, so it is refused here instead of being reported as a function with no
        // body.
        let function_indices = imports.len() + bodies.len();
        for (name, index) in &exports {
            if *index >= function_indices {
                return Err(WasmError(format!(
                    "{path}: export `{name}` names function {index}, and the module defines \
                     {}",
                    function_indices
                )));
            }
        }

        Ok(Self {
            path: path.to_owned(),
            bytes: bytes.len(),
            imports,
            functions: bodies,
            exports,
            other_exports,
        })
    }

    /// The absolute index of the first function this module defines.
    pub fn defined_base(&self) -> usize {
        self.imports.len()
    }

    /// The number of functions in the module's index space.
    pub fn function_count(&self) -> usize {
        self.imports.len() + self.functions.len()
    }

    /// The facts for a function by absolute index, if it is defined here.
    pub fn function(&self, index: usize) -> Option<&FunctionFacts> {
        index
            .checked_sub(self.defined_base())
            .and_then(|offset| self.functions.get(offset))
    }

    /// The host function at an absolute index, if that index is an import.
    pub fn host_import(&self, index: usize) -> Option<&HostImport> {
        self.imports.get(index)
    }
}

/// Reads one function body's facts.
fn read_body(body: &wasmparser::FunctionBody<'_>, path: &str) -> Result<FunctionFacts, WasmError> {
    let mut facts = FunctionFacts::default();
    let mut reader = body
        .get_operators_reader()
        .map_err(|error| WasmError(format!("{path}: {error}")))?;

    while !reader.eof() {
        let operator = reader
            .read()
            .map_err(|error| WasmError(format!("{path}: {error}")))?;
        match operator {
            // `end` closes the body or an enclosing block. It is structure, not work, so
            // it is the one operator that is not counted.
            Operator::End => continue,
            Operator::Call { function_index } => {
                facts.calls.push(function_index as usize);
            }
            Operator::CallIndirect { .. } => facts.indirect_calls += 1,
            Operator::Loop { .. } => facts.loops += 1,
            Operator::Br { .. } | Operator::BrIf { .. } | Operator::BrTable { .. } => {
                facts.branches += 1
            }
            _ => {}
        }
        facts.instructions += 1;
    }

    Ok(facts)
}
