//! Fuzzing configuration.

use std::path::PathBuf;

use crate::budget::{mainnet_limits, InvocationResourceLimits};

/// How the harness treats Soroban authorization during a fuzz run.
///
/// The default is [`AuthPolicy::Strict`] because the single most common Soroban
/// vulnerability class is a missing `require_auth`: a contract that mutates state
/// for an address that never authorized the call. Mocking every authorization
/// makes that class of bug *invisible*, so the harness leaves it unmocked unless
/// you ask otherwise.
///
/// The policy is applied before every action, so an action that wants to exercise
/// a specific authorization can still install its own via
/// [`crate::Runtime::env`] without leaking into later actions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthPolicy {
    /// No authorization is mocked. A call that needs `require_auth` and does not
    /// present credentials is rejected by the contract.
    #[default]
    Strict,
    /// Every `require_auth` call succeeds, as if credentials were supplied.
    ///
    /// Useful for fuzzing business logic deeply, but it cannot detect missing
    /// authorization checks. Combine with explicit invariants if you use it.
    MockAll,
}

/// How the harness reacts to invocations that exceed network resource limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResourcePolicy {
    /// Disable the SDK's own limit enforcement and enforce
    /// [`FuzzConfig::limits`] in the harness instead.
    ///
    /// This is the default because a breach is then reported as a structured
    /// finding naming the limit, the measured value, the excess, and the exact
    /// action in the shrunk sequence — instead of a panic from inside the host.
    #[default]
    Enforce,
    /// Measure and record resource usage without ever failing a case.
    Record,
    /// Leave the SDK's default mainnet limit enforcement enabled.
    ///
    /// A breach panics inside the host and is reported as a failure with far less
    /// detail than [`ResourcePolicy::Enforce`].
    Sdk,
}

/// Knobs for a fuzz run.
///
/// Start from [`FuzzConfig::default`] and adjust with the builder methods, or use
/// [`FuzzConfig::from_env`] so CI can widen a run without a code change.
#[derive(Clone, Debug)]
pub struct FuzzConfig {
    /// Number of generated call sequences to run. Defaults to `128`.
    pub cases: u32,
    /// Minimum number of actions per sequence. Defaults to `1`.
    pub min_actions: usize,
    /// Maximum number of actions per sequence. Defaults to `12`.
    pub max_actions: usize,
    /// Fixed RNG seed. `None` picks a fresh seed each run and reports it.
    pub seed: Option<u64>,
    /// Authorization policy. Defaults to [`AuthPolicy::Strict`].
    pub auth: AuthPolicy,
    /// Resource-limit policy. Defaults to [`ResourcePolicy::Enforce`].
    pub resources: ResourcePolicy,
    /// Resource ceilings used by [`ResourcePolicy::Enforce`]. Defaults to the
    /// network's mainnet limits.
    pub limits: InvocationResourceLimits,
    /// Maximum shrink attempts once a failure is found. Defaults to `1024`.
    pub max_shrink_iters: u32,
    /// Write proptest's `proptest-regressions` files on failure. Defaults to
    /// `false`; the harness's own JSON report is usually more useful.
    pub persist_failures: bool,
    /// Where to write the JSON failure report. `None` writes nothing.
    pub report_path: Option<PathBuf>,
    /// proptest verbosity: `0` silent, `1` logs each case, `2` logs each action.
    pub verbose: u32,
    /// Warn when at least this fraction of generated actions was rejected by the
    /// contract without the target expecting it. Defaults to `Some(0.5)`; `None`
    /// disables the warning.
    ///
    /// A run that warns has still passed. See
    /// [`FuzzOutcome::Passed`](crate::FuzzOutcome::Passed) for why that is worth
    /// knowing about.
    pub rejection_warning_ratio: Option<f64>,
    /// Run only this case of the seeded sequence, instead of all of them. `None`
    /// (the default) runs every case.
    ///
    /// Reproducing one case by re-running a whole run is a lot of noise when a target
    /// takes minutes per run, and a failing case's report already names the one worth
    /// looking at. Replaying is only meaningful against a pinned [`FuzzConfig::seed`],
    /// because the index names a position in the generated stream; without a seed the
    /// run aborts with a message saying so rather than quietly running some other case.
    pub replay_case: Option<u32>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            cases: 128,
            min_actions: 1,
            max_actions: 12,
            seed: None,
            auth: AuthPolicy::Strict,
            resources: ResourcePolicy::Enforce,
            limits: mainnet_limits(),
            max_shrink_iters: 1024,
            persist_failures: false,
            report_path: None,
            verbose: 0,
            rejection_warning_ratio: Some(0.5),
            replay_case: None,
        }
    }
}

impl FuzzConfig {
    /// Builds a configuration from the environment, falling back to defaults.
    ///
    /// Recognised variables:
    ///
    /// | Variable | Meaning |
    /// | --- | --- |
    /// | `SOROBAN_FUZZ_CASES` | Number of cases to run |
    /// | `SOROBAN_FUZZ_SEED` | Fixed RNG seed |
    /// | `SOROBAN_FUZZ_MAX_ACTIONS` | Maximum actions per sequence |
    /// | `SOROBAN_FUZZ_REPORT` | Path for the JSON failure report |
    /// | `SOROBAN_FUZZ_REPLAY` | Run only this case of the seeded sequence |
    ///
    /// Unparsable values are ignored and fall back to the default, so a malformed
    /// CI variable can never turn a green run red.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(cases) = env_parse::<u32>("SOROBAN_FUZZ_CASES") {
            config.cases = cases;
        }
        if let Some(max_actions) = env_parse::<usize>("SOROBAN_FUZZ_MAX_ACTIONS") {
            config.max_actions = max_actions;
        }
        if let Some(seed) = env_parse::<u64>("SOROBAN_FUZZ_SEED") {
            config.seed = Some(seed);
        }
        if let Some(index) = env_parse::<u32>("SOROBAN_FUZZ_REPLAY") {
            config.replay_case = Some(index);
        }
        if let Ok(path) = std::env::var("SOROBAN_FUZZ_REPORT") {
            if !path.is_empty() {
                config.report_path = Some(PathBuf::from(path));
            }
        }
        config
    }

    /// Sets the number of cases to run.
    pub fn cases(mut self, cases: u32) -> Self {
        self.cases = cases;
        self
    }

    /// Sets the inclusive action-count range for a generated sequence.
    pub fn actions(mut self, min: usize, max: usize) -> Self {
        self.min_actions = min;
        self.max_actions = max.max(min);
        self
    }

    /// Fixes the RNG seed so a failure is reproducible.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Sets the authorization policy.
    pub fn auth(mut self, auth: AuthPolicy) -> Self {
        self.auth = auth;
        self
    }

    /// Sets the resource-limit policy.
    pub fn resources(mut self, resources: ResourcePolicy) -> Self {
        self.resources = resources;
        self
    }

    /// Overrides the resource ceilings used for enforcement.
    pub fn limits(mut self, limits: InvocationResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Writes a JSON failure report to `path`.
    pub fn report_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.report_path = Some(path.into());
        self
    }

    /// Enables proptest's `proptest-regressions` persistence.
    pub fn persist_failures(mut self, persist: bool) -> Self {
        self.persist_failures = persist;
        self
    }

    /// Sets proptest verbosity.
    pub fn verbose(mut self, verbose: u32) -> Self {
        self.verbose = verbose;
        self
    }

    /// Sets the fraction of unexpectedly-rejected actions at which to warn, or `None`
    /// to disable the warning.
    pub fn rejection_warning_ratio(mut self, ratio: Option<f64>) -> Self {
        self.rejection_warning_ratio = ratio;
        self
    }

    /// Runs only case `index` of the seeded sequence.
    ///
    /// Pair this with [`FuzzConfig::seed`]; on its own it aborts, because a case index
    /// without a seed does not name the same case twice.
    pub fn replay_case(mut self, index: u32) -> Self {
        self.replay_case = Some(index);
        self
    }

    /// A serializable summary for inclusion in failure reports.
    pub fn summary(&self) -> crate::report::ReportConfig {
        crate::report::ReportConfig {
            cases: self.cases,
            min_actions: self.min_actions,
            max_actions: self.max_actions,
            seed: self.seed,
            auth: match self.auth {
                AuthPolicy::Strict => "strict".to_owned(),
                AuthPolicy::MockAll => "mock_all".to_owned(),
            },
            resources: match self.resources {
                ResourcePolicy::Enforce => "enforce".to_owned(),
                ResourcePolicy::Record => "record".to_owned(),
                ResourcePolicy::Sdk => "sdk".to_owned(),
            },
        }
    }
}

fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok()?.trim().parse().ok()
}
