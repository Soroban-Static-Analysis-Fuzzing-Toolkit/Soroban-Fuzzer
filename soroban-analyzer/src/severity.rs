//! Finding severity, and the gate a run exits on.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// How much a finding matters.
///
/// The scale is deliberately small and ordered, because its two jobs are to sort
/// output and to be compared against an exit threshold. Both need a total order and
/// neither needs a taxonomy.
///
/// The severities used by this crate's own rules:
///
/// | Severity | Means |
/// | --- | --- |
/// | [`Severity::Critical`] | Funds or authorization are directly at risk |
/// | [`Severity::High`] | A privileged path is unprotected, or a call cannot land on mainnet |
/// | [`Severity::Medium`] | State can be lost, or a call fails for part of its input range |
/// | [`Severity::Low`] | Robustness, cost or maintainability, with no direct loss |
/// | [`Severity::Info`] | Worth knowing; not a defect |
///
/// Note that "traps instead of wrapping" keeps unchecked arithmetic out of the top
/// two rungs even though it is a real bug: with `overflow-checks = true` a Soroban
/// contract panics rather than minting value, so the failure is a denial of service
/// rather than a loss of funds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing; not a defect.
    Info,
    /// Robustness, cost or maintainability, with no direct loss.
    Low,
    /// State can be lost, or a call fails for part of its input range.
    Medium,
    /// A privileged path is unprotected, or a call cannot land on mainnet.
    High,
    /// Funds or authorization are directly at risk.
    Critical,
}

impl Severity {
    /// Every severity, weakest first.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Lowercase name, as it appears in rule metadata and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::ALL
            .into_iter()
            .find(|severity| severity.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| {
                let allowed = Severity::ALL.map(Severity::as_str).join(", ");
                format!("unknown severity `{s}`; expected one of: {allowed}")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_order_from_info_to_critical() {
        let mut ordered = Severity::ALL.to_vec();
        ordered.sort();
        assert_eq!(ordered, Severity::ALL, "ALL must already be weakest-first");
        assert!(Severity::High > Severity::Medium);
    }

    #[test]
    fn parsing_is_case_insensitive_and_reports_the_allowed_set() {
        assert_eq!("CRITICAL".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!(" medium ".parse::<Severity>().unwrap(), Severity::Medium);
        let err = "nope".parse::<Severity>().unwrap_err();
        assert!(err.contains("info, low, medium, high, critical"), "{err}");
    }
}
