//! The detectors, and the registry generated from the files in this directory.
//!
//! One detector per file, one rule per detector, and no shared list to edit: `build.rs`
//! reads this directory and emits the registry, so a new detector is a new file plus its
//! rule metadata, and two contributor pull requests never touch the same line.
//!
//! Every detector in this module is written against the same contract, and the crate's
//! tests enforce it:
//!
//! * it names its rule with [`Detector::id`](crate::detector::Detector::id), and that
//!   rule's metadata loads;
//! * its rule's `examples.triggers` produces at least one finding from **it**;
//! * its rule's `examples.clean` produces none.
//!
//! The middle two are what make "one detector per pull request" a real contribution
//! standard rather than a wish, because a new detector cannot merge without both
//! fixtures — and they are written as part of the rule the detector declares.

mod registry {
    include!(concat!(env!("OUT_DIR"), "/detector_registry.rs"));
}

pub use registry::all;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Analyzer;

    #[test]
    fn the_registry_is_not_empty_and_is_in_a_stable_order() {
        let names = registry::DETECTOR_MODULES;
        assert!(
            !names.is_empty(),
            "a registry with no detectors is a broken build"
        );
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        assert_eq!(names, sorted.as_slice(), "the build script sorts these");
        assert_eq!(
            all().len(),
            names.len(),
            "every registered module must contribute exactly one detector"
        );
    }

    #[test]
    fn the_embedded_analyzer_has_a_rule_for_every_detector() {
        // The same check `Analyzer::validate` makes, asserted here as well so that a
        // missing rule file is a test failure rather than a runtime message.
        let analyzer = Analyzer::embedded();
        assert_eq!(analyzer.validate(), Vec::<String>::new());
        assert_eq!(analyzer.detectors().len(), registry::DETECTOR_MODULES.len());
    }
}
