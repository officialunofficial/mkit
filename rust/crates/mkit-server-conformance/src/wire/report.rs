//! Per-case results and their TAP-like rendering.

use std::fmt::Write as _;

/// One case's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Passed, with an optional note (e.g. a measured size).
    Pass(Option<String>),
    /// Failed, with the reason.
    Fail(String),
    /// Outside the declared feature set, with the feature name.
    NotApplicable(String),
    /// Not run because of a declared gap or runner selection.
    Skip(String),
}

/// A case and its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseReport {
    /// The stable case name.
    pub name: &'static str,
    /// Its result.
    pub verdict: Verdict,
}

/// A run's results, in suite order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Lines printed as `#` comments before the results.
    pub preamble: Vec<String>,
    /// One entry per selected case.
    pub cases: Vec<CaseReport>,
}

impl Report {
    /// Names of failed cases.
    #[must_use]
    pub fn failures(&self) -> Vec<&'static str> {
        self.names(|v| matches!(v, Verdict::Fail(_)))
    }

    /// Names of skipped cases.
    #[must_use]
    pub fn skips(&self) -> Vec<&'static str> {
        self.names(|v| matches!(v, Verdict::Skip(_)))
    }

    /// Names of cases outside the declared feature set.
    #[must_use]
    pub fn not_applicable(&self) -> Vec<&'static str> {
        self.names(|v| matches!(v, Verdict::NotApplicable(_)))
    }

    /// Names of passed cases.
    #[must_use]
    pub fn passes(&self) -> Vec<&'static str> {
        self.names(|v| matches!(v, Verdict::Pass(_)))
    }

    fn names(&self, pick: impl Fn(&Verdict) -> bool) -> Vec<&'static str> {
        self.cases
            .iter()
            .filter(|c| pick(&c.verdict))
            .map(|c| c.name)
            .collect()
    }

    /// The verdict of case `name`.
    #[must_use]
    pub fn verdict(&self, name: &str) -> Option<&Verdict> {
        self.cases
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.verdict)
    }

    /// Whether any case failed: the runner then exits 1.
    #[must_use]
    pub fn failed(&self) -> bool {
        !self.failures().is_empty()
    }

    /// TAP version 14: `ok N - name`, `not ok N - name`, `# SKIP reason`,
    /// then a summary comment.
    #[must_use]
    pub fn tap(&self) -> String {
        let mut out = String::from("TAP version 14\n");
        for line in &self.preamble {
            let _ = writeln!(out, "# {line}");
        }
        let _ = writeln!(out, "1..{}", self.cases.len());
        for (i, case) in self.cases.iter().enumerate() {
            let n = i + 1;
            let name = case.name;
            let _ = match &case.verdict {
                Verdict::Pass(None) => writeln!(out, "ok {n} - {name}"),
                Verdict::Pass(Some(note)) => writeln!(out, "ok {n} - {name} # {note}"),
                Verdict::NotApplicable(why) => {
                    writeln!(out, "ok {n} - {name} # SKIP not applicable: {why}")
                }
                Verdict::Skip(why) => writeln!(out, "ok {n} - {name} # SKIP {why}"),
                Verdict::Fail(why) => {
                    let why = why.replace('\n', "\n  # ");
                    writeln!(out, "not ok {n} - {name}\n  # {why}")
                }
            };
        }
        let _ = writeln!(
            out,
            "# pass {} fail {} skip {} not-applicable {}",
            self.passes().len(),
            self.failures().len(),
            self.skips().len(),
            self.not_applicable().len()
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_lists_every_case_and_counts() {
        let report = Report {
            preamble: vec!["profile none".into()],
            cases: vec![
                CaseReport {
                    name: "a.pass",
                    verdict: Verdict::Pass(None),
                },
                CaseReport {
                    name: "b.fail",
                    verdict: Verdict::Fail("got ok\nwanted invalid_argument".into()),
                },
                CaseReport {
                    name: "c.skip",
                    verdict: Verdict::Skip("known gap".into()),
                },
                CaseReport {
                    name: "d.not_applicable",
                    verdict: Verdict::NotApplicable("quota".into()),
                },
            ],
        };
        let tap = report.tap();
        assert!(tap.contains("# profile none\n1..4\nok 1 - a.pass\nnot ok 2 - b.fail\n"));
        assert!(tap.contains("  # got ok\n  # wanted invalid_argument\n"));
        assert!(tap.contains("ok 3 - c.skip # SKIP known gap\n"));
        assert!(tap.ends_with("# pass 1 fail 1 skip 1 not-applicable 1\n"));
        assert!(tap.contains("ok 4 - d.not_applicable # SKIP not applicable: quota\n"));
        assert_eq!(report.not_applicable(), ["d.not_applicable"]);
        assert_eq!(report.skips(), ["c.skip"]);
        assert!(report.failed());
        assert_eq!(report.failures(), ["b.fail"]);
    }
}
