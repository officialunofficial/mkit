// Shared adversarial wire fixtures for each listing driver.
/// One scripted listing and its expected validity.
#[derive(Debug)]
pub struct ListingCase {
    /// Description shown on failure.
    pub name: &'static str,
    /// Ordered response pages (names and continuation token).
    pub pages: Vec<(Vec<String>, Option<String>)>,
    /// Lower page cap supplied to the listing driver.
    pub max_pages: u32,
    /// Whether the complete listing is accepted.
    pub valid: bool,
}
/// Adversarial and successful listings shared by the three driver suites.
#[must_use]
pub fn listing_cases() -> Vec<ListingCase> {
    let page = |names: &[&str], token: Option<&str>| {
        (
            names.iter().map(|name| (*name).to_owned()).collect(),
            token.map(str::to_owned),
        )
    };
    vec![
        ListingCase {
            name: "byte budget exhaustion",
            // 105 pages fit; page 106 crosses the shared 128 MiB charge.
            // Each name is a valid 496-byte branch ref; every encoded page
            // stays below 2 MiB, so the failure is cumulative state alone.
            pages: (0..106)
                .map(|page| {
                    (
                        (0..2048)
                            .map(|entry| {
                                format!("refs/heads/{:06}{}", page * 2048 + entry, "x".repeat(479))
                            })
                            .collect(),
                        Some(format!("shared-page-{}", page + 1)),
                    )
                })
                .collect(),
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "page cap exhaustion",
            pages: (0..16)
                .map(|n| (vec![], Some(format!("shared-page-{}", n + 1))))
                .collect(),
            max_pages: 16,
            valid: false,
        },
        ListingCase {
            name: "near two MiB empty cursor",
            pages: vec![(vec![], Some("x".repeat(2 * 1024 * 1024 - 128)))],
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "oversized empty cursor",
            pages: vec![(vec![], Some("x".repeat(4097)))],
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "long cursor cycle",
            pages: (0..32)
                .map(|n| page(&[], Some(&format!("cursor-{n}"))))
                .chain([page(&[], Some("cursor-0"))])
                .collect(),
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "unordered",
            pages: vec![page(&["b", "a"], None)],
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "overlapping",
            pages: vec![
                page(&["b"], Some("next")),
                page(&[], Some("after-empty")),
                page(&["a"], None),
            ],
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "duplicate within page",
            pages: vec![page(&["a", "a"], None)],
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "duplicate across pages",
            pages: vec![page(&["a"], Some("next")), page(&["a"], None)],
            max_pages: 100_000,
            valid: false,
        },
        ListingCase {
            name: "happy path",
            pages: vec![
                page(&["a", "b"], Some("next")),
                page(&[], Some("after-empty")),
                page(&["c"], Some("")),
            ],
            max_pages: 100_000,
            valid: true,
        },
    ]
}
