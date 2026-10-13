//! Runtime-free, bounded accumulation of strictly ordered ref pages.

use std::collections::HashSet;

use crate::hash::{Hash, hash};

/// Maximum pages requested by any complete listing.
pub const MAX_PAGES: u32 = 100_000;
/// Maximum bytes in one opaque continuation token.
pub const MAX_CURSOR_BYTES: usize = 4096;
/// Shared retained-state budget, including names, entries, and cursor history.
pub const MAX_RETAINED_BYTES: usize = 128 * 1024 * 1024;
// Conservative collection charges include vector spare capacity / hash-table
// load factor, control bytes, and the 32-byte object id or cursor digest.
// Covers the state struct and minimum collection allocations.
const FIXED_BYTES: usize = 1024;
const ENTRY_BYTES: usize = 128;
const CURSOR_HISTORY_BYTES: usize = 128;

/// Invalid or excessive remote listing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or excessive ref listing")]
pub struct InvalidListing;

/// Reject unordered names and duplicates within one page.
///
/// # Errors
/// Returns [`InvalidListing`] unless names are strictly increasing.
pub fn validate_page<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), InvalidListing> {
    let mut previous = None;
    for name in names {
        if previous.is_some_and(|last| last >= name) {
            return Err(InvalidListing);
        }
        previous = Some(name);
    }
    Ok(())
}

/// Accumulates decoded refs without retaining unbounded opaque cursors.
///
/// `T` must occupy at most 64 bytes inline and own no heap allocations except
/// its name string. `name` supplies that string; its allocation is compacted to its length
/// before charging, so decoding allocation strategies cannot change the limits.
/// All three drivers use the same fixed limits; `max_pages` can only lower
/// the page cap. Hash collisions conservatively reject a listing.
#[derive(Debug)]
pub struct RefListing<T> {
    refs: Vec<T>,
    cursor: String,
    seen: HashSet<Hash>,
    retained: usize,
    pages: u32,
    max_pages: u32,
    max_bytes: usize,
    finished: bool,
}

impl<T> RefListing<T> {
    /// Start a listing with safe fixed limits and an optional lower page cap.
    #[must_use]
    pub fn new(max_pages: u32) -> Self {
        Self {
            refs: Vec::new(),
            cursor: String::new(),
            seen: HashSet::new(),
            retained: FIXED_BYTES,
            pages: 0,
            max_pages: max_pages.min(MAX_PAGES),
            max_bytes: MAX_RETAINED_BYTES,
            finished: false,
        }
    }

    /// Whether another page may be requested.
    #[must_use]
    pub fn can_request(&self) -> bool {
        !self.finished && self.pages < self.max_pages
    }

    /// Token for the next request; initially empty.
    #[must_use]
    pub fn cursor(&self) -> &str {
        &self.cursor
    }

    /// Validate and retain one page. Returns `true` at the end of the listing.
    ///
    /// # Errors
    /// Invalid ordering, a cursor cycle, or an exceeded resource cap.
    pub fn push(
        &mut self,
        mut page: Vec<T>,
        next: Option<String>,
        name: fn(&mut T) -> &mut String,
    ) -> Result<bool, InvalidListing> {
        if !self.can_request() || std::mem::size_of::<T>() > ENTRY_BYTES / 2 {
            return Err(InvalidListing);
        }
        validate_page(page.iter_mut().map(|entry| name(entry).as_str()))?;
        if let (Some(last), Some(first)) = (self.refs.last_mut(), page.first_mut())
            && name(last) >= name(first)
        {
            return Err(InvalidListing);
        }
        let next = next.filter(|token| !token.is_empty());
        let cursor_len = next.as_ref().map_or(0, String::len);
        if cursor_len > MAX_CURSOR_BYTES {
            return Err(InvalidListing);
        }
        let digest = next.as_ref().map(|token| hash(token.as_bytes()));
        if digest.is_some_and(|id| self.seen.contains(&id)) {
            return Err(InvalidListing);
        }
        // Replace the active cursor charge; history retains only fixed digests.
        let mut retained = self.retained - self.cursor.len();
        for entry in &mut page {
            let compact = std::mem::take(name(entry)).into_boxed_str().into_string();
            *name(entry) = compact;
            retained = retained
                .checked_add(name(entry).len())
                .and_then(|bytes| bytes.checked_add(ENTRY_BYTES))
                .ok_or(InvalidListing)?;
        }
        retained = retained
            .checked_add(cursor_len)
            .and_then(|bytes| {
                bytes.checked_add(if digest.is_some() {
                    CURSOR_HISTORY_BYTES
                } else {
                    0
                })
            })
            .ok_or(InvalidListing)?;
        if retained > self.max_bytes || (next.is_some() && self.pages + 1 == self.max_pages) {
            return Err(InvalidListing);
        }
        self.refs.extend(page);
        if let Some(id) = digest {
            self.seen.insert(id);
        }
        // Copy only the bounded bytes, discarding any excess input capacity.
        let cursor = next.as_deref().unwrap_or_default().to_owned();
        self.cursor = cursor;
        self.retained = retained;
        self.pages += 1;
        self.finished = next.is_none();
        Ok(self.finished)
    }

    /// Consume a completed listing.
    ///
    /// # Errors
    /// The final page has not been accepted.
    pub fn finish(self) -> Result<Vec<T>, InvalidListing> {
        if self.finished {
            Ok(self.refs)
        } else {
            Err(InvalidListing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn name(entry: &mut String) -> &mut String {
        entry
    }
    #[test]
    fn byte_budget_charges_refs_history_and_active_cursor() {
        let mut listing = RefListing::new(10);
        listing.max_bytes = FIXED_BYTES + ENTRY_BYTES + CURSOR_HISTORY_BYTES + 2;
        assert!(
            !listing
                .push(vec!["a".into()], Some("A".into()), name)
                .unwrap()
        );
        assert_eq!(
            listing.retained,
            FIXED_BYTES + ENTRY_BYTES + CURSOR_HISTORY_BYTES + 2
        );
        assert_eq!(
            listing.push(vec![], Some("B".into()), name),
            Err(InvalidListing)
        );
        assert_eq!(
            listing.retained,
            FIXED_BYTES + ENTRY_BYTES + CURSOR_HISTORY_BYTES + 2
        );
        let mut listing = RefListing::new(10);
        listing.max_bytes = FIXED_BYTES + ENTRY_BYTES;
        assert_eq!(
            listing.push(vec!["a".into()], None, name),
            Err(InvalidListing)
        );
    }
    #[test]
    fn page_cap_includes_empty_pages_and_accepts_terminal_at_cap() {
        let mut listing: RefListing<String> = RefListing::new(2);
        assert!(!listing.push(vec![], Some("A".into()), name).unwrap());
        assert_eq!(
            listing.push(vec![], Some("B".into()), name),
            Err(InvalidListing)
        );
        assert!(listing.push(vec![], None, name).unwrap());
        assert_eq!(listing.push(vec![], None, name), Err(InvalidListing));
        assert!(listing.finish().unwrap().is_empty());
        assert!(!RefListing::<String>::new(0).can_request());
        assert_eq!(RefListing::<String>::new(u32::MAX).max_pages, MAX_PAGES);
    }
    #[test]
    fn cursor_capacity_is_discarded_and_empty_tokens_finish() {
        let mut cursor = String::with_capacity(MAX_CURSOR_BYTES * 2);
        cursor.push('A');
        let mut listing: RefListing<String> = RefListing::new(2);
        listing.push(vec![], Some(cursor), name).unwrap();
        assert_eq!(listing.cursor.capacity(), 1);
        assert_eq!(listing.retained, FIXED_BYTES + CURSOR_HISTORY_BYTES + 1);
        assert!(listing.push(vec![], Some(String::new()), name).unwrap());
        assert_eq!(listing.retained, FIXED_BYTES + CURSOR_HISTORY_BYTES);
    }
    #[test]
    fn cursor_limit_is_inclusive_and_name_capacity_is_discarded() {
        let mut listing: RefListing<String> = RefListing::new(3);
        assert!(
            listing
                .push(vec![], Some("x".repeat(MAX_CURSOR_BYTES)), name)
                .is_ok()
        );
        assert_eq!(
            listing.push(vec![], Some("y".repeat(MAX_CURSOR_BYTES + 1)), name),
            Err(InvalidListing)
        );
        let mut entry = String::with_capacity(ENTRY_BYTES * 2);
        entry.push('a');
        let mut listing = RefListing::new(1);
        listing.max_bytes = FIXED_BYTES + ENTRY_BYTES + 1;
        assert!(listing.push(vec![entry], None, name).unwrap());
        assert_eq!(listing.retained, FIXED_BYTES + ENTRY_BYTES + 1);
        assert_eq!(listing.finish().unwrap()[0].capacity(), 1);
    }
    #[test]
    fn fixed_page_cap_bounds_empty_cursor_history() {
        let mut listing: RefListing<String> = RefListing::new(u32::MAX);
        for page in 1..MAX_PAGES {
            assert!(!listing.push(vec![], Some(page.to_string()), name).unwrap());
        }
        assert_eq!(
            listing.push(vec![], Some(MAX_PAGES.to_string()), name),
            Err(InvalidListing)
        );
        assert_eq!(listing.seen.len(), (MAX_PAGES - 1) as usize);
        assert!(
            listing.retained
                <= FIXED_BYTES + CURSOR_HISTORY_BYTES * MAX_PAGES as usize + MAX_CURSOR_BYTES
        );
    }
}
