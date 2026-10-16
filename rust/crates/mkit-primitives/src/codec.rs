//! Private bounded cursor and shared cumulative decode budget.
use crate::error::{BoundedDetail, Failure, FailureCode, Location};

fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

/// A single mutable budget is borrowed by every nested cursor.
#[derive(Debug)]
pub(crate) struct Budget {
    work: u64,
    owned: u64,
}
impl Budget {
    pub(crate) const fn new(work: u64, owned: u64) -> Self {
        Self { work, owned }
    }
    /// Charge before work or allocation; failure leaves both counters unchanged.
    pub(crate) fn charge(&mut self, work: u64, owned: u64) -> Result<(), Failure> {
        let next_work = self
            .work
            .checked_sub(work)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        let next_owned = self
            .owned
            .checked_sub(owned)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        self.work = next_work;
        self.owned = next_owned;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Cursor<'a, 'b> {
    bytes: &'a [u8],
    offset: usize,
    budget: &'b mut Budget,
}
impl<'a, 'b> Cursor<'a, 'b> {
    pub(crate) const fn new(bytes: &'a [u8], budget: &'b mut Budget) -> Self {
        Self {
            bytes,
            offset: 0,
            budget,
        }
    }
    pub(crate) fn take(&mut self, len: u64) -> Result<&'a [u8], Failure> {
        let len = usize::try_from(len).map_err(|_| failure(FailureCode::ResourceLimit))?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| failure(FailureCode::UnexpectedEof))?;
        self.budget.charge(1, 0)?;
        self.offset = end;
        Ok(bytes)
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Failure> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| failure(FailureCode::UnexpectedEof))?;
        Ok(u32::from_le_bytes(bytes))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Failure> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| failure(FailureCode::UnexpectedEof))?;
        Ok(u64::from_le_bytes(bytes))
    }
    pub(crate) fn finish(self) -> Result<(), Failure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(failure(FailureCode::TrailingData))
        }
    }
    /// Fallible copy after bounds and shared ownership/work charges.
    pub(crate) fn owned(&mut self, len: u64, cap: u64) -> Result<Vec<u8>, Failure> {
        if len > cap {
            return Err(failure(FailureCode::ResourceLimit));
        }
        self.budget.charge(len, len)?;
        let bytes = self.take(len)?;
        let mut out = Vec::new();
        out.try_reserve_exact(bytes.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        out.extend_from_slice(bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_cursors_share_work_and_copy_budget() {
        let mut budget = Budget::new(3, 2);
        assert_eq!(
            Cursor::new(&[1, 2], &mut budget).owned(2, 2).unwrap(),
            [1, 2]
        );
        let error = Cursor::new(&[1], &mut budget).owned(1, 1).unwrap_err();
        assert_eq!(error.code, FailureCode::ResourceLimit);
        assert_eq!(budget.owned, 0);
    }
    #[test]
    fn charge_failure_is_atomic() {
        let mut budget = Budget::new(5, 2);
        assert!(budget.charge(3, 3).is_err());
        assert_eq!((budget.work, budget.owned), (5, 2));
    }
    #[test]
    fn truncation_overflow_caps_and_trailing_bytes_refuse() {
        let mut budget = Budget::new(100, 100);
        assert_eq!(
            Cursor::new(&[], &mut budget).u32().unwrap_err().code,
            FailureCode::UnexpectedEof
        );
        assert!(Cursor::new(&[], &mut budget).take(u64::MAX).is_err());
        assert!(Cursor::new(&[1, 2], &mut budget).owned(2, 1).is_err());
        assert_eq!(
            Cursor::new(&[1], &mut budget).finish().unwrap_err().code,
            FailureCode::TrailingData
        );
        let mut cursor = Cursor::new(&[1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0], &mut budget);
        assert_eq!(cursor.u32().unwrap(), 1);
        assert_eq!(cursor.u64().unwrap(), 2);
        cursor.finish().unwrap();
    }
}
