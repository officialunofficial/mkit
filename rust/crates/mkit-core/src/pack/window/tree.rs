//! A binary-counter stack of complete power-of-two windows. Keep the final
//! window separate: a root cannot be recovered from a merged non-root CV.
use super::PackError;
use crate::hash::{self, Hash};
use blake3::hazmat::{self, HasherExt, Mode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Tree {
    pub stack: Vec<Hash>,
    pub root: Option<Hash>,
}

impl Tree {
    pub(super) fn new() -> Self {
        Self {
            stack: Vec::new(),
            root: None,
        }
    }

    pub(super) fn absorb(
        &mut self,
        offset: u64,
        bytes: &[u8],
        total: u64,
        window: u64,
    ) -> Result<(), PackError> {
        if offset >= total {
            return Ok(());
        }
        let len = total
            .checked_sub(offset)
            .ok_or(PackError::PackfileCorrupted)?
            .min(u64::try_from(bytes.len()).map_err(|_| PackError::PackfileTooLarge)?);
        let input = &bytes[..super::us(len)?];
        if offset == 0 && len == total {
            self.root = Some(hash::hash(input));
            return Ok(());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset(offset);
        hasher.update(input);
        let mut cv = hasher.finalize_non_root();
        if offset.checked_add(len) == Some(total) {
            // The highest prefix CV is the root's complete left subtree;
            // fold the smaller prefix CVs into the final right subtree.
            let split = hazmat::left_subtree_len(total);
            if !split.is_multiple_of(window) || offset / split != 1 {
                return Err(PackError::PackfileCorrupted);
            }
            let (left, rest) = self
                .stack
                .split_first()
                .ok_or(PackError::PackfileCorrupted)?;
            for left in rest.iter().rev() {
                cv = hazmat::merge_subtrees_non_root(left, &cv, Mode::Hash);
            }
            self.root = Some(*hazmat::merge_subtrees_root(left, &cv, Mode::Hash).as_bytes());
        } else {
            // These windows are all exactly `window` bytes. Binary carries
            // produce the same left-balanced splits as left_subtree_len.
            let mut count = offset / window;
            while count & 1 != 0 {
                let left = self.stack.pop().ok_or(PackError::PackfileCorrupted)?;
                cv = hazmat::merge_subtrees_non_root(&left, &cv, Mode::Hash);
                count >>= 1;
            }
            self.stack
                .try_reserve(1)
                .map_err(|_| PackError::PackfileTooLarge)?;
            self.stack.push(cv);
        }
        Ok(())
    }

    pub(super) fn validate(&self, completed: u64, total: u64, window: u64) -> bool {
        let prefix = (total - 1) / window;
        self.stack.len() == completed.min(prefix).count_ones() as usize
            && self.root.is_some() == (completed > prefix)
    }
}
