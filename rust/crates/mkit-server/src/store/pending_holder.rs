//! Durable queued-holder identity. It never expires by age: only the
//! matching atomic holder delivery or proven intent reconciliation releases it.
use super::{Holder, Key, Partition, StoreError, Value, keys};
use mkit_core::hash::{Hash, Hasher};

/// Identity of a pending extraction holder intent, stored under `gp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHolderV1 {
    /// Repository that will hold the object.
    pub holder: Holder,
    /// Source partition retaining the queued work.
    pub source: Partition,
    /// Verification job's consuming ticket.
    pub ticket: Hash,
    /// Protected object; checked against the gp/request key.
    pub object: Hash,
    /// Matching ordinary extraction hold.
    pub hold_id: Hash,
    /// Stable source operation, unchanged by transport retries.
    pub operation: Hash,
    /// Domain-bound relay intent identity, distinct from transport redelivery.
    pub intent: Hash,
}

impl PendingHolderV1 {
    /// Construct one stable intent from its complete provenance.
    pub fn new(
        holder: Holder,
        source: Partition,
        ticket: Hash,
        object: Hash,
        hold_id: Hash,
        operation: Hash,
    ) -> Result<Self, StoreError> {
        let mut record = Self {
            holder,
            source,
            ticket,
            object,
            hold_id,
            operation,
            intent: [0; 32],
        };
        record.intent = record.intent_id()?;
        record.validate()?;
        Ok(record)
    }

    fn intent_id(&self) -> Result<Hash, StoreError> {
        let mut hasher = Hasher::new();
        hasher.update(b"mkit-content-holder-intent:v1");
        for bytes in [
            self.source.encode()?.as_ref(),
            keys::holder(&self.object, &self.holder.ns, &self.holder.repo)?.as_bytes(),
            &self.ticket,
            &self.hold_id,
            &self.operation,
        ] {
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        Ok(hasher.finalize())
    }

    fn validate(&self) -> Result<(), StoreError> {
        let bound = match &self.source {
            Partition::Namespace(ns) => ns == &self.holder.ns,
            Partition::Ref { ns, repo, .. } => ns == &self.holder.ns && repo == &self.holder.repo,
            _ => false,
        };
        if !bound || self.intent != self.intent_id()? {
            return Err(StoreError::Corrupt("pending holder source mismatch".into()));
        }
        Ok(())
    }

    /// Strict bounded canonical encoding; binds both repository and source.
    pub fn encode(&self) -> Result<Value, StoreError> {
        self.validate()?;
        let source = self.source.encode()?;
        let owner = keys::holder(&[0; 32], &self.holder.ns, &self.holder.repo)?;
        let mut bytes = vec![1];
        for field in [source.as_ref(), owner.as_bytes()] {
            let len = u16::try_from(field.len())
                .map_err(|_| StoreError::Invalid("pending holder identity too large".into()))?;
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(field);
        }
        for hash in [
            &self.ticket,
            &self.object,
            &self.hold_id,
            &self.operation,
            &self.intent,
        ] {
            bytes.extend_from_slice(hash);
        }
        if bytes.len() > 4096 {
            return Err(StoreError::Invalid(
                "pending holder identity too large".into(),
            ));
        }
        Ok(Value::new(bytes))
    }

    /// Unknown, malformed or noncanonical identity is never releasable.
    pub fn decode(value: &Value) -> Result<Self, StoreError> {
        fn corrupt() -> StoreError {
            StoreError::Corrupt("bad pending holder identity".into())
        }
        fn field<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], StoreError> {
            let Some((len, rest)) = bytes.split_first_chunk::<2>() else {
                return Err(corrupt());
            };
            let len = usize::from(u16::from_be_bytes(*len));
            let Some((value, tail)) = rest.split_at_checked(len) else {
                return Err(corrupt());
            };
            *bytes = tail;
            Ok(value)
        }
        if value.as_bytes().len() > 4096 {
            return Err(corrupt());
        }
        let Some((&1, mut rest)) = value.as_bytes().split_first() else {
            return Err(corrupt());
        };
        let source = Partition::decode(field(&mut rest)?)?;
        let owner = Key::new(field(&mut rest)?.to_vec());
        let Some(keys::ParsedKey::Holder { object, ns, repo }) = keys::parse(&owner) else {
            return Err(corrupt());
        };
        if object != [0; 32] {
            return Err(corrupt());
        }
        let hashes: &[u8; 160] = rest.try_into().map_err(|_| corrupt())?;
        let at = |i| hashes[i..i + 32].try_into().map_err(|_| corrupt());
        let record = Self {
            holder: Holder::new(ns, repo),
            source,
            ticket: at(0)?,
            object: at(32)?,
            hold_id: at(64)?,
            operation: at(96)?,
            intent: at(128)?,
        };
        record.validate()?;
        if record.encode()? != *value {
            return Err(corrupt());
        }
        Ok(record)
    }
}
