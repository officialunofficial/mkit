// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure validation for the optional one-repository managed service profile.
use serde::{Deserialize, Serialize};

pub const MAX_ADMIN_BODY: usize = 64 * 1024;
pub const MAX_COLLABORATORS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub audience: String,
    pub repository: String,
    pub owner: String,
}

impl Identity {
    pub fn parse(audience: &str, repository: &str, owner: &str) -> Result<Self, &'static str> {
        mkit_core::write_auth::validate_audience(audience)
            .map_err(|_| "invalid managed audience")?;
        if repository.is_empty()
            || repository.len() > 255
            || !repository.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err("invalid managed repository");
        }
        validate_key(owner)?;
        Ok(Self {
            audience: audience.into(),
            repository: repository.into(),
            owner: owner.into(),
        })
    }
}

pub fn validate_key(key: &str) -> Result<(), &'static str> {
    if !mkit_core::write_auth::is_hex(key, 32) || key.bytes().all(|b| b == b'0') {
        return Err("invalid public key");
    }
    let bytes: [u8; 32] = hex::decode(key)
        .map_err(|_| "invalid public key")?
        .try_into()
        .map_err(|_| "invalid public key")?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid public key")?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Reader,
    Writer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collaborator {
    pub public_key: String,
    pub role: Role,
}

pub fn validate_collaborators(owner: &str, members: &[Collaborator]) -> Result<(), &'static str> {
    if members.len() > MAX_COLLABORATORS {
        return Err("too many collaborators");
    }
    let mut previous = "";
    for member in members {
        validate_key(&member.public_key)?;
        if member.public_key == owner || member.public_key.as_str() <= previous {
            return Err("collaborators must be sorted, distinct and exclude owner");
        }
        previous = &member.public_key;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeRequest {
    pub version: u64,
    pub collaborators: Vec<Collaborator>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetRequest {
    pub version: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceRequest {
    pub version: u64,
    pub expected_generation: String,
    pub collaborators: Vec<Collaborator>,
}

pub fn generation(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid generation");
    }
    value.parse().map_err(|_| "invalid generation")
}

pub fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, &'static str> {
    if body.len() > MAX_ADMIN_BODY {
        return Err("request body too large");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut deserializer).map_err(|_| "invalid management JSON")?;
    deserializer.end().map_err(|_| "trailing management JSON")?;
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u64,
    pub audience: String,
    pub repository: String,
    pub owner: String,
    pub generation: String,
    pub collaborators: Vec<Collaborator>,
}

impl Policy {
    pub fn new(identity: &Identity, generation: u64, collaborators: Vec<Collaborator>) -> Self {
        Self {
            version: 1,
            audience: identity.audience.clone(),
            repository: identity.repository.clone(),
            owner: identity.owner.clone(),
            generation: generation.to_string(),
            collaborators,
        }
    }
    pub fn validate(&self, configured: &Identity) -> Result<u64, &'static str> {
        if self.version != 1
            || &(Identity {
                audience: self.audience.clone(),
                repository: self.repository.clone(),
                owner: self.owner.clone(),
            }) != configured
        {
            return Err("managed identity mismatch");
        }
        let value = generation(&self.generation)?;
        if value == 0 {
            return Err("invalid generation");
        }
        validate_collaborators(&self.owner, &self.collaborators)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(number: u32) -> String {
        let mut seed = [0; 32];
        seed[..4].copy_from_slice(&number.to_le_bytes());
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }
    fn identity() -> Identity {
        Identity::parse("https://host.example", "repo", &key(1)).unwrap()
    }
    #[test]
    fn config_is_pinned_and_canonical() {
        let owner = key(1);
        assert!(Identity::parse("https://host.example", "repo", &owner).is_ok());
        for (audience, repository, owner) in [
            ("", "repo", owner.as_str()),
            ("https://host.example/", "repo", owner.as_str()),
            ("https://host.example", "", owner.as_str()),
            ("https://host.example", "repo", "00"),
        ] {
            assert!(Identity::parse(audience, repository, owner).is_err());
        }
        assert!(Identity::parse("https://host.example", "repo", &key(2)).is_ok());
        let policy = Policy::new(&identity(), 1, vec![]);
        assert!(
            policy
                .validate(&Identity::parse("https://host.example", "repo", &key(2)).unwrap())
                .is_err()
        );
    }
    #[test]
    fn membership_is_bounded_sorted_and_owner_excluded() {
        let owner = key(1);
        let mut members: Vec<_> = (2..=257)
            .map(|i| Collaborator {
                public_key: key(i),
                role: Role::Reader,
            })
            .collect();
        members.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert!(validate_collaborators(&owner, &members).is_ok());
        let mut too_many = members.clone();
        too_many.push(Collaborator {
            public_key: key(0),
            role: Role::Writer,
        });
        too_many.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert!(validate_collaborators(&owner, &too_many).is_err());
        let mut owner_member = members.clone();
        owner_member.push(Collaborator {
            public_key: key(1),
            role: Role::Reader,
        });
        owner_member.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert!(validate_collaborators(&owner, &owner_member).is_err());
        let mut duplicate = members.clone();
        duplicate.push(members[0].clone());
        duplicate.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert!(validate_collaborators(&owner, &duplicate).is_err());
        members.swap(0, 1);
        assert!(validate_collaborators(&owner, &members).is_err());
    }
    #[test]
    fn json_rejects_ambiguity_and_generation_precision_loss() {
        assert!(decode::<GetRequest>(br#"{"version":1}"#).is_ok());
        for bad in [
            br#"{"version":1,"version":1}"#.as_slice(),
            br#"{"version":1,"extra":0}"#,
            br#"{"version":1} {}"#,
            br#"{"version":"1"}"#,
        ] {
            assert!(decode::<GetRequest>(bad).is_err());
        }
        for bad in ["", "01", "+1", "-1", "1.0", "18446744073709551616"] {
            assert!(generation(bad).is_err());
        }
        assert_eq!(generation("18446744073709551615"), Ok(u64::MAX));
        let mut exact = br#"{"version":1}"#.to_vec();
        exact.resize(MAX_ADMIN_BODY, b' ');
        assert!(decode::<GetRequest>(&exact).is_ok());
        assert!(decode::<GetRequest>(&vec![b' '; MAX_ADMIN_BODY + 1]).is_err());
        let owner = key(1);
        let invalid_role = format!(
            r#"{{"version":1,"collaborators":[{{"public_key":"{}","role":"admin"}}]}}"#,
            key(2)
        );
        assert!(decode::<InitializeRequest>(invalid_role.as_bytes()).is_err());
        let invalid_owner = format!(
            r#"{{"version":1,"collaborators":[{{"public_key":"{owner}","role":"reader"}}]}}"#
        );
        let parsed = decode::<InitializeRequest>(invalid_owner.as_bytes()).unwrap();
        assert!(validate_collaborators(&owner, &parsed.collaborators).is_err());
    }
}
