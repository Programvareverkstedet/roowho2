use std::{collections::HashSet, path::Path};

use anyhow::Context;
use nix::unistd::{Uid, User};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IgnoreEntry {
    Uid(u32),
    User(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoreList {
    entries: HashSet<IgnoreEntry>,
}

impl IgnoreList {
    pub fn load_optional(path: Option<&Path>) -> anyhow::Result<Option<Self>> {
        match path {
            Some(path) => Self::load(path).map(Some),
            None => Ok(None),
        }
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read ignore list {}", path.display()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> anyhow::Result<Self> {
        let mut entries = HashSet::new();

        for (idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let entry = if let Some(uid) = line.strip_prefix("uid:") {
                let uid = uid.trim().parse::<u32>().with_context(|| {
                    format!("Invalid uid on ignore list line {}: {}", idx + 1, raw_line)
                })?;
                IgnoreEntry::Uid(uid)
            } else if let Some(user) = line.strip_prefix("user:") {
                let user = user.trim();
                if user.is_empty() {
                    anyhow::bail!("Invalid user on ignore list line {}: {}", idx + 1, raw_line);
                }
                IgnoreEntry::User(user.to_string())
            } else {
                anyhow::bail!(
                    "Invalid ignore list entry on line {}: {}",
                    idx + 1,
                    raw_line
                );
            };

            entries.insert(entry);
        }

        Ok(Self { entries })
    }

    pub fn ignores_username(&self, username: &str) -> bool {
        if self
            .entries
            .contains(&IgnoreEntry::User(username.to_string()))
        {
            return true;
        }

        match User::from_name(username) {
            Ok(Some(user)) => self.entries.contains(&IgnoreEntry::Uid(user.uid.as_raw())),
            Ok(None) => false,
            Err(err) => {
                tracing::warn!(
                    "Failed to resolve username '{}' for ignore list lookup: {}",
                    username,
                    err
                );
                false
            }
        }
    }

    pub fn ignores_uid(&self, uid: u32) -> bool {
        if self.entries.contains(&IgnoreEntry::Uid(uid)) {
            return true;
        }

        match User::from_uid(Uid::from_raw(uid)) {
            Ok(Some(user)) => self.entries.contains(&IgnoreEntry::User(user.name)),
            Ok(None) => false,
            Err(err) => {
                tracing::warn!(
                    "Failed to resolve uid {} for ignore list lookup: {}",
                    uid,
                    err
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ignore_list() {
        let list = IgnoreList::parse(
            &["uid:1000", "user:alice", "  user:bob  "].join("\n"), // "\n# comment\nuid:1000\nuser:alice # trailing comment\n\nuser:bob\n",
        )
        .unwrap();

        assert!(list.ignores_uid(1000));
        assert!(list.ignores_username("alice"));
        assert!(list.ignores_username("bob"));
    }

    #[test]
    fn test_parse_ignore_list_with_comments() {
        let list = IgnoreList::parse(
            &[
                "# This is a comment",
                "uid:1000",
                "user:alice # trailing comment",
                "",
                "user:bob",
            ]
            .join("\n"),
        )
        .unwrap();

        assert!(list.ignores_uid(1000));
        assert!(list.ignores_username("alice"));
        assert!(list.ignores_username("bob"));
    }
}
