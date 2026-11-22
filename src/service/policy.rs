use std::collections::BTreeSet;

use json::JsonValue;

use crate::Error;

const ALLOW_INBOUND: i32 = 1;
const LEGACY_CONFIGURATION: i32 = 1;
const PRIVATE_HANDLE: i32 = 2;

/// API permissions supplied by the hub when registering the local service.
#[derive(Debug)]
pub(crate) struct ServicePolicy {
    group_rules: Vec<Rule>,
    trust_rules: Vec<Rule>,
    legacy: bool,
    legacy_private: bool,
}

/// Access grants supplied by the hub for a specific peer socket.
#[derive(Debug)]
pub(crate) struct PeerPolicy {
    inbound: bool,
    authorized_by_listener: bool,
    groups: BTreeSet<String>,
    trust: Option<String>,
}

impl ServicePolicy {
    pub(crate) fn from_hub(
        groups: Option<&str>,
        provided_trusts: Option<&str>,
        flags: i32,
    ) -> Result<Self, Error> {
        let legacy = flags & LEGACY_CONFIGURATION != 0;
        let has_group_policy = groups.is_some_and(|value| !value.is_empty());
        Ok(Self {
            group_rules: group_rules(groups)?,
            trust_rules: trust_rules(provided_trusts)?,
            legacy,
            legacy_private: legacy && has_group_policy && flags & PRIVATE_HANDLE != 0,
        })
    }

    pub(super) fn permits(
        &self,
        peer: &PeerPolicy,
        category: &str,
        method: &str,
        public: bool,
    ) -> bool {
        if peer.authorized_by_listener {
            return !public;
        }
        if !peer.inbound || (self.legacy && (public || !self.legacy_private)) {
            return false;
        }

        let (provided, has_privacy_policy) = self.provided_groups(category, method);
        if has_privacy_policy || !provided.iter().any(|group| peer.groups.contains(*group)) {
            return false;
        }

        let mut needs_trust = false;
        for group in provided {
            // Native LS2 builds a list by prepending hub rules and uses the first
            // matching trust rule for each group.
            if let Some(rule) = self
                .trust_rules
                .iter()
                .rev()
                .find(|rule| matches_pattern(&rule.pattern, group))
            {
                needs_trust |= !rule.values.is_empty();
                if let Some(trust) = peer.trust.as_deref() {
                    if rule
                        .values
                        .iter()
                        .any(|required| trust_allows(required, trust))
                    {
                        return true;
                    }
                }
            }
        }
        !needs_trust
    }

    pub(super) fn provided_groups(&self, category: &str, method: &str) -> (BTreeSet<&str>, bool) {
        let path = format!("{}/{method}", category.trim_end_matches('/'));
        let mut provided = BTreeSet::new();
        let mut has_privacy_policy = false;
        for rule in &self.group_rules {
            let candidate = if rule.category_only { category } else { &path };
            if matches_pattern(&rule.pattern, candidate) {
                has_privacy_policy |= rule.has_privacy_policy;
                provided.extend(rule.values.iter().map(String::as_str));
            }
        }
        if self.legacy_private {
            provided.insert("private");
        }
        (provided, has_privacy_policy)
    }
}

impl PeerPolicy {
    pub(crate) fn from_legacy_listener() -> Self {
        Self {
            inbound: true,
            authorized_by_listener: true,
            groups: BTreeSet::new(),
            trust: None,
        }
    }

    pub(crate) fn from_hub(
        groups: Option<&str>,
        trust: Option<&str>,
        permissions: i32,
    ) -> Result<Self, Error> {
        let groups = parse_array(groups, "peer groups")?;
        Ok(Self {
            inbound: permissions & ALLOW_INBOUND != 0,
            authorized_by_listener: false,
            groups: labels(&groups, "peer groups")?.into_iter().collect(),
            trust: parse_trust(trust)?,
        })
    }
}

#[derive(Debug)]
struct Rule {
    pattern: String,
    category_only: bool,
    values: Vec<String>,
    has_privacy_policy: bool,
}

impl Rule {
    fn new(entry: &JsonValue, key: &str, values: Vec<String>) -> Result<Self, Error> {
        let pattern = entry[key]
            .as_str()
            .filter(|name| !name.is_empty() && !name.contains('\0'))
            .ok_or_else(|| policy_error(key))?;
        let category_only = pattern.ends_with('/');
        let pattern = match pattern {
            "/" => pattern,
            _ => pattern.strip_suffix('/').unwrap_or(pattern),
        };
        Ok(Self {
            pattern: pattern.to_owned(),
            category_only,
            values,
            has_privacy_policy: false,
        })
    }
}

fn group_rules(value: Option<&str>) -> Result<Vec<Rule>, Error> {
    parse_array(value, "category groups")?
        .members()
        .map(|entry| {
            let mut rule = Rule::new(entry, "category", labels(&entry["groups"], "groups")?)?;
            let privacy = if entry.has_key("privacy") {
                entry["privacy"]
                    .as_bool()
                    .ok_or_else(|| policy_error("privacy"))?
            } else {
                false
            };
            let privacy_groups = if entry.has_key("privacyGroups") {
                entry["privacyGroups"]
                    .as_str()
                    .ok_or_else(|| policy_error("privacyGroups"))?
            } else {
                ""
            };
            // The TV hub reports privacy controls separately from ordinary ACGs.
            // Until we can evaluate these controls, a matching rule cannot authorize a call.
            rule.has_privacy_policy = privacy || !privacy_groups.is_empty();
            Ok(rule)
        })
        .collect()
}

fn trust_rules(value: Option<&str>) -> Result<Vec<Rule>, Error> {
    parse_array(value, "provided trust")?
        .members()
        .map(|entry| {
            let field = match (entry.has_key("provided"), entry.has_key("trust")) {
                (true, false) => "provided",
                (false, true) => "trust",
                _ => return Err(policy_error("provided trust")),
            };
            let value = &entry[field];
            // The webOS TV hub represents an unset trust restriction as [""].
            let labels = if field == "trust"
                && value.is_array()
                && value.len() == 1
                && value[0].as_str().is_some_and(str::is_empty)
            {
                Vec::new()
            } else {
                labels(value, field)?
            };
            Rule::new(entry, "group", labels)
        })
        .collect()
}

fn parse_array(value: Option<&str>, field: &str) -> Result<JsonValue, Error> {
    match value {
        None | Some("") => Ok(JsonValue::new_array()),
        Some(value) => json::parse(value)
            .ok()
            .filter(JsonValue::is_array)
            .ok_or_else(|| policy_error(field)),
    }
}

fn labels(values: &JsonValue, field: &str) -> Result<Vec<String>, Error> {
    if !values.is_array() {
        return Err(policy_error(field));
    }
    values
        .members()
        .map(|value| {
            value
                .as_str()
                .filter(|label| !label.is_empty() && !label.contains('\0'))
                .map(str::to_owned)
                .ok_or_else(|| policy_error(field))
        })
        .collect()
}

fn parse_trust(trust: Option<&str>) -> Result<Option<String>, Error> {
    let Some(trust) = trust.map(str::trim).filter(|trust| !trust.is_empty()) else {
        return Ok(None);
    };
    if trust.starts_with('[') || trust.starts_with('"') {
        let mut value = json::parse(trust).map_err(|_| policy_error("peer trust"))?;
        if value.is_array() {
            // The SDK's hub transmits the peer's one trust label as an array.
            match value.len() {
                0 => return Ok(None),
                1 => value = value.pop(),
                _ => return Err(policy_error("peer trust")),
            }
        }
        return trust_label(value.as_str().ok_or_else(|| policy_error("peer trust"))?);
    }
    trust_label(trust)
}

fn trust_label(trust: &str) -> Result<Option<String>, Error> {
    if trust.is_empty() {
        return Ok(None);
    }
    if trust
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Ok(Some(trust.to_owned()));
    }
    Err(policy_error("peer trust"))
}

fn policy_error(field: &str) -> Error {
    Error::protocol(format!("invalid Luna hub security metadata for {field}"))
}

fn trust_allows(required: &str, caller: &str) -> bool {
    matches!(
        (required, caller),
        ("public", "public")
            | ("platform", "platform")
            | ("dev", "dev" | "part" | "oem")
            | ("part", "part" | "oem")
            | ("oem", "oem")
    )
}

// GLib patterns use '*' for a sequence and '?' for one Unicode character.
fn matches_pattern(pattern: &str, value: &str) -> bool {
    let mut pattern = pattern.chars().peekable();
    let mut value = value.chars().peekable();
    let mut after_star = None;
    while let Some(&character) = value.peek() {
        match pattern.peek().copied() {
            Some('*') => {
                pattern.next();
                after_star = Some((pattern.clone(), value.clone()));
            }
            Some(expected) if expected == '?' || expected == character => {
                pattern.next();
                value.next();
            }
            _ => {
                let Some((retry_pattern, retry_value)) = after_star.as_mut() else {
                    return false;
                };
                if retry_value.next().is_none() {
                    return false;
                }
                pattern = retry_pattern.clone();
                value = retry_value.clone();
            }
        }
    }
    pattern.all(|character| character == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_grants_from_hub_permit_inbound_methods() -> Result<(), Error> {
        let policy = ServicePolicy::from_hub(
            Some(
                r#"[{"category":"/camera/","groups":["camera"]},{"category":"/video/r?cord","groups":["video"]}]"#,
            ),
            None,
            0,
        )?;
        let camera = PeerPolicy::from_hub(Some(r#"["camera"]"#), None, 1)?;
        let outbound_only = PeerPolicy::from_hub(Some(r#"["camera"]"#), None, 2)?;
        let video = PeerPolicy::from_hub(Some(r#"["video"]"#), None, 3)?;
        let missing = PeerPolicy::from_hub(None, None, 3)?;

        assert!(policy.permits(&camera, "/camera", "record", false));
        assert!(!policy.permits(&camera, "/camera/other", "record", false));
        assert!(!policy.permits(&camera, "/video", "record", false));
        assert!(!policy.permits(&outbound_only, "/camera", "record", false));
        assert!(!policy.permits(&missing, "/camera", "record", false));
        assert!(policy.permits(&video, "/video", "record", false));
        assert!(!policy.permits(&video, "/video", "view", false));
        Ok(())
    }

    #[test]
    fn trust_requirements_apply_even_with_a_default_group() -> Result<(), Error> {
        let policy = ServicePolicy::from_hub(
            Some(r#"[{"category":"/*","groups":["all","permission.secret"]}]"#),
            Some(r#"[{"group":"permission.*","provided":["part"]}]"#),
            0,
        )?;
        for (trust, allows) in [
            (None, false),
            (Some("dev"), false),
            (Some(r#"["part"]"#), true),
            (Some("oem"), true),
        ] {
            let peer = PeerPolicy::from_hub(Some(r#"["all"]"#), trust, 3)?;
            assert_eq!(
                policy.permits(&peer, "/", "echo", false),
                allows,
                "{trust:?}"
            );
        }
        assert!(PeerPolicy::from_hub(Some(r#"["all"]"#), Some(r#"["dev","oem"]"#), 3).is_err());
        assert!(
            ServicePolicy::from_hub(Some(r#"[{"category":"/x/","groups":true}]"#), None, 0)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn tv_groups_enforce_method_permissions_with_unset_trust() -> Result<(), Error> {
        let policy = ServicePolicy::from_hub(
            Some(
                r#"[
                {"privacy":false,"category":"/test/echo","groups":["org.ls2.test.calls"],"privacyGroups":""},
                {"privacy":false,"category":"/test/secret","groups":["org.ls2.test.secret"],"privacyGroups":""},
                {"privacy":true,"category":"/test/private","groups":["org.ls2.test.calls"],"privacyGroups":"example"},
                {"privacy":false,"category":"/test/unknown","groups":["org.ls2.test.unknown"],"privacyGroups":""}
            ]"#,
            ),
            Some(
                r#"[
                {"group":"org.ls2.test.calls","trust":[""]},
                {"group":"org.ls2.test.secret","trust":[""]},
                {"group":"org.ls2.test.unknown","trust":["unrecognized"]}
            ]"#,
            ),
            0,
        )?;
        let peer = PeerPolicy::from_hub(
            Some(r#"["org.ls2.test.calls"]"#),
            Some("public"),
            ALLOW_INBOUND,
        )?;
        let unknown = PeerPolicy::from_hub(
            Some(r#"["org.ls2.test.unknown"]"#),
            Some("unrecognized"),
            ALLOW_INBOUND,
        )?;

        assert!(policy.permits(&peer, "/test", "echo", false));
        assert!(!policy.permits(&peer, "/test", "secret", false));
        assert!(!policy.permits(&peer, "/test", "private", false));
        assert!(!policy.permits(&unknown, "/test", "unknown", false));
        Ok(())
    }

    #[test]
    fn malformed_stock_trust_and_privacy_metadata_fail_closed() {
        for trust in [
            r#"[{"group":"test","provided":[""]}]"#,
            r#"[{"group":"test","trust":["","public"]}]"#,
            r#"[{"group":"test","trust":[],"provided":[]}]"#,
        ] {
            assert!(ServicePolicy::from_hub(Some("[]"), Some(trust), 0).is_err());
        }
        let groups = r#"[{"category":"/test/echo","groups":["test"],"privacy":"false"}]"#;
        assert!(ServicePolicy::from_hub(Some(groups), None, 0).is_err());
    }

    #[test]
    fn legacy_private_group_is_scoped_to_the_private_handle() -> Result<(), Error> {
        let policy =
            ServicePolicy::from_hub(Some("[]"), None, LEGACY_CONFIGURATION | PRIVATE_HANDLE)?;
        let private = PeerPolicy::from_hub(Some(r#"["private"]"#), None, ALLOW_INBOUND)?;
        assert!(policy.permits(&private, "/", "echo", false));
        assert!(!policy.permits(&private, "/", "echo", true));
        Ok(())
    }

    #[test]
    fn glob_matches_only_with_the_required_characters() {
        for (pattern, value, matches) in [
            ("/cam*fix", "/camera/fix", true),
            ("/cam*fix", "/camfixing", false),
            ("/cam?", "/camé", true),
            ("/cam?", "/cam", false),
            ("**", "", true),
            ("*?", "", false),
            ("a*b*c", "abcc", true),
        ] {
            assert_eq!(
                matches_pattern(pattern, value),
                matches,
                "{pattern:?} against {value:?}"
            );
        }
    }
}
