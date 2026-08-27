//! `${env:NAME}` resolution.
//!
//! Substitution happens on the PARSED document, over string values only —
//! deliberately, rather than on the raw file before YAML is read. Raw
//! substitution is the obvious implementation and it has two faults that matter
//! for a file full of credentials: a value containing a newline or a quote
//! rewrites the document's structure rather than filling in a field, and a
//! placeholder written inside a comment is resolved too, so an unset one there
//! fails a boot for no reason.

use serde_norway::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One placeholder that could not be resolved, and where it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// Where in the document, as a reader would point at it: `stores[0].key`.
    pub path: String,
    /// The placeholder as written, without its `${}`.
    pub reference: String,
    /// Why it did not resolve.
    pub reason: Reason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// `${env:NAME}` where NAME is not set.
    UnsetVariable(String),
    /// A source other than `env`. The syntax is namespaced so that another
    /// source can be added later; until one is, anything else is a typo.
    UnknownSource(String),
    /// No `:` at all, e.g. the bare `${NAME}` other tools use.
    Malformed,
}

impl std::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ${{{}}} ", self.path, self.reference)?;
        match &self.reason {
            Reason::UnsetVariable(name) => write!(f, "is unset in the environment ({name})"),
            Reason::UnknownSource(source) => {
                write!(f, "names an unknown source {source:?}, expected env")
            }
            Reason::Malformed => write!(f, "is missing a source, expected ${{env:NAME}}"),
        }
    }
}

/// Resolves every placeholder in the document, or reports all of them at once.
///
/// All of them, rather than the first: a deployment with three unset variables
/// should learn that in one boot, not in three.
pub fn resolve(
    value: &mut Value,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), Vec<Unresolved>> {
    let mut errors = Vec::new();
    walk(value, &mut String::new(), lookup, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn walk(
    value: &mut Value,
    path: &mut String,
    lookup: &impl Fn(&str) -> Option<String>,
    errors: &mut Vec<Unresolved>,
) {
    match value {
        Value::String(text) => {
            if let Some(replaced) = substitute(text, path, lookup, errors) {
                *text = replaced;
            }
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                let mark = path.len();
                write!(path, "[{index}]").expect("writing to a String cannot fail");
                walk(item, path, lookup, errors);
                path.truncate(mark);
            }
        }
        Value::Mapping(entries) => {
            // Sorted so the reported order is the same on every run; a mapping
            // preserves file order, but a caller comparing two boots should not
            // have to care which.
            let keys: BTreeMap<String, Value> = entries
                .iter()
                .filter_map(|(k, _)| k.as_str().map(|s| (s.to_owned(), k.clone())))
                .collect();
            for (name, key) in keys {
                let Some(entry) = entries.get_mut(&key) else {
                    continue;
                };
                let mark = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(&name);
                walk(entry, path, lookup, errors);
                path.truncate(mark);
            }
        }
        _ => {}
    }
}

/// Returns the substituted string, or None when there was nothing to do.
fn substitute(
    text: &str,
    path: &str,
    lookup: &impl Fn(&str) -> Option<String>,
    errors: &mut Vec<Unresolved>,
) -> Option<String> {
    if !text.contains("${") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // An unterminated `${` is literal text: there is nothing to resolve
            // and nothing to complain about.
            out.push_str(&rest[start..]);
            return Some(out);
        };
        let reference = &after[..end];
        match value_of(reference, lookup) {
            Ok(value) => out.push_str(&value),
            Err(reason) => {
                errors.push(Unresolved {
                    path: path.to_owned(),
                    reference: reference.to_owned(),
                    reason,
                });
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn value_of(reference: &str, lookup: &impl Fn(&str) -> Option<String>) -> Result<String, Reason> {
    let Some((source, name)) = reference.split_once(':') else {
        return Err(Reason::Malformed);
    };
    if source != "env" {
        return Err(Reason::UnknownSource(source.to_owned()));
    }
    lookup(name).ok_or_else(|| Reason::UnsetVariable(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn parse(yaml: &str) -> Value {
        serde_norway::from_str(yaml).expect("valid yaml")
    }

    #[test]
    fn resolves_a_placeholder_in_a_nested_value() {
        let mut doc = parse("postgres:\n  password: ${env:PGPASS}\n");
        resolve(&mut doc, &env(&[("PGPASS", "hunter2")])).unwrap();
        assert_eq!(doc["postgres"]["password"].as_str(), Some("hunter2"));
    }

    #[test]
    fn resolves_a_placeholder_embedded_in_a_longer_string() {
        let mut doc = parse("postgres:\n  addr: ${env:PGHOST}:5432\n");
        resolve(&mut doc, &env(&[("PGHOST", "db.internal")])).unwrap();
        assert_eq!(doc["postgres"]["addr"].as_str(), Some("db.internal:5432"));
    }

    #[test]
    fn reports_every_unresolved_placeholder_at_once() {
        let mut doc = parse("a: ${env:ONE}\nb: ${env:TWO}\n");
        let errors = resolve(&mut doc, &env(&[])).unwrap_err();
        assert_eq!(errors.len(), 2, "a boot should report all of them, not one");
    }

    #[test]
    fn names_the_path_a_reader_would_point_at() {
        let mut doc = parse("stores:\n  - id: local\n    key: ${env:KEY}\n");
        let errors = resolve(&mut doc, &env(&[])).unwrap_err();
        assert_eq!(errors[0].path, "stores[0].key");
    }

    #[test]
    fn a_bare_placeholder_is_malformed_rather_than_an_env_lookup() {
        // Other tools spell it `${NAME}`. Silently treating that as env would
        // make the namespace meaningless the moment a second source exists.
        let mut doc = parse("a: ${PGPASS}\n");
        let errors = resolve(&mut doc, &env(&[("PGPASS", "hunter2")])).unwrap_err();
        assert_eq!(errors[0].reason, Reason::Malformed);
    }

    #[test]
    fn an_unknown_source_is_refused() {
        let mut doc = parse("a: ${file:/etc/secret}\n");
        let errors = resolve(&mut doc, &env(&[])).unwrap_err();
        assert_eq!(errors[0].reason, Reason::UnknownSource("file".to_owned()));
    }

    #[test]
    fn a_value_containing_yaml_cannot_restructure_the_document() {
        // The reason substitution runs after the parse. A raw-file
        // implementation would turn this into two mapping entries.
        let mut doc = parse("stores:\n  - key: ${env:EVIL}\n");
        resolve(&mut doc, &env(&[("EVIL", "x\nallow: [delete]")])).unwrap();
        assert_eq!(doc["stores"][0]["key"].as_str(), Some("x\nallow: [delete]"));
        assert!(doc["stores"][0].get("allow").is_none());
    }

    #[test]
    fn a_comment_is_not_a_place_a_boot_can_fail() {
        // Also a consequence of parsing first: comments are gone by then.
        let mut doc = parse("# see ${env:NOT_SET}\na: 1\n");
        assert!(resolve(&mut doc, &env(&[])).is_ok());
    }

    #[test]
    fn an_unterminated_placeholder_is_literal_text() {
        let mut doc = parse("a: \"${env:X\"\n");
        resolve(&mut doc, &env(&[])).unwrap();
        assert_eq!(doc["a"].as_str(), Some("${env:X"));
    }
}
