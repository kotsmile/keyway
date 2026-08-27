//! How results are printed.
//!
//! Plain by default, `--json` and `--yaml` on every command. Plain output for
//! `get` is the bare value with no trailing newline decoration, because it is
//! almost always being piped into something.

use crate::wire::{Grant, Secret, Version};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Plain,
    Json,
    Yaml,
}

impl Format {
    fn render<T: serde::Serialize>(self, value: &T) -> eyre::Result<Option<String>> {
        Ok(match self {
            Format::Json => Some(serde_json::to_string_pretty(value)?),
            Format::Yaml => Some(serde_norway::to_string(value)?),
            Format::Plain => None,
        })
    }
}

pub fn secrets(secrets: &[Secret], format: Format) -> eyre::Result<()> {
    if let Some(rendered) = format.render(&secrets)? {
        println!("{rendered}");
        return Ok(());
    }

    if secrets.is_empty() {
        eprintln!("nothing you can see");
        return Ok(());
    }

    let width = secrets.iter().map(|s| s.store.len()).max().unwrap_or(0);
    for secret in secrets {
        // The uuid first: it is what every other command takes.
        println!(
            "{}  {:width$}  {}{}",
            secret.id,
            secret.store,
            secret.name,
            secret
                .level
                .as_deref()
                .map(|l| format!("  ({l})"))
                .unwrap_or_default(),
        );
    }
    Ok(())
}

pub fn secret(secret: &Secret, format: Format) -> eyre::Result<()> {
    if let Some(rendered) = format.render(secret)? {
        println!("{rendered}");
        return Ok(());
    }
    println!("id      {}", secret.id);
    println!("store   {}", secret.store);
    println!("name    {}", secret.name);
    if !secret.latest_version.is_empty() {
        println!("version {}", secret.latest_version);
    }
    if let Some(level) = &secret.level {
        println!("level   {level}");
    }
    if !secret.basis.is_empty() {
        println!("access  {}", secret.basis);
    }
    Ok(())
}

/// A revealed value.
///
/// Plain prints it bare — no key, no quotes, no label — because the whole
/// point is `export DB_PASSWORD=$(keyway get … -k db_password)`.
pub fn value(value: &str, format: Format) -> eyre::Result<()> {
    match format {
        Format::Plain => println!("{value}"),
        Format::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        Format::Yaml => print!("{}", serde_norway::to_string(&value)?),
    }
    Ok(())
}

pub fn version(version: &Version, format: Format) -> eyre::Result<()> {
    if let Some(rendered) = format.render(version)? {
        println!("{rendered}");
        return Ok(());
    }
    println!("version {} ({})", version.id, version.state);
    Ok(())
}

pub fn grant(grant: &Grant, format: Format) -> eyre::Result<()> {
    if let Some(rendered) = format.render(grant)? {
        println!("{rendered}");
        return Ok(());
    }
    print!(
        "granted {} to {} {}",
        grant.level, grant.subject_kind, grant.subject
    );
    if grant.keys.is_empty() {
        println!();
    } else {
        println!(" (keys: {})", grant.keys.join(", "));
    }
    Ok(())
}
