//! Where the CLI keeps its credential.

use eyre::{Context as _, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub url: String,
    pub token: String,
}

fn path() -> eyre::Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| eyre::eyre!("no home directory"))?;
    Ok(base.join(".keyway").join("config.yml"))
}

/// The profile to use: flags first, then the environment, then what `login`
/// saved.
pub fn resolve(url: Option<&str>, token: Option<&str>) -> eyre::Result<Profile> {
    let saved = load()?;
    let url = url
        .map(ToOwned::to_owned)
        .or_else(|| saved.as_ref().map(|p| p.url.clone()))
        .ok_or_else(|| eyre::eyre!("no keyway url; run `keyway login <url>` or pass --url"))?;
    let token = token
        .map(ToOwned::to_owned)
        .or_else(|| saved.as_ref().map(|p| p.token.clone()))
        .ok_or_else(|| eyre::eyre!("no token; run `keyway login <url>` or pass --token"))?;
    Ok(Profile { url, token })
}

fn load() -> eyre::Result<Option<Profile>> {
    let path = path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).wrap_err_with(|| format!("reading {}", path.display()))?;
    Ok(Some(serde_norway::from_str(&text)?))
}

/// Signs in by sending somebody to the console to mint a token.
///
/// The CLI does not mint over the API, deliberately: minting passes through a
/// browser session, which is what keeps a token's remembered groups seeded by
/// a real sign-in (ADR-0004). It also means a leaked CLI credential cannot
/// spawn replacements that survive revoking it.
pub fn login(url: &str) -> eyre::Result<()> {
    let url = url.trim_end_matches('/');
    let tokens_page = format!("{url}/tokens");

    println!("Open {tokens_page} and create a token, then paste it here.");
    if let Err(error) = open_browser(&tokens_page) {
        println!("(could not open a browser: {error})");
    }
    print!("Token: ");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut token = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut token)?;
    let token = token.trim().to_owned();

    if !token.starts_with("kw-") {
        bail!("that does not look like a keyway token (they start with `kw-`)");
    }

    save(&Profile {
        url: url.to_owned(),
        token,
    })?;
    println!("Saved to {}.", path()?.display());
    Ok(())
}

fn save(profile: &Profile) -> eyre::Result<()> {
    let path = path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_norway::to_string(profile)?)?;
    restrict(&path)?;
    Ok(())
}

/// A file holding a long-lived credential should not be world-readable.
#[cfg(unix)]
fn restrict(path: &std::path::Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) -> eyre::Result<()> {
    Ok(())
}

fn open_browser(url: &str) -> eyre::Result<()> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener).arg(url).spawn()?;
    Ok(())
}
