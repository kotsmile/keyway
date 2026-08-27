//! The keyway command-line client.
//!
//! Seven commands, and the two omissions are the interesting part: there is no
//! `delete` and no ownership transfer (ADR-0005). The split is by blast radius
//! rather than by read/write — a mistaken grant is visible in the audit log
//! and revocable in a click, whereas a deleted secret has no undo, and a
//! non-interactive `delete` in a CI script is the one operation with no way
//! back.
//!
//! It speaks the HTTP API and defines its own wire types. Depending on the
//! backend crate would compile the whole server — database driver, cloud SDKs
//! and all — into a binary that formats output.

mod output;
mod profile;
mod wire;

use clap::{Parser, Subcommand};
use output::Format;

#[derive(Parser)]
#[command(name = "keyway", version, about = "Talk to a keyway console")]
struct Cli {
    /// Where keyway lives. Falls back to the saved profile.
    #[arg(long, global = true, env = "KEYWAY_URL")]
    url: Option<String>,

    /// An API token. Falls back to the saved profile.
    #[arg(long, global = true, env = "KEYWAY_TOKEN", hide_env_values = true)]
    token: Option<String>,

    #[arg(long, global = true, conflicts_with = "yaml")]
    json: bool,

    #[arg(long, global = true, conflicts_with = "json")]
    yaml: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Every secret you can see.
    List {
        /// Only this Store.
        #[arg(long)]
        store: Option<String>,
    },

    /// Show a secret's VALUE. Audited as a reveal.
    Get {
        /// The secret's uuid.
        id: String,
        /// One key of a key/value secret.
        #[arg(long, short)]
        key: Option<String>,
        /// A particular version; the latest by default.
        #[arg(long)]
        version: Option<String>,
    },

    /// Show a secret's metadata. NOT a reveal, and not audited as one — which
    /// is why it is a separate command rather than a flag on `get`.
    View {
        /// The secret's uuid.
        id: String,
    },

    /// Bring a new secret into the inventory.
    Create {
        #[arg(long)]
        store: String,
        #[arg(long)]
        name: String,
        /// The value. `-` reads stdin, which is how a value stays out of shell
        /// history.
        #[arg(long)]
        value: String,
        #[arg(long, default_value = "")]
        note: String,
    },

    /// Write a new version of a secret.
    Patch {
        /// The secret's uuid.
        id: String,
        /// The value. `-` reads stdin.
        #[arg(long)]
        value: String,
        #[arg(long, default_value = "")]
        note: String,
    },

    /// Grant sight of a secret to somebody.
    Delegate {
        /// The secret's uuid.
        id: String,
        /// A person's handle.
        #[arg(long, conflicts_with = "group")]
        user: Option<String>,
        /// A group, as the identity provider spells it.
        #[arg(long, conflicts_with = "user")]
        group: Option<String>,
        /// guest, read or write.
        #[arg(long, default_value = "read")]
        level: String,
        /// Limit the grant to these keys of a key/value secret.
        #[arg(long)]
        key: Vec<String>,
        /// Expire the grant after this many days.
        #[arg(long, default_value_t = 0)]
        days: i64,
        #[arg(long, default_value = "")]
        note: String,
    },

    /// Sign in: opens the console to mint a token, and saves it.
    Login {
        /// Where keyway lives.
        url: String,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    let format = if cli.yaml {
        Format::Yaml
    } else if cli.json {
        Format::Json
    } else {
        Format::Plain
    };

    if let Command::Login { url } = &cli.command {
        return profile::login(url);
    }

    let saved = profile::resolve(cli.url.as_deref(), cli.token.as_deref())?;
    let client = wire::Client::new(saved);

    match cli.command {
        Command::List { store } => {
            let mut secrets = client.list().await?;
            if let Some(store) = store {
                secrets.retain(|s| s.store == store);
            }
            output::secrets(&secrets, format)
        }
        Command::Get { id, key, version } => {
            let value = client
                .reveal(&id, key.as_deref(), version.as_deref())
                .await?;
            // Deliberately bare on stdout: a value is usually being piped, and
            // wrapping it in JSON by default would mean every caller unwraps.
            output::value(&value, format)
        }
        Command::View { id } => output::secret(&client.view(&id).await?, format),
        Command::Create {
            store,
            name,
            value,
            note,
        } => {
            let value = read_value(&value)?;
            output::secret(&client.create(&store, &name, &value, &note).await?, format)
        }
        Command::Patch { id, value, note } => {
            let value = read_value(&value)?;
            output::version(&client.patch(&id, &value, &note).await?, format)
        }
        Command::Delegate {
            id,
            user,
            group,
            level,
            key,
            days,
            note,
        } => {
            let (kind, subject) = match (user, group) {
                (Some(user), None) => ("user", user),
                (None, Some(group)) => ("group", group),
                _ => eyre::bail!("give exactly one of --user or --group"),
            };
            let grant = client
                .delegate(
                    &id,
                    wire::NewGrant {
                        kind,
                        subject: &subject,
                        level: &level,
                        keys: &key,
                        days,
                        note: &note,
                    },
                )
                .await?;
            output::grant(&grant, format)
        }
        Command::Login { .. } => unreachable!("handled above"),
    }
}

/// `-` reads stdin, so a value never has to appear in shell history or in a
/// process listing.
fn read_value(given: &str) -> eyre::Result<String> {
    if given != "-" {
        return Ok(given.to_owned());
    }
    let mut buffer = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)?;
    Ok(buffer.trim_end_matches('\n').to_owned())
}
