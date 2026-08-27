use std::fmt;

/// How far a delegation opens its secret.
///
/// It is an ORDER, and a comparison is the whole authorisation test. Being
/// allowed to overwrite a secret you may not read is not a power anybody wants
/// to grant by accident, so the variants are declared weakest first and the
/// derived `Ord` is the ladder.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Sees that a secret exists and which keys it has.
    Guest,
    /// May reveal the values.
    Read,
    /// May also push a new version.
    Write,
}

impl Level {
    /// The word a config file and an API spell this level with.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Guest => "guest",
            Level::Read => "read",
            Level::Write => "write",
        }
    }

    /// Whether this level discloses a secret's value.
    #[must_use]
    pub fn reveals(self) -> bool {
        self >= Level::Read
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Level {
    type Err = UnknownLevel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "guest" => Ok(Level::Guest),
            "read" => Ok(Level::Read),
            "write" => Ok(Level::Write),
            other => Err(UnknownLevel(other.to_owned())),
        }
    }
}

/// A level word nothing here can interpret. It is an error rather than a
/// silent `Guest`: a delegation whose level failed to parse is one nobody can
/// reason about, and guessing the weakest reading still guesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownLevel(pub String);

impl fmt::Display for UnknownLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown level {:?}, expected guest, read or write",
            self.0
        )
    }
}

impl std::error::Error for UnknownLevel {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_ordered() {
        assert!(Level::Guest < Level::Read);
        assert!(Level::Read < Level::Write);
    }

    #[test]
    fn only_read_and_above_reveal() {
        assert!(!Level::Guest.reveals());
        assert!(Level::Read.reveals());
        assert!(Level::Write.reveals());
    }

    #[test]
    fn round_trips_through_its_word() {
        for level in [Level::Guest, Level::Read, Level::Write] {
            assert_eq!(level.as_str().parse(), Ok(level));
        }
    }

    #[test]
    fn a_retired_spelling_is_refused_rather_than_downgraded() {
        // `readonly` and `viewer` were the pre-rename words upstream. Reading
        // one as Guest would quietly narrow a grant somebody wrote.
        assert!("readonly".parse::<Level>().is_err());
        assert!("viewer".parse::<Level>().is_err());
    }
}
