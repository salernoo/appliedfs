use strum::EnumString;

use crate::error::{PEMError, PEMResult};

#[derive(Debug, PartialEq, EnumString)]
pub enum Bound {
    #[strum(serialize = "BEGIN")]
    Begin,

    #[strum(serialize = "END")]
    End,
}

#[derive(Debug, PartialEq, EnumString)]
pub enum Kind {
    #[strum(serialize = "CERTIFICATE")]
    Certificate,

    #[strum(serialize = "PRIVATE KEY")]
    PrivateKey,
}

#[derive(Debug, PartialEq)]
pub enum Token {
    Begin(Kind),
    End(Kind),

    // Represents anything in a line that isn't structured in a particular format
    Arbitrary(String),
}

impl Token {
    pub fn parse_line(line: &str) -> PEMResult<Token> {
        if let Some(inner) = line
            .strip_prefix("-----")
            .and_then(|l| l.strip_suffix("-----"))
        {
            if let Some((bound, kind)) = inner.split_once(" ") {
                let token: Token = match (bound.parse(), kind.parse()) {
                    (Ok(bound), Ok(kind)) => match bound {
                        Bound::Begin => Token::Begin(kind),
                        Bound::End => Token::End(kind),
                    },
                    _ => {
                        return Err(PEMError::InvalidBlockBound {
                            bound: bound.to_string(),
                            kind: kind.to_string(),
                        });
                    }
                };

                return Ok(token);
            }
        }

        Ok(Token::Arbitrary(line.trim_end().to_string()))
    }
}
