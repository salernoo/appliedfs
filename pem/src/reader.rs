use std::{
    fs::File,
    io::{BufRead, BufReader, Lines},
    path::Path,
};

use base64::Engine;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{
    error::PEMResult,
    tokenize::{Bound, Kind, Token},
};

struct Block {
    kind: Kind,

    // the block's decoded bytes
    content: Vec<u8>,
}

#[derive(Debug)]
pub struct PEMReader {
    // in this context, individual lines represent unparsed tokens
    tokens: Vec<Token>,
    lines: Lines<BufReader<File>>,
}

impl PEMReader {
    pub fn new(path: impl AsRef<Path>) -> PEMResult<PEMReader> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let lines = reader.lines();

        return Ok(PEMReader {
            tokens: Vec::new(),
            lines,
        });
    }
}

impl PEMReader {
    // goto the next token with the given bound
    fn next_bound(&mut self, bound: Bound) -> PEMResult<()> {
        while let Some(token) = self.next_token()? {
            if bound == Bound::Begin && matches!(token, Token::Begin(_))
                || bound == Bound::End && matches!(token, Token::End(_))
            {
                return Ok(());
            }
        }

        Ok(())
    }

    fn next_token(&mut self) -> PEMResult<Option<&Token>> {
        Ok(match self.lines.next() {
            Some(line) => {
                let token = Token::parse_line(&line?)?;
                self.tokens.push(token);

                self.tokens.last()
            }
            None => None,
        })
    }

    fn next_block(&mut self) -> PEMResult<Option<Block>> {
        self.tokens.clear();
        self.next_bound(Bound::Begin)?;

        if let Some(Token::Begin(kind)) = self.tokens.pop() {
            self.tokens.clear();
            self.next_bound(Bound::End)?;

            let mut content = String::new();
            for line in self.tokens.iter().filter_map(|t| match t {
                Token::Arbitrary(line) => Some(line),
                _ => None,
            }) {
                content += line;
            }

            return Ok(Some(Block {
                kind,
                content: base64::engine::general_purpose::STANDARD.decode(content)?,
            }));
        }

        Ok(None)
    }

    pub fn next_certificate(&mut self) -> PEMResult<Option<CertificateDer<'static>>> {
        while let Some(block) = self.next_block()? {
            if matches!(block.kind, Kind::Certificate) {
                return Ok(Some(CertificateDer::from(block.content)));
            }
        }

        Ok(None)
    }

    pub fn next_private_key(&mut self) -> PEMResult<Option<PrivateKeyDer<'static>>> {
        while let Some(block) = self.next_block()? {
            if matches!(block.kind, Kind::PrivateKey) {
                return Ok(Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    //todo: make it support beyond pkcs#8
                    block.content,
                ))));
            }
        }

        Ok(None)
    }
}
