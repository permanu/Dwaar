// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Tokenizer (lexer) for Dwaarfile syntax.
//!
//! Breaks raw text into a stream of [`Token`]s with source locations.
//! Handles comments (`#`), quoted strings, braces, and bare words.

/// A token with its source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub col: usize,
}

/// The type of token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenKind {
    /// A bare word or domain: `reverse_proxy`, `example.com`, `localhost:8080`
    Word(String),
    /// A quoted string: `"some value with spaces"`
    QuotedString(String),
    /// `{`
    OpenBrace,
    /// `}`
    CloseBrace,
    /// End of input
    Eof,
}

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenKind::Word(w) => write!(f, "'{w}'"),
            TokenKind::QuotedString(s) => write!(f, "\"{s}\""),
            TokenKind::OpenBrace => write!(f, "'{{'"),
            TokenKind::CloseBrace => write!(f, "'}}'"),
            TokenKind::Eof => write!(f, "end of file"),
        }
    }
}

/// Tokenizes Dwaarfile input into a sequence of tokens.
///
/// Skips whitespace and comments (`# ...` to end of line).
/// Tracks line and column numbers for error reporting.
pub(crate) struct Tokenizer<'a> {
    input: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Tokenizer<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    /// Consume the next token from the input.
    pub(crate) fn next_token(&mut self) -> Token {
        self.skip_whitespace_and_comments();

        if self.pos >= self.input.len() {
            return Token {
                kind: TokenKind::Eof,
                line: self.line,
                col: self.col,
            };
        }

        let line = self.line;
        let col = self.col;

        match self.input[self.pos] {
            b'{' => {
                self.advance();
                Token {
                    kind: TokenKind::OpenBrace,
                    line,
                    col,
                }
            }
            b'}' => {
                self.advance();
                Token {
                    kind: TokenKind::CloseBrace,
                    line,
                    col,
                }
            }
            b'"' => self.read_quoted_string(line, col),
            _ => self.read_word(line, col),
        }
    }

    /// Peek at the next token without consuming it.
    pub(crate) fn peek(&mut self) -> Token {
        let saved_pos = self.pos;
        let saved_line = self.line;
        let saved_col = self.col;

        let token = self.next_token();

        self.pos = saved_pos;
        self.line = saved_line;
        self.col = saved_col;

        token
    }

    /// Current position for error reporting.
    pub(crate) fn position(&self) -> (usize, usize) {
        (self.line, self.col)
    }

    fn advance(&mut self) {
        if self.pos < self.input.len() {
            if self.input[self.pos] == b'\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
            self.pos += 1;
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
                self.advance();
            }

            // Skip line comments (# to end of line)
            if self.pos < self.input.len() && self.input[self.pos] == b'#' {
                while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
                    self.advance();
                }
                continue; // Loop back to skip whitespace after comment
            }

            break;
        }
    }

    fn read_quoted_string(&mut self, line: usize, col: usize) -> Token {
        self.advance(); // skip opening quote

        let mut value = String::new();
        while self.pos < self.input.len() && self.input[self.pos] != b'"' {
            // Handle escape sequences
            if self.input[self.pos] == b'\\' && self.pos + 1 < self.input.len() {
                self.advance();
                match self.input[self.pos] {
                    b'"' => value.push('"'),
                    b'\\' => value.push('\\'),
                    b'n' => value.push('\n'),
                    b't' => value.push('\t'),
                    other => {
                        value.push('\\');
                        value.push(char::from(other));
                    }
                }
            } else {
                // Read a full UTF-8 character from the input.
                // The input is valid UTF-8 (constructor takes &str), so this is safe.
                let remaining = &self.input[self.pos..];
                let s = std::str::from_utf8(remaining).expect("input is valid UTF-8");
                if let Some(ch) = s.chars().next() {
                    value.push(ch);
                    // advance() for each byte of the character to keep pos tracking correct
                    // (multi-byte chars are never newlines, so col tracking stays accurate)
                    for _ in 1..ch.len_utf8() {
                        self.pos += 1;
                        self.col += 1;
                    }
                }
            }
            self.advance();
        }

        // Skip closing quote (if present)
        if self.pos < self.input.len() {
            self.advance();
        }

        Token {
            kind: TokenKind::QuotedString(value),
            line,
            col,
        }
    }

    fn read_word(&mut self, line: usize, col: usize) -> Token {
        let start = self.pos;
        while self.pos < self.input.len() && !Self::is_delimiter(self.input[self.pos]) {
            self.advance();
        }

        let word = String::from_utf8_lossy(&self.input[start..self.pos]).to_string();
        Token {
            kind: TokenKind::Word(word),
            line,
            col,
        }
    }

    fn is_delimiter(b: u8) -> bool {
        b.is_ascii_whitespace() || b == b'{' || b == b'}' || b == b'"' || b == b'#'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokenize(input: &str) -> Vec<Token> {
        let mut t = Tokenizer::new(input);
        let mut tokens = Vec::new();
        loop {
            let tok = t.next_token();
            if tok.kind == TokenKind::Eof {
                tokens.push(tok);
                break;
            }
            tokens.push(tok);
        }
        tokens
    }

    #[test]
    fn empty_input() {
        let tokens = tokenize("");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, TokenKind::Eof);
    }

    #[test]
    fn simple_site_block() {
        let tokens = tokenize("example.com {\n    reverse_proxy localhost:8080\n}");
        let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word("example.com".to_string()),
                &TokenKind::OpenBrace,
                &TokenKind::Word("reverse_proxy".to_string()),
                &TokenKind::Word("localhost:8080".to_string()),
                &TokenKind::CloseBrace,
                &TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn quoted_strings() {
        let tokens = tokenize("header X-Custom \"hello world\"");
        let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word("header".to_string()),
                &TokenKind::Word("X-Custom".to_string()),
                &TokenKind::QuotedString("hello world".to_string()),
                &TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn escape_sequences_in_quoted_strings() {
        let tokens = tokenize(r#""hello \"world\"""#);
        assert_eq!(
            tokens[0].kind,
            TokenKind::QuotedString("hello \"world\"".to_string())
        );
    }

    #[test]
    fn comments_are_skipped() {
        let tokens = tokenize("# this is a comment\nexample.com {\n# another comment\n}");
        let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word("example.com".to_string()),
                &TokenKind::OpenBrace,
                &TokenKind::CloseBrace,
                &TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn line_numbers_are_tracked() {
        let tokens = tokenize("first\nsecond\nthird");
        assert_eq!(tokens[0].line, 1);
        assert_eq!(tokens[1].line, 2);
        assert_eq!(tokens[2].line, 3);
    }

    #[test]
    fn column_numbers_are_tracked() {
        let tokens = tokenize("  indented");
        assert_eq!(tokens[0].col, 3); // 2 spaces then word starts at col 3
    }

    #[test]
    fn peek_does_not_consume() {
        let mut t = Tokenizer::new("hello world");
        let peeked = t.peek();
        let consumed = t.next_token();
        assert_eq!(peeked.kind, consumed.kind);
    }

    #[test]
    fn braces_adjacent_to_words() {
        // Caddyfile allows "example.com{" without space
        let tokens = tokenize("example.com{reverse_proxy :8080}");
        let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
        assert_eq!(
            kinds,
            vec![
                &TokenKind::Word("example.com".to_string()),
                &TokenKind::OpenBrace,
                &TokenKind::Word("reverse_proxy".to_string()),
                &TokenKind::Word(":8080".to_string()),
                &TokenKind::CloseBrace,
                &TokenKind::Eof,
            ]
        );
    }
}
