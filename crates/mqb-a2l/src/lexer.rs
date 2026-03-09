/// Tokenizer for A2L (ASAP2) files.
///
/// A2L uses a simple token grammar:
///   - C-style block comments: `/* ... */`
///   - Quoted strings: `"..."` (no escape sequences in practice)
///   - Identifiers / keywords: sequences of non-whitespace, non-`"` characters
///     that are not comments.  This includes `/begin`, `/end`, `0x...`, numbers,
///     and bare words.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    /// Returns the next token, or `None` at end of input.
    pub fn next_token(&mut self) -> Option<Token<'a>> {
        self.skip_ws_and_comments();
        if self.pos >= self.src.len() {
            return None;
        }
        let b = self.src[self.pos];
        if b == b'"' {
            Some(self.read_string())
        } else {
            Some(self.read_word())
        }
    }

    /// Peek at the next token without consuming it.
    #[allow(dead_code)]
    pub fn peek_token(&mut self) -> Option<Token<'a>> {
        let saved = self.pos;
        let tok = self.next_token();
        self.pos = saved;
        tok
    }

    // ── internal ────────────────────────────────────────────────────────────

    fn skip_ws_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            // Skip C-style block comment
            if self.pos + 1 < self.src.len()
                && self.src[self.pos] == b'/'
                && self.src[self.pos + 1] == b'*'
            {
                self.pos += 2;
                while self.pos + 1 < self.src.len() {
                    if self.src[self.pos] == b'*' && self.src[self.pos + 1] == b'/' {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn read_string(&mut self) -> Token<'a> {
        // consume opening `"`
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.src.len() {
            match self.src[self.pos] {
                b'"' => break,
                b'\\' => {
                    // Skip the backslash and the following byte (e.g. `\"`)
                    self.pos += 2;
                }
                _ => {
                    self.pos += 1;
                }
            }
        }
        let s = &self.src[start..self.pos];
        if self.pos < self.src.len() {
            self.pos += 1; // consume closing `"`
        }
        Token::Str(s)
    }

    fn read_word(&mut self) -> Token<'a> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            if b.is_ascii_whitespace() || b == b'"' {
                break;
            }
            // stop before a `/*` comment
            if b == b'/' && self.pos + 1 < self.src.len() && self.src[self.pos + 1] == b'*' {
                break;
            }
            self.pos += 1;
        }
        Token::Word(&self.src[start..self.pos])
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Token<'a> {
    /// A quoted string (contents without the quotes).
    Str(&'a [u8]),
    /// Any other token (keyword, identifier, number, `/begin`, `/end`, …).
    Word(&'a [u8]),
}

impl<'a> Token<'a> {
    /// Decode the token bytes as Latin-1 (ISO-8859-1 / Windows-1252).
    ///
    /// A2L files are typically Latin-1 encoded, so bytes 0x80–0xFF map
    /// directly to the matching Unicode code point (e.g. 0xB0 → U+00B0 '°').
    /// Pure-ASCII tokens are returned as a borrowed `&str` without allocation.
    pub fn as_str_lossy(&self) -> std::borrow::Cow<'a, str> {
        let b = match self {
            Token::Str(b) | Token::Word(b) => b,
        };
        // Fast path: valid UTF-8 (covers all-ASCII, the common case).
        if let Ok(s) = std::str::from_utf8(b) {
            return std::borrow::Cow::Borrowed(s);
        }
        // Slow path: decode as Latin-1 — each byte is its Unicode code point.
        std::borrow::Cow::Owned(b.iter().map(|&byte| byte as char).collect())
    }

    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            Token::Str(b) | Token::Word(b) => b,
        }
    }

    pub fn eq_word(&self, s: &str) -> bool {
        matches!(self, Token::Word(b) if *b == s.as_bytes())
    }
}
