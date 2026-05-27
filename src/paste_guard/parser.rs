use super::{END_SEQ, MAX_PASTE_BYTES, START_SEQ};

/// Streaming parser that extracts bracketed-paste payloads from a byte
/// stream, runs each through a user-supplied redactor, and reframes the
/// result. Everything outside a paste passes through byte-for-byte.
///
/// Operates on arbitrarily-chunked input: partial matches at chunk
/// boundaries are remembered across `feed()` calls.
#[derive(Debug)]
pub struct PasteParser {
    state: State,
    // Passthrough: how many bytes of START_SEQ are matched.
    start_match: usize,
    // InPaste: accumulator + how many bytes of END_SEQ are matched in tail.
    paste_buffer: Vec<u8>,
    end_match: usize,
    // Sticky flag: set when the buffer cap fires during the current or any
    // prior `feed` call. Cleared by `take_overflow()`. Lets the caller emit
    // the localized stderr notice exactly once per overflow event.
    overflowed: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Outside any paste. Watching for `\e[200~`.
    Passthrough,
    /// Inside a paste, buffering for redaction. Watching for `\e[201~`.
    InPaste,
    /// Inside a paste that exceeded the buffer cap. Forward bytes as-is and
    /// just watch for the end marker so we don't permanently desync.
    InPasteBypass,
}

impl Default for PasteParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PasteParser {
    pub fn new() -> Self {
        Self {
            state: State::Passthrough,
            start_match: 0,
            paste_buffer: Vec::new(),
            end_match: 0,
            overflowed: false,
        }
    }

    /// True if a paste hit the buffer cap since the last call. Resets the
    /// internal flag so the caller emits the notice at most once per event.
    pub fn take_overflow(&mut self) -> bool {
        std::mem::replace(&mut self.overflowed, false)
    }

    /// Feed a chunk of input. `redact` is called once per completed paste
    /// with the paste payload (without the surrounding sequences); it must
    /// return the redacted payload to splice back in. Returns the bytes to
    /// forward to the child PTY.
    pub fn feed<F>(&mut self, input: &[u8], redact: &mut F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            match self.state {
                State::Passthrough => self.feed_passthrough(b, &mut out),
                State::InPaste => self.feed_in_paste(b, &mut out, redact),
                State::InPasteBypass => self.feed_bypass(b, &mut out),
            }
        }
        out
    }

    fn feed_passthrough(&mut self, b: u8, out: &mut Vec<u8>) {
        if b == START_SEQ[self.start_match] {
            self.start_match += 1;
            if self.start_match == START_SEQ.len() {
                self.state = State::InPaste;
                self.paste_buffer.clear();
                self.end_match = 0;
                self.start_match = 0;
            }
            return;
        }
        // Mismatch: flush whatever prefix we'd buffered, then re-evaluate b.
        if self.start_match > 0 {
            out.extend_from_slice(&START_SEQ[..self.start_match]);
            self.start_match = 0;
        }
        if b == START_SEQ[0] {
            self.start_match = 1;
        } else {
            out.push(b);
        }
    }

    fn feed_in_paste<F>(&mut self, b: u8, out: &mut Vec<u8>, redact: &mut F)
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        self.paste_buffer.push(b);
        // Track end-marker match in tail of paste_buffer.
        if b == END_SEQ[self.end_match] {
            self.end_match += 1;
            if self.end_match == END_SEQ.len() {
                // Strip the end marker bytes (last 6) from the payload.
                let cut = self.paste_buffer.len() - END_SEQ.len();
                let payload = self.paste_buffer[..cut].to_vec();
                let redacted = redact(&payload);
                out.extend_from_slice(START_SEQ);
                out.extend_from_slice(&redacted);
                out.extend_from_slice(END_SEQ);
                self.paste_buffer.clear();
                self.end_match = 0;
                self.state = State::Passthrough;
                return;
            }
        } else {
            // Partial-match restart for the end marker.
            self.end_match = if b == END_SEQ[0] { 1 } else { 0 };
        }
        if self.paste_buffer.len() > MAX_PASTE_BYTES {
            // Fail open: emit the original start marker plus everything we
            // buffered so far and switch to bypass so subsequent bytes (and
            // the eventual end marker) just stream through unchanged. The
            // caller observes the event via `take_overflow()`.
            out.extend_from_slice(START_SEQ);
            out.extend_from_slice(&self.paste_buffer);
            self.paste_buffer.clear();
            self.end_match = 0;
            self.state = State::InPasteBypass;
            self.overflowed = true;
        }
    }

    fn feed_bypass(&mut self, b: u8, out: &mut Vec<u8>) {
        out.push(b);
        if b == END_SEQ[self.end_match] {
            self.end_match += 1;
            if self.end_match == END_SEQ.len() {
                self.end_match = 0;
                self.state = State::Passthrough;
            }
        } else {
            self.end_match = if b == END_SEQ[0] { 1 } else { 0 };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_redact(payload: &[u8]) -> Vec<u8> {
        payload.to_vec()
    }

    fn upper_redact(payload: &[u8]) -> Vec<u8> {
        payload.iter().map(|b| b.to_ascii_uppercase()).collect()
    }

    #[test]
    fn passthrough_keeps_normal_bytes() {
        let mut p = PasteParser::new();
        let out = p.feed(b"hello world\n", &mut identity_redact);
        assert_eq!(out, b"hello world\n");
    }

    #[test]
    fn paste_is_redacted_in_place() {
        let mut p = PasteParser::new();
        let mut input = Vec::new();
        input.extend_from_slice(b"prefix ");
        input.extend_from_slice(START_SEQ);
        input.extend_from_slice(b"hello");
        input.extend_from_slice(END_SEQ);
        input.extend_from_slice(b" suffix");

        let out = p.feed(&input, &mut upper_redact);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"prefix ");
        expected.extend_from_slice(START_SEQ);
        expected.extend_from_slice(b"HELLO");
        expected.extend_from_slice(END_SEQ);
        expected.extend_from_slice(b" suffix");
        assert_eq!(out, expected);
    }

    #[test]
    fn paste_split_across_chunks() {
        let mut p = PasteParser::new();
        let mut all = Vec::new();
        // Chunk 1: partial start marker
        all.extend(p.feed(b"\x1b[", &mut upper_redact));
        // Chunk 2: rest of start marker + first half of payload
        all.extend(p.feed(b"200~hel", &mut upper_redact));
        // Chunk 3: second half + partial end marker
        all.extend(p.feed(b"lo\x1b[20", &mut upper_redact));
        // Chunk 4: rest of end marker + trailing text
        all.extend(p.feed(b"1~done", &mut upper_redact));

        let mut expected = Vec::new();
        expected.extend_from_slice(START_SEQ);
        expected.extend_from_slice(b"HELLO");
        expected.extend_from_slice(END_SEQ);
        expected.extend_from_slice(b"done");
        assert_eq!(all, expected);
    }

    #[test]
    fn escape_that_is_not_paste_start_passes_through() {
        let mut p = PasteParser::new();
        // ESC [ 1 ; 5 D - some cursor key sequence, must pass through.
        let out = p.feed(b"\x1b[1;5D", &mut identity_redact);
        assert_eq!(out, b"\x1b[1;5D");
    }

    #[test]
    fn partial_start_followed_by_new_escape() {
        let mut p = PasteParser::new();
        // ESC [ 2 then a stray byte that breaks the start sequence: should
        // flush "ESC [ 2" and then re-evaluate the stray byte. Final stream
        // should equal the input unchanged.
        let out = p.feed(b"\x1b[2X", &mut identity_redact);
        assert_eq!(out, b"\x1b[2X");
    }

    #[test]
    fn empty_paste() {
        let mut p = PasteParser::new();
        let mut input = Vec::new();
        input.extend_from_slice(START_SEQ);
        input.extend_from_slice(END_SEQ);
        let out = p.feed(&input, &mut upper_redact);
        // redactor called with empty payload -> empty output
        let mut expected = Vec::new();
        expected.extend_from_slice(START_SEQ);
        expected.extend_from_slice(END_SEQ);
        assert_eq!(out, expected);
    }

    #[test]
    fn overflow_sets_take_overflow_flag_once() {
        let mut p = PasteParser::new();
        let mut input = Vec::new();
        input.extend_from_slice(START_SEQ);
        // Paste payload bigger than the cap.
        input.resize(input.len() + MAX_PASTE_BYTES + 16, b'A');
        input.extend_from_slice(END_SEQ);

        let _ = p.feed(&input, &mut identity_redact);
        assert!(p.take_overflow(), "overflow flag should be set");
        assert!(
            !p.take_overflow(),
            "second take_overflow should be false (one-shot)"
        );
    }

    #[test]
    fn back_to_back_pastes() {
        let mut p = PasteParser::new();
        let mut input = Vec::new();
        input.extend_from_slice(START_SEQ);
        input.extend_from_slice(b"one");
        input.extend_from_slice(END_SEQ);
        input.extend_from_slice(START_SEQ);
        input.extend_from_slice(b"two");
        input.extend_from_slice(END_SEQ);
        let out = p.feed(&input, &mut upper_redact);
        let mut expected = Vec::new();
        expected.extend_from_slice(START_SEQ);
        expected.extend_from_slice(b"ONE");
        expected.extend_from_slice(END_SEQ);
        expected.extend_from_slice(START_SEQ);
        expected.extend_from_slice(b"TWO");
        expected.extend_from_slice(END_SEQ);
        assert_eq!(out, expected);
    }
}
