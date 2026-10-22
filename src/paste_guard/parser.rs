use super::{END_SEQ, MAX_PASTE_BYTES, START_SEQ};

/// Shared prefix of the child's `\e[?2004h` / `\e[?2004l` requests.
const MODE_PREFIX: &[u8] = b"\x1b[?2004";

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
    // Whether the child asked for bracketed paste. The parent terminal is
    // always in that mode, so the markers are only re-added for a child that
    // understands them; others (cat, sh) would print them literally.
    framed: bool,
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
            framed: true,
        }
    }

    pub fn set_framed(&mut self, framed: bool) {
        self.framed = framed;
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
                self.frame(out, START_SEQ);
                out.extend_from_slice(&redacted);
                self.frame(out, END_SEQ);
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
            self.frame(out, START_SEQ);
            out.extend_from_slice(&self.paste_buffer);
            self.paste_buffer.clear();
            self.end_match = 0;
            self.state = State::InPasteBypass;
            self.overflowed = true;
        }
    }

    // Holds back a partial end marker so it can be dropped when unframed.
    fn feed_bypass(&mut self, b: u8, out: &mut Vec<u8>) {
        if b == END_SEQ[self.end_match] {
            self.end_match += 1;
            if self.end_match == END_SEQ.len() {
                self.frame(out, END_SEQ);
                self.end_match = 0;
                self.state = State::Passthrough;
            }
            return;
        }
        out.extend_from_slice(&END_SEQ[..self.end_match]);
        if b == END_SEQ[0] {
            self.end_match = 1;
        } else {
            self.end_match = 0;
            out.push(b);
        }
    }

    fn frame(&self, out: &mut Vec<u8>, marker: &[u8]) {
        if self.framed {
            out.extend_from_slice(marker);
        }
    }
}

/// Watches the child's output for bracketed-paste requests. Enables pass
/// through; disables are dropped so the parent terminal keeps framing
/// pastes and the wrapper can still see them.
#[derive(Debug, Default)]
pub struct ModeFilter {
    matched: usize,
    enabled: bool,
}

impl ModeFilter {
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            if self.matched == MODE_PREFIX.len() {
                self.matched = 0;
                match b {
                    b'h' => {
                        self.enabled = true;
                        out.extend_from_slice(MODE_PREFIX);
                        out.push(b);
                        continue;
                    }
                    b'l' => {
                        self.enabled = false;
                        continue;
                    }
                    _ => out.extend_from_slice(MODE_PREFIX),
                }
            } else if b == MODE_PREFIX[self.matched] {
                self.matched += 1;
                continue;
            } else {
                out.extend_from_slice(&MODE_PREFIX[..self.matched]);
                self.matched = 0;
            }
            if b == MODE_PREFIX[0] {
                self.matched = 1;
            } else {
                out.push(b);
            }
        }
        out
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
    fn unframed_child_gets_the_bare_payload() {
        let mut p = PasteParser::new();
        p.set_framed(false);
        let mut input = Vec::new();
        input.extend_from_slice(START_SEQ);
        input.extend_from_slice(b"hello");
        input.extend_from_slice(END_SEQ);
        input.extend_from_slice(b"\r");
        assert_eq!(p.feed(&input, &mut upper_redact), b"HELLO\r");
    }

    #[test]
    fn unframed_overflow_drops_both_markers() {
        let mut p = PasteParser::new();
        p.set_framed(false);
        let mut input = Vec::new();
        input.extend_from_slice(START_SEQ);
        input.resize(input.len() + MAX_PASTE_BYTES + 16, b'A');
        input.extend_from_slice(b"\x1b[2");
        input.extend_from_slice(END_SEQ);
        let out = p.feed(&input, &mut identity_redact);
        assert!(p.take_overflow());
        assert!(out.ends_with(b"AA\x1b[2"));
        assert!(!out.windows(START_SEQ.len()).any(|w| w == START_SEQ));
        assert!(!out.windows(END_SEQ.len()).any(|w| w == END_SEQ));
    }

    #[test]
    fn mode_filter_tracks_and_drops_disable() {
        let mut f = ModeFilter::default();
        assert!(!f.enabled());
        assert_eq!(f.feed(b"a\x1b[?2004hb"), b"a\x1b[?2004hb");
        assert!(f.enabled());
        assert_eq!(f.feed(b"c\x1b[?20"), b"c");
        assert_eq!(f.feed(b"04ld"), b"d");
        assert!(!f.enabled());
    }

    #[test]
    fn mode_filter_passes_other_sequences() {
        let mut f = ModeFilter::default();
        let input = b"\x1b[?25l\x1b[?2004x\x1b\x1b[?2004h";
        assert_eq!(f.feed(input), input);
        assert!(f.enabled());
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
