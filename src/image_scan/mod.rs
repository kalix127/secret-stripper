use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::detector::Detector;

pub struct OcrWord {
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub conf: f32,
    pub block: u32,
    pub line: u32,
}

#[derive(Debug)]
pub enum OcrError {
    NotInstalled,
    Failed(String),
}

pub trait Ocr {
    fn recognize(&self, bytes: &[u8], width: u32, height: u32) -> Result<Vec<OcrWord>, OcrError>;
}

pub struct TesseractOcr;

impl Ocr for TesseractOcr {
    fn recognize(&self, bytes: &[u8], width: u32, height: u32) -> Result<Vec<OcrWord>, OcrError> {
        let png = encode_png(bytes, width, height).map_err(|e| OcrError::Failed(e.to_string()))?;
        let mut tmp = tempfile::Builder::new()
            .suffix(".png")
            .tempfile()
            .map_err(|e| OcrError::Failed(e.to_string()))?;
        tmp.write_all(&png)
            .and_then(|()| tmp.flush())
            .map_err(|e| OcrError::Failed(e.to_string()))?;

        let output = Command::new("tesseract")
            .arg(tmp.path())
            .arg("stdout")
            .args(["-c", "tessedit_create_tsv=1", "--psm", "6"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();

        let output = match output {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(OcrError::NotInstalled)
            }
            Err(e) => return Err(OcrError::Failed(e.to_string())),
        };
        if !output.status.success() {
            return Err(OcrError::Failed(format!(
                "tesseract exited with {}",
                output.status
            )));
        }
        let tsv = String::from_utf8_lossy(&output.stdout);
        if tsv.trim().is_empty() {
            return Err(OcrError::Failed("empty tesseract output".to_string()));
        }
        Ok(parse_tsv(&tsv))
    }
}

fn encode_png(bytes: &[u8], width: u32, height: u32) -> image::ImageResult<Vec<u8>> {
    use image::codecs::png::{CompressionType, FilterType, PngEncoder};
    use image::{ExtendedColorType, ImageEncoder};

    let mut buf = Vec::new();
    let encoder =
        PngEncoder::new_with_quality(&mut buf, CompressionType::Fast, FilterType::Adaptive);
    encoder.write_image(bytes, width, height, ExtendedColorType::Rgba8)?;
    Ok(buf)
}

fn parse_tsv(tsv: &str) -> Vec<OcrWord> {
    let mut words = Vec::new();
    for row in tsv.lines().skip(1) {
        let mut cols = row.splitn(12, '\t');
        let level = cols.next();
        let _page = cols.next();
        let block = cols.next();
        let _par = cols.next();
        let lineno = cols.next();
        let _word = cols.next();
        let left = cols.next();
        let top = cols.next();
        let width = cols.next();
        let height = cols.next();
        let conf = cols.next();
        let text = cols.next();

        let (
            Some(level),
            Some(block),
            Some(lineno),
            Some(left),
            Some(top),
            Some(width),
            Some(height),
            Some(conf),
            Some(text),
        ) = (level, block, lineno, left, top, width, height, conf, text)
        else {
            continue;
        };

        if level.trim() != "5" {
            continue;
        }
        let Ok(conf) = conf.trim().parse::<f32>() else {
            continue;
        };
        if conf < 0.0 {
            continue;
        }
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let (Some(x), Some(y), Some(w), Some(h)) = (
            left.trim().parse::<u32>().ok(),
            top.trim().parse::<u32>().ok(),
            width.trim().parse::<u32>().ok(),
            height.trim().parse::<u32>().ok(),
        ) else {
            continue;
        };

        words.push(OcrWord {
            text: text.to_string(),
            x,
            y,
            w,
            h,
            conf,
            block: block.trim().parse().unwrap_or(0),
            line: lineno.trim().parse().unwrap_or(0),
        });
    }
    words
}

pub struct Assembled {
    pub text: String,
    pub ranges: Vec<(usize, usize)>,
}

pub fn assemble(words: &[OcrWord]) -> Assembled {
    let mut text = String::new();
    let mut ranges = Vec::with_capacity(words.len());
    let mut prev: Option<(u32, u32)> = None;
    for word in words {
        if let Some(p) = prev {
            text.push(if (word.block, word.line) == p {
                ' '
            } else {
                '\n'
            });
        }
        let start = text.len();
        text.push_str(&word.text);
        ranges.push((start, text.len()));
        prev = Some((word.block, word.line));
    }
    Assembled { text, ranges }
}

pub fn boxes_for_spans(
    words: &[OcrWord],
    ranges: &[(usize, usize)],
    spans: &[(usize, usize)],
) -> Vec<(u32, u32, u32, u32)> {
    let mut boxes: Vec<(u32, u32, u32, u32)> = Vec::new();
    for &(s, e) in spans {
        if s >= e {
            continue;
        }
        for (i, &(ws, we)) in ranges.iter().enumerate() {
            if ws < e && s < we {
                let word = &words[i];
                let rect = (word.x, word.y, word.w, word.h);
                if !boxes.contains(&rect) {
                    boxes.push(rect);
                }
            }
        }
    }
    boxes
}

pub fn paint_boxes(
    bytes: &mut [u8],
    width: u32,
    height: u32,
    boxes: &[(u32, u32, u32, u32)],
    rgba: [u8; 4],
) -> usize {
    let width = width as usize;
    let height = height as usize;
    let mut painted = 0;
    for &(bx, by, bw, bh) in boxes {
        let x0 = (bx as usize).min(width);
        let y0 = (by as usize).min(height);
        let x1 = (bx as usize + bw as usize).min(width);
        let y1 = (by as usize + bh as usize).min(height);
        if x0 >= x1 || y0 >= y1 {
            continue;
        }
        for py in y0..y1 {
            for px in x0..x1 {
                let idx = (py * width + px) * 4;
                if idx + 4 <= bytes.len() {
                    bytes[idx..idx + 4].copy_from_slice(&rgba);
                }
            }
        }
        painted += 1;
    }
    painted
}

pub enum ImageResult {
    Unavailable,
    NoSecrets,
    Redacted {
        bytes: Vec<u8>,
        w: u32,
        h: u32,
        count: usize,
    },
    DetectedUnmappable,
}

const REDACT_FILL: [u8; 4] = [0, 0, 0, 255];

pub fn redact_image(bytes: &[u8], w: u32, h: u32, ocr: &dyn Ocr, det: &Detector) -> ImageResult {
    let words = match ocr.recognize(bytes, w, h) {
        Ok(words) => words,
        Err(_) => return ImageResult::Unavailable,
    };

    let assembled = assemble(&words);
    let text = zeroize::Zeroizing::new(assembled.text);
    let result = det.scan(&text);
    if !result.has_secrets {
        return ImageResult::NoSecrets;
    }

    let mut spans: Vec<(usize, usize)> = result
        .matched_spans
        .iter()
        .map(|(s, e, _)| (*s, *e))
        .collect();
    spans.extend(result.extra_spans.iter().map(|(s, e, _)| (*s, *e)));
    spans.extend(result.deep_findings.iter().filter_map(|f| f.span));
    for (token, _) in &result.high_entropy_tokens {
        if token.is_empty() {
            continue;
        }
        for (s, frag) in text.match_indices(token.as_str()) {
            spans.push((s, s + frag.len()));
        }
    }

    let count = result.matched_patterns.len()
        + result.deep_findings.len()
        + result.high_entropy_tokens.len();

    let boxes = boxes_for_spans(&words, &assembled.ranges, &spans);
    if boxes.is_empty() {
        return ImageResult::DetectedUnmappable;
    }

    let mut out = bytes.to_vec();
    paint_boxes(&mut out, w, h, &boxes, REDACT_FILL);
    ImageResult::Redacted {
        bytes: out,
        w,
        h,
        count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn word(text: &str, x: u32, line: u32) -> OcrWord {
        OcrWord {
            text: text.to_string(),
            x,
            y: 10,
            w: 40,
            h: 12,
            conf: 90.0,
            block: 1,
            line,
        }
    }

    #[test]
    fn assemble_tracks_byte_offsets_and_separators() {
        let words = vec![word("foo", 0, 1), word("bar", 50, 1), word("baz", 0, 2)];
        let a = assemble(&words);
        assert_eq!(a.text, "foo bar\nbaz");
        for (i, &(s, e)) in a.ranges.iter().enumerate() {
            assert_eq!(&a.text[s..e], words[i].text);
        }
        assert_eq!(&a.text[a.ranges[0].1..a.ranges[1].0], " ");
        assert_eq!(&a.text[a.ranges[1].1..a.ranges[2].0], "\n");
    }

    #[test]
    fn span_on_separator_selects_no_box() {
        let words = vec![word("foo", 0, 1), word("bar", 50, 1)];
        let a = assemble(&words);
        let sep = a.ranges[0].1;
        let boxes = boxes_for_spans(&words, &a.ranges, &[(sep, sep + 1)]);
        assert!(boxes.is_empty());
    }

    #[test]
    fn multiword_span_selects_every_overlapped_word() {
        let words = vec![word("aaa", 0, 1), word("bbb", 50, 1), word("ccc", 100, 1)];
        let a = assemble(&words);
        let span = (a.ranges[0].0, a.ranges[1].1);
        let boxes = boxes_for_spans(&words, &a.ranges, &[span]);
        assert_eq!(boxes, vec![(0, 10, 40, 12), (50, 10, 40, 12)]);
    }

    #[test]
    fn paint_clamps_to_bounds_and_fills_region() {
        let mut bytes = vec![255u8; 4 * 4 * 4];
        let painted = paint_boxes(&mut bytes, 4, 4, &[(2, 2, 10, 10)], REDACT_FILL);
        assert_eq!(painted, 1);
        let at = |x: usize, y: usize| {
            let i = (y * 4 + x) * 4;
            [bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]
        };
        assert_eq!(at(3, 3), [0, 0, 0, 255]);
        assert_eq!(at(0, 0), [255, 255, 255, 255]);
        assert_eq!(at(1, 1), [255, 255, 255, 255]);
    }

    #[test]
    fn fully_out_of_bounds_box_paints_nothing() {
        let mut bytes = vec![255u8; 4 * 4 * 4];
        let painted = paint_boxes(&mut bytes, 4, 4, &[(10, 10, 5, 5)], REDACT_FILL);
        assert_eq!(painted, 0);
        assert!(bytes.iter().all(|&b| b == 255));
    }

    struct StubOcr(Vec<OcrWord>);
    impl Ocr for StubOcr {
        fn recognize(&self, _: &[u8], _: u32, _: u32) -> Result<Vec<OcrWord>, OcrError> {
            Ok(self.0.iter().map(|w| word(&w.text, w.x, w.line)).collect())
        }
    }

    struct MissingOcr;
    impl Ocr for MissingOcr {
        fn recognize(&self, _: &[u8], _: u32, _: u32) -> Result<Vec<OcrWord>, OcrError> {
            Err(OcrError::NotInstalled)
        }
    }

    #[test]
    fn redacts_only_the_secret_word_box() {
        let det = Detector::from_config(&Config::default());
        let words = vec![
            word("hello", 0, 1),
            word("AKIAIOSFODNN7EXAMPLE", 100, 1),
            word("world", 300, 1),
        ];
        let bytes = vec![255u8; 400 * 30 * 4];
        match redact_image(&bytes, 400, 30, &StubOcr(words), &det) {
            ImageResult::Redacted {
                bytes: out, count, ..
            } => {
                assert!(count >= 1);
                let painted_at = |x: usize| {
                    let i = (10 * 400 + x) * 4;
                    out[i] == 0 && out[i + 1] == 0 && out[i + 2] == 0
                };
                assert!(painted_at(110), "secret word should be painted");
                assert!(!painted_at(10), "clean word should be untouched");
                assert!(!painted_at(310), "clean word should be untouched");
            }
            _ => panic!("expected a redacted image"),
        }
    }

    #[test]
    fn missing_ocr_is_unavailable() {
        let det = Detector::from_config(&Config::default());
        let bytes = vec![0u8; 4 * 4 * 4];
        assert!(matches!(
            redact_image(&bytes, 4, 4, &MissingOcr, &det),
            ImageResult::Unavailable
        ));
    }

    #[test]
    fn clean_image_reports_no_secrets() {
        let det = Detector::from_config(&Config::default());
        let words = vec![word("hello", 0, 1), word("world", 80, 1)];
        let bytes = vec![255u8; 200 * 30 * 4];
        assert!(matches!(
            redact_image(&bytes, 200, 30, &StubOcr(words), &det),
            ImageResult::NoSecrets
        ));
    }
}
