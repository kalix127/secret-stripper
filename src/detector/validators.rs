//! Pure post-match validators (checksums / structural checks).
//!
//! The Rust `regex` crate has no lookaround or arithmetic, so a check digit
//! can never run inside a pattern. These functions are the second stage:
//! `Detector::scan` calls `validator_for(pattern.regex.as_str())` after a
//! regex match and drops the match when the validator rejects it. This is
//! the keyword-free path that lets numeric IDs / cards / IBAN ship without a
//! proximity keyword.
//!
//! `validator_for` is intentionally empty right now (every pattern is
//! unvalidated, so detector behaviour is unchanged). Each later block that
//! adds a checksum-gated pattern registers its regex source here.
//!
//! All helpers are pure and unit-tested against authoritative reference
//! values; the concrete per-country wrappers are added with their blocks.

/// Keep only ASCII digits.
fn digits(s: &str) -> Vec<u32> {
    s.bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u32)
        .collect()
}

/// Luhn mod-10 (payment cards, IMEI, the NPI/`80840` base, etc.).
pub fn luhn(s: &str) -> bool {
    let d = digits(s);
    if d.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &v) in d.iter().rev().enumerate() {
        if i % 2 == 1 {
            let dbl = v * 2;
            sum += if dbl > 9 { dbl - 9 } else { dbl };
        } else {
            sum += v;
        }
    }
    sum.is_multiple_of(10)
}

/// Generic weighted mod-11 over a digit string `payload` (no check digit);
/// returns the check value in `0..=10` (10 meaning the "X" symbol).
pub fn mod11_weighted(payload: &[u32], weights: &[u32]) -> u32 {
    let sum: u32 = payload.iter().zip(weights.iter()).map(|(d, w)| d * w).sum();
    sum % 11
}

/// US NHS / CHI number: 10 digits, weights 10..2, check = 11 - (sum % 11),
/// 11 -> 0, a remainder giving 10 is invalid.
pub fn nhs_mod11(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let weights = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let check = mod11_weighted(&d[..9], &weights);
    let expected = match 11 - check {
        11 => 0,
        10 => return false,
        v => v,
    };
    expected == d[9]
}

/// US NPI: Luhn over the constant `80840` prefix + the 10-digit NPI.
pub fn npi_80840(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    luhn(&format!(
        "80840{}",
        d.iter().map(|x| x.to_string()).collect::<String>()
    ))
}

/// US DEA registration number: 2 letters + 7 digits, where
/// (d1+d3+d5) + 2*(d2+d4+d6) ends in d7.
pub fn dea(s: &str) -> bool {
    let letters = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let d = digits(s);
    if letters < 2 || d.len() != 7 {
        return false;
    }
    let chk = (d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5]);
    chk % 10 == d[6]
}

/// ISO 7064 MOD 97-10 over a digit string: value mod 97 == 1. Computed
/// digit-by-digit so arbitrarily long inputs never overflow.
pub fn iso7064_mod97_10(numeric: &str) -> bool {
    let mut rem: u32 = 0;
    let mut any = false;
    for b in numeric.bytes() {
        if !b.is_ascii_digit() {
            return false;
        }
        any = true;
        rem = (rem * 10 + (b - b'0') as u32) % 97;
    }
    any && rem == 1
}

/// IBAN check: ISO 13616 structure -> move first 4 chars to the end,
/// expand letters (A=10..Z=35), then ISO 7064 MOD 97-10.
pub fn iban_mod97(s: &str) -> bool {
    let raw: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if raw.len() < 5 || raw.len() > 34 {
        return false;
    }
    if !raw.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let (head, tail) = raw.split_at(4);
    let rearranged = format!("{tail}{head}");
    let mut expanded = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            expanded.push(c);
        } else {
            expanded.push_str(&((c as u32) - ('A' as u32) + 10).to_string());
        }
    }
    iso7064_mod97_10(&expanded)
}

/// Two-pass mod-11 (Estonia Isikukood style): first pass weights, and on a
/// remainder of 10 a second pass with shifted weights; returns the digit.
pub fn dual_pass_mod11(payload: &[u32], w1: &[u32], w2: &[u32]) -> u32 {
    let r1 = mod11_weighted(payload, w1);
    if r1 < 10 {
        return r1;
    }
    let r2 = mod11_weighted(payload, w2);
    if r2 < 10 {
        r2
    } else {
        0
    }
}

/// MRZ (ICAO 9303) check digit over `data`: weights 7,3,1 repeating;
/// digits as-is, A-Z = 10..35, filler `<` = 0. Returns the check digit.
pub fn mrz_check_731(data: &str) -> u32 {
    let w = [7u32, 3, 1];
    let mut sum = 0u32;
    for (i, c) in data.chars().enumerate() {
        let v = if c == '<' {
            0
        } else if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else if c.is_ascii_alphabetic() {
            c.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        } else {
            return u32::MAX;
        };
        sum += v * w[i % 3];
    }
    sum % 10
}

/// TD3 passport MRZ (2x44). Shared so the bucket pattern and the registry
/// key are byte-identical (`Regex::as_str()` returns the source verbatim).
pub const MRZ_TD3_RE: &str = r"P[A-Z<][A-Z]{3}[A-Z<]{39}[\r\n]+[A-Z0-9<]{44}";

/// Generic IBAN shape; the `iban_mod97` validator does CC-length + ISO 7064
/// MOD 97-10, so this stays keyword-free with near-zero false positives.
pub const IBAN_RE: &str = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b";

/// Per-country IBAN fast-paths. Each is `iban_mod97`-gated in the registry,
/// so the loose shape never redacts a non-IBAN digit run.
pub const IBAN_DE_RE: &str = r"\bDE\d{20}\b";
pub const IBAN_GB_RE: &str = r"\bGB\d{2}[A-Z]{4}\d{14}\b";
pub const IBAN_FR_RE: &str = r"\bFR\d{12}[A-Z0-9]{11}\d{2}\b";
pub const IBAN_IT_RE: &str = r"\bIT\d{2}[A-Z]\d{10}[A-Z0-9]{12}\b";
pub const IBAN_ES_RE: &str = r"\bES\d{22}\b";

/// Payment-card BIN/IIN shapes. Every brand here is `luhn`-gated in the
/// registry: shape + issuer prefix + Mod-10 must all agree, which drives the
/// card false-positive rate to near zero (a random digit run starting with a
/// valid BIN passes Luhn only ~1 in 10). Separators are matched but ignored
/// by `luhn` (it keeps digits only). UnionPay is intentionally NOT here:
/// genuine UnionPay cards are not all Luhn-valid, so it stays prefix-anchored
/// in the bucket without a checksum gate.
pub const CARD_VISA_RE: &str = r"\b4\d{3}(?:[ -]?\d{4}){3}(?:[ -]?\d{3})?\b";
pub const CARD_MASTERCARD_RE: &str =
    r"\b(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)(?:[ -]?\d{4}){3}\b";
pub const CARD_AMEX_RE: &str = r"\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b";
pub const CARD_DISCOVER_RE: &str =
    r"\b(?:6011|64[4-9]\d|65\d{2}|622\d{3})(?:[ -]?\d{4}){2}[ -]?\d{1,4}\b";
pub const CARD_DINERS_RE: &str = r"\b3(?:0[0-5]|[68]\d)\d{11}\b";
pub const CARD_JCB_RE: &str = r"\b35(?:2[89]|[3-8]\d)\d{12}\b";
pub const CARD_MAESTRO_RE: &str = r"\b(?:5018|5020|5038|5893|6304|6759|676[1-3])\d{8,15}\b";
pub const CARD_DANKORT_RE: &str = r"\b5019\d{12}\b";
pub const CARD_MIR_RE: &str = r"\b220[0-4]\d{12}\b";

/// Validate a matched TD3 MRZ: the document-number, DOB and expiry field
/// check digits plus the line-2 composite check digit (ICAO 9303, 7-3-1).
pub fn mrz_td3(s: &str) -> bool {
    let chars: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '<')
        .collect();
    if chars.len() < 88 {
        return false;
    }
    let l2: String = chars[chars.len() - 44..].iter().collect();
    let cd = |c: char| -> u32 {
        if c == '<' {
            0
        } else if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else {
            u32::MAX
        }
    };
    let b: Vec<char> = l2.chars().collect();
    if mrz_check_731(&l2[0..9]) != cd(b[9]) {
        return false;
    }
    if mrz_check_731(&l2[13..19]) != cd(b[19]) {
        return false;
    }
    if mrz_check_731(&l2[21..27]) != cd(b[27]) {
        return false;
    }
    let composite = format!("{}{}{}", &l2[0..10], &l2[13..20], &l2[21..43]);
    mrz_check_731(&composite) == cd(b[43])
}

/// Poland PESEL: 11 digits, weights 1,3,7,9 cycled, check = (10 - sum%10)%10.
pub fn pesel(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 {
        return false;
    }
    let w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = d[..10].iter().zip(w).map(|(a, b)| a * b).sum();
    (10 - sum % 10) % 10 == d[10]
}

/// Netherlands BSN 11-proef: 9 digits, weights 9..2 then -1, sum % 11 == 0.
pub fn bsn_11proef(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let w: [i64; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i64 = d.iter().zip(w).map(|(a, b)| *a as i64 * b).sum();
    sum % 11 == 0
}

/// Belgium Rijksregisternummer: 11 digits; check = 97 - (first9 % 97),
/// with a `2` prepended for births from 2000 onward.
pub fn belgium_rrn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 {
        return false;
    }
    let to_num = |sl: &[u32]| sl.iter().fold(0u64, |a, &x| a * 10 + x as u64);
    let f9 = to_num(&d[..9]);
    let chk = to_num(&d[9..]);
    97 - (f9 % 97) == chk || 97 - ((2_000_000_000 + f9) % 97) == chk
}

/// France NIR: 15 digits, key = 97 - (first13 % 97) (Corsica 2A/2B
/// substitution is handled by the caller's regex; numeric form here).
pub fn france_nir(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 15 {
        return false;
    }
    let n = d[..13].iter().fold(0u64, |a, &x| a * 10 + x as u64);
    let key = d[13..].iter().fold(0u64, |a, &x| a * 10 + x as u64);
    97 - (n % 97) == key
}

/// Spain DNI/NIE control letter: letter = "TRWAGMYFPDXBNJZSQVHLCKE"[n % 23],
/// where NIE replaces the leading X/Y/Z with 0/1/2. Parsed from the end of
/// the match so the preceding "DNI"/"NIE" label is ignored.
pub fn spain_dni(s: &str) -> bool {
    let t: Vec<char> = s.chars().collect();
    let mut i = t.len();
    while i > 0 && !t[i - 1].is_ascii_alphabetic() {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let ctrl = t[i - 1].to_ascii_uppercase();
    let mut j = i - 1;
    let mut digs = String::new();
    while j > 0 && t[j - 1].is_ascii_digit() {
        digs.insert(0, t[j - 1]);
        j -= 1;
    }
    if digs.len() < 7 || digs.len() > 8 {
        return false;
    }
    let num: u64 = if j > 0 && matches!(t[j - 1].to_ascii_uppercase(), 'X' | 'Y' | 'Z') {
        let p = match t[j - 1].to_ascii_uppercase() {
            'X' => '0',
            'Y' => '1',
            _ => '2',
        };
        format!("{p}{digs}").parse().unwrap_or(u64::MAX)
    } else {
        digs.parse().unwrap_or(u64::MAX)
    };
    if num == u64::MAX {
        return false;
    }
    b"TRWAGMYFPDXBNJZSQVHLCKE"[(num % 23) as usize] as char == ctrl
}

/// Brazil CPF: 11 digits, two mod-11 check digits (weights 10..2 / 11..2;
/// r = sum*10 % 11, 10 -> 0). Repdigits rejected.
pub fn brazil_cpf(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    for n in [9usize, 10] {
        let sum: u32 = (0..n).map(|i| d[i] * (n as u32 + 1 - i as u32)).sum();
        let r = (sum * 10) % 11;
        let c = if r == 10 { 0 } else { r };
        if c != d[n] {
            return false;
        }
    }
    true
}

/// Brazil CNPJ: 14 alnum, two mod-11 check DIGITS. Covers both the legacy
/// numeric form and the 2026 alphanumeric form (char value = ASCII - 48,
/// which equals the digit value for '0'..'9', so one routine serves both).
pub fn brazil_cnpj(s: &str) -> bool {
    let body: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if body.len() != 14 || body.iter().all(|&c| c == body[0]) {
        return false;
    }
    if !body[12].is_ascii_digit() || !body[13].is_ascii_digit() {
        return false;
    }
    let v = |c: char| (c as i32 - 48) as i64;
    let w1 = [5i64, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let w2 = [6i64, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let mut vals: Vec<i64> = body[..12].iter().map(|&c| v(c)).collect();
    for w in [&w1[..], &w2[..]] {
        let sum: i64 = vals
            .iter()
            .rev()
            .zip(w.iter().rev())
            .map(|(a, b)| a * b)
            .sum();
        let r = sum % 11;
        let c = if r < 2 { 0 } else { 11 - r };
        vals.push(c);
    }
    vals[12] == v(body[12]) && vals[13] == v(body[13])
}

/// Estonia Isikukood: 11 digits, dual-pass mod-11 over the first 10
/// (weights 1..9,1 then 3..9,1,2,3; a second-pass 10 -> check 0).
pub fn estonia_isikukood(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 {
        return false;
    }
    let w1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
    let w2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3];
    dual_pass_mod11(&d[..10], &w1, &w2) == d[10]
}

/// Czech/Slovak rodne cislo, modern 10-digit form: plausible YYMMDD (female
/// month +50, post-2004 overflow +20/+70; sequence-overflow day offsets are
/// not stripped) and the whole number divisible by 11, or the pre-1985
/// exception where the first 9 digits mod 11 == 10 and the check digit is 0.
pub fn czech_rc(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let mut mm = d[2] * 10 + d[3];
    mm = if (51..=62).contains(&mm) {
        mm - 50
    } else if (71..=82).contains(&mm) {
        mm - 70
    } else if (21..=32).contains(&mm) {
        mm - 20
    } else {
        mm
    };
    let dd = d[4] * 10 + d[5];
    if !(1..=12).contains(&mm) || !(1..=31).contains(&dd) {
        return false;
    }
    let n10 = d.iter().fold(0u64, |a, &x| a * 10 + x as u64);
    let f9 = d[..9].iter().fold(0u64, |a, &x| a * 10 + x as u64);
    n10 % 11 == 0 || (f9 % 11 == 10 && d[9] == 0)
}

/// Romania CNP: 13 digits, weights 279146358279 over the first 12,
/// control = sum % 11 (a remainder of 10 -> control digit 1).
pub fn romania_cnp(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    let w = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];
    let r = d[..12].iter().zip(w).map(|(a, b)| a * b).sum::<u32>() % 11;
    let c = if r == 10 { 1 } else { r };
    c == d[12]
}

/// China Resident Identity Card: 18 chars, ISO 7064 MOD 11-2 over the
/// first 17 digits (weights 7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2),
/// remainder mapped via "10X98765432" to the trailing check character.
pub fn china_rid(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, 'X' | 'x'))
        .collect();
    if c.len() != 18 || !c[..17].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let w = [7u32, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let sum: u32 = c[..17]
        .iter()
        .zip(w)
        .map(|(d, w)| (*d as u32 - '0' as u32) * w)
        .sum();
    let expected = b"10X98765432"[(sum % 11) as usize] as char;
    c[17].to_ascii_uppercase() == expected
}

/// Turkey TC Kimlik No: 11 digits, d1 != 0, two check digits -
/// d10 = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) mod 10,
/// d11 = (d1..d10 sum) mod 10.
pub fn turkey_tckn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let even = d[1] + d[3] + d[5] + d[7];
    let c10 = (odd * 7 + 100 - even) % 10;
    let c11 = d[..10].iter().sum::<u32>() % 10;
    c10 == d[9] && c11 == d[10]
}

/// Israel Teudat Zehut: up to 9 digits (left-zero-padded), alternating
/// weights 1,2 with digit-sum folding, total mod 10 == 0.
pub fn israel_id(s: &str) -> bool {
    let mut d = digits(s);
    if d.is_empty() || d.len() > 9 {
        return false;
    }
    while d.len() < 9 {
        d.insert(0, 0);
    }
    let mut t = 0u32;
    for (i, &v) in d.iter().enumerate() {
        let x = v * if i % 2 == 0 { 1 } else { 2 };
        t += if x < 10 { x } else { x - 9 };
    }
    t.is_multiple_of(10)
}

/// US SSN structural validity (no checksum exists): area not 000/666/
/// 900-999, group not 00, serial not 0000.
pub fn us_ssn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let area = d[0] * 100 + d[1] * 10 + d[2];
    let group = d[3] * 10 + d[4];
    let serial = d[5] * 1000 + d[6] * 100 + d[7] * 10 + d[8];
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// Keyword-free, checksum-gated gov-ID regexes (shared so the registry key
/// is byte-identical to the bucket pattern's source).
/// US DEA registration number (2 letters + 7 digits, `dea` checksum).
/// Unified so the two bucket definitions share one registry key.
pub const US_DEA_RE: &str = r"\b[ABCDEFGHJKLMNPRSTUX][A-Z9]\d{7}\b";
/// UK NHS number, label-gated + `nhs_mod11` (10 digits, keyword-free is
/// too FP-prone per the locked discipline). Shared by both buckets.
pub const UK_NHS_RE: &str = r"(?i)\bNHS[:#\s]+\d{3}[ -]?\d{3}[ -]?\d{4}\b";
/// US NPI, label-gated + `npi_80840` (Luhn over the 80840 prefix); and
/// the 80840-card form, Luhn over the full 15 digits.
pub const US_NPI_RE: &str = r"(?i)\bNPI[:#\s]+\d{10}\b";
pub const US_NPI_CARD_RE: &str = r"\b80840\d{10}\b";
pub const TR_TCKN_RE: &str = r"\b[1-9]\d{10}\b";
pub const IL_TZ_RE: &str = r"(?i)\b(?:teudat[\s-]?zehut|israeli?[\s-]?id)\b[:#=\s]+\d{8,9}\b";
pub const US_SSN_RE: &str = r"\b\d{3}-\d{2}-\d{4}\b";
pub const IMEI_RE: &str = r"(?i)\bimei\s*[:=]?\s*\d{15}\b";
pub const ICCID_RE: &str = r"(?i)\biccid\s*[:=]?\s*89\d{17,18}\b";
pub const CN_RID_RE: &str =
    r"\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b";
pub const EE_ISIKUKOOD_RE: &str = r"\b[1-6]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b";
pub const CZ_RC_RE: &str = r"\b\d{6}/\d{4}\b";
pub const RO_CNP_RE: &str = r"\b[1-9]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{6}\b";

/// Label+checksum gov-ID regexes (shared so the registry key is identical).
pub const SPAIN_DNI_RE: &str = r"(?i)\b(?:DNI|NIE)\b[:#=\s]+[XYZ]?\d{7,8}[A-Za-z]\b";
pub const BR_CPF_RE: &str = r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b";
pub const BR_CNPJ_RE: &str = r"\b[0-9A-Z]{2}\.?[0-9A-Z]{3}\.?[0-9A-Z]{3}/?[0-9A-Z]{4}-?\d{2}\b";
pub const PESEL_RE: &str = r"(?i)\bPESEL\b[:#=\s]+\d{11}\b";
pub const BSN_RE: &str = r"(?i)\b(?:BSN|burgerservicenummer)\b[:#=\s]+\d{9}\b";
pub const BE_RRN_RE: &str = r"(?i)\b(?:rijksregisternummer|RRN|NISS)\b[:#=\s]+[\d.\-]{11,17}";
pub const FR_NIR_RE: &str = r"(?i)\b(?:NIR|INSEE|secu)\b[:#=\s]+[\d ]{15,25}";

/// Generic E.164: leading `+CC` then 9-16 more digits, tolerating single
/// space/hyphen group separators (`+39 333 1234567`). The `e164`
/// post-filter strips separators and does the real FP control.
pub const E164_RE: &str = r"\+[1-9](?:[ \-]?\d){9,16}\b";

/// ITU-T assigned country/zone calling codes (Recommendation E.164
/// numbering plan). Longest-prefix matched; codes not in this set are
/// false positives.
const E164_CC: &[&str] = &[
    "1", "7", "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45",
    "46", "47", "48", "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63",
    "64", "65", "66", "81", "82", "84", "86", "90", "91", "92", "93", "94", "95", "98", "211",
    "212", "213", "216", "218", "220", "221", "222", "223", "224", "225", "226", "227", "228",
    "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240", "241",
    "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253", "254",
    "255", "256", "257", "258", "260", "261", "262", "263", "264", "265", "266", "267", "268",
    "269", "290", "291", "297", "298", "299", "350", "351", "352", "353", "354", "355", "356",
    "357", "358", "359", "370", "371", "372", "373", "374", "375", "376", "377", "378", "379",
    "380", "381", "382", "383", "385", "386", "387", "389", "420", "421", "423", "500", "501",
    "502", "503", "504", "505", "506", "507", "508", "509", "590", "591", "592", "593", "594",
    "595", "596", "597", "598", "599", "670", "672", "673", "674", "675", "676", "677", "678",
    "679", "680", "681", "682", "683", "685", "686", "687", "688", "689", "690", "691", "692",
    "850", "852", "853", "855", "856", "880", "886", "960", "961", "962", "963", "964", "965",
    "966", "967", "968", "970", "971", "972", "973", "974", "975", "976", "977", "992", "993",
    "994", "995", "996", "998",
];

/// Freephone / UIFN / satellite / network-services codes - valid E.164
/// but never a personal subscriber number, so treated as non-PII.
const E164_SPECIAL_CC: &[&str] = &[
    "800", "808", "870", "878", "879", "881", "882", "883", "888", "979",
];

/// E.164 post-filter: 8-15 digits, an assigned (non-special) ITU country
/// code by longest-prefix, and not an all-same / strictly sequential run.
pub fn e164(s: &str) -> bool {
    let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let n = d.len();
    if !(8..=15).contains(&n) {
        return false;
    }
    let b = d.as_bytes();
    if b.iter().all(|&x| x == b[0]) {
        return false;
    }
    let asc = (1..n).all(|i| b[i] as i16 - b[i - 1] as i16 == 1);
    let desc = (1..n).all(|i| b[i - 1] as i16 - b[i] as i16 == 1);
    if asc || desc {
        return false;
    }
    if E164_SPECIAL_CC.iter().any(|sp| d.starts_with(sp)) {
        return false;
    }
    [3usize, 2, 1]
        .into_iter()
        .filter(|&len| n > len)
        .any(|len| E164_CC.contains(&&d[..len]))
}

/// VIN transliteration (ISO 3779 / NA check digit): digits as-is,
/// letters A=1..Z mapped skipping I/O/Q.
fn vin_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return Some(c as u32 - '0' as u32);
    }
    match c.to_ascii_uppercase() {
        'A' | 'J' => Some(1),
        'B' | 'K' | 'S' => Some(2),
        'C' | 'L' | 'T' => Some(3),
        'D' | 'M' | 'U' => Some(4),
        'E' | 'N' | 'V' => Some(5),
        'F' | 'W' => Some(6),
        'G' | 'P' | 'X' => Some(7),
        'H' | 'Y' => Some(8),
        'R' | 'Z' => Some(9),
        _ => None,
    }
}

/// North-America VIN: 17 chars, position-9 check digit (weights
/// 8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2; sum mod 11; 10 -> 'X'). Repdigit
/// rejected (passes the maths but is never a real VIN).
pub fn vin_na(s: &str) -> bool {
    let all: Vec<char> = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    // A labeled match keeps the "VIN" label letters; the VIN is the
    // trailing 17-char token (regex-anchored), so take the last 17.
    if all.len() < 17 {
        return false;
    }
    let c = &all[all.len() - 17..];
    if c.iter().all(|&x| x == c[0]) {
        return false;
    }
    let w = [8u32, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let mut sum = 0u32;
    for (i, &ch) in c.iter().enumerate() {
        match vin_value(ch) {
            Some(v) => sum += v * w[i],
            None => return false,
        }
    }
    let chk = match sum % 11 {
        10 => 'X',
        r => (b'0' + r as u8) as char,
    };
    c[8].to_ascii_uppercase() == chk
}

/// IMO ship number: 7 digits, weights 7,6,5,4,3,2 over the first 6,
/// check = sum mod 10.
pub fn imo_number(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 7 {
        return false;
    }
    (7 * d[0] + 6 * d[1] + 5 * d[2] + 4 * d[3] + 3 * d[4] + 2 * d[5]) % 10 == d[6]
}

/// ISO 6346 shipping container: 4 letters + 6 serial digits + check.
/// Letter values A=10.. skipping multiples of 11, weights 2^position
/// over the first 10 chars, mod 11 then mod 10 == check digit.
pub fn iso6346(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 11 {
        return false;
    }
    let mut sum = 0u64;
    for (i, &ch) in c[..10].iter().enumerate() {
        let v = if ch.is_ascii_digit() {
            ch as u64 - '0' as u64
        } else {
            let mut n = 10u64;
            for letter in 'A'..='Z' {
                if n.is_multiple_of(11) {
                    n += 1;
                }
                if letter == ch {
                    break;
                }
                n += 1;
            }
            n
        };
        sum += v * (1u64 << i);
    }
    let chk = c[10] as u64 - '0' as u64;
    c[10].is_ascii_digit() && (sum % 11) % 10 == chk
}

/// UPU S10 international mail item: 2 service letters, 8-digit serial,
/// 1 check digit, country code. Check weights 8,6,4,2,3,5,9,7;
/// c = 11 - (sum mod 11); 10 -> 0, 11 -> 5.
pub fn usps_s10(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let w = [8u32, 6, 4, 2, 3, 5, 9, 7];
    let c = 11 - (d[..8].iter().zip(w).map(|(a, b)| a * b).sum::<u32>() % 11);
    let c = match c {
        10 => 0,
        11 => 5,
        v => v,
    };
    c == d[8]
}

/// Per-country phone NSN: strip the country code and one optional trunk
/// `0`, return the national significant number digits.
fn nsn(s: &str, cc: &str) -> Vec<u32> {
    let d = digits(s);
    let ccd: Vec<u32> = cc.bytes().map(|b| (b - b'0') as u32).collect();
    if d.len() < ccd.len() || d[..ccd.len()] != ccd[..] {
        return d;
    }
    let mut rest = d[ccd.len()..].to_vec();
    if rest.first() == Some(&0) {
        rest.remove(0);
    }
    rest
}

/// Permissive separator-tolerant per-country phone regexes; the strict
/// NSN-length / leading-digit rules live in the validators below.
pub const PHONE_US_RE: &str = r"(?:\+1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b";
pub const PHONE_UK_RE: &str = r"\+44[ .\-]?0?(?:[ .\-]?\d){9,11}\b";
pub const PHONE_IT_RE: &str = r"\+39[ .\-]?0?(?:[ .\-]?\d){8,12}\b";
pub const PHONE_FR_RE: &str = r"\+33[ .\-]?0?(?:[ .\-]?\d){9,11}\b";
pub const PHONE_DE_RE: &str = r"\+49[ .\-]?0?(?:[ .\-]?\d){6,12}\b";
pub const PHONE_ES_RE: &str = r"\+34[ .\-]?(?:[ .\-]?\d){9,11}\b";
pub const PHONE_BR_RE: &str = r"\+55[ .\-]?(?:[ .\-]?\d){10,12}\b";
pub const PHONE_IN_RE: &str = r"\+91[ .\-]?(?:[ .\-]?\d){10,12}\b";

/// Pull signed decimal numbers out of a coordinate string.
fn coord_nums(s: &str) -> Vec<f64> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'+' || c == b'-' || c.is_ascii_digit() {
            let start = i;
            if c == b'+' || c == b'-' {
                i += 1;
            }
            let mut digit = false;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                digit |= b[i].is_ascii_digit();
                i += 1;
            }
            if digit {
                if let Ok(f) = s[start..i].parse::<f64>() {
                    out.push(f);
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Coordinate range check (order-agnostic so it serves both lat,lon and
/// GeoJSON/KML lon,lat order): two numbers, one within +/-90 and the
/// other within +/-180.
pub fn geo_coord(s: &str) -> bool {
    let n = coord_nums(s);
    if n.len() < 2 {
        return false;
    }
    let (a, b) = (n[0].abs(), n[1].abs());
    (a <= 90.0 && b <= 180.0) || (b <= 90.0 && a <= 180.0)
}

/// Geo coordinate regexes (range-checked by `geo_coord`).
pub const GEO_URI_RE: &str = r"(?i)\bgeo:[-+]?\d{1,3}(?:\.\d+)?,[-+]?\d{1,3}(?:\.\d+)?";
pub const GEO_ISO6709_RE: &str = r"[-+]\d{1,3}(?:\.\d+)?[-+]\d{1,3}(?:\.\d+)?/";
pub const GEO_MAPLINK_RE: &str = r"/@-?\d{1,2}\.\d{3,},-?\d{1,3}\.\d{3,}";
pub const GEO_KML_RE: &str = r"<coordinates>\s*[-+]?\d+\.\d+,[-+]?\d+\.\d+";
pub const GEO_GEOJSON_RE: &str = r#""type"\s*:\s*"Point"\s*,\s*"coordinates"\s*:\s*\[\s*-?\d{1,3}(?:\.\d+)?\s*,\s*-?\d{1,3}(?:\.\d+)?"#;

/// ORCID iD: 16 chars (15 digits + check), ISO 7064 MOD 11-2,
/// check 10 written as 'X'.
pub fn orcid(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, 'X' | 'x'))
        .collect();
    if c.len() != 16 || !c[..15].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut total = 0u32;
    for ch in &c[..15] {
        total = (total + (*ch as u32 - '0' as u32)) * 2;
    }
    let chk = (12 - total % 11) % 11;
    let expected = if chk == 10 {
        'X'
    } else {
        (b'0' + chk as u8) as char
    };
    c[15].to_ascii_uppercase() == expected
}

/// ISIN: 2-letter country + 9 alnum + check digit; expand letters
/// A=10..Z=35 to digits, then Luhn mod 10 over the whole string.
pub fn isin(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 12 {
        return false;
    }
    let mut expanded = String::new();
    for ch in &c {
        if ch.is_ascii_digit() {
            expanded.push(*ch);
        } else {
            expanded.push_str(&((*ch as u32) - 'A' as u32 + 10).to_string());
        }
    }
    luhn(&expanded)
}

/// Vehicle / maritime / mail identifiers (checksum-gated).
pub const VIN_LABELED_RE: &str = r"(?i)\bVIN:\s*[A-HJ-NPR-Z0-9]{17}\b";
pub const VIN_NA_RE: &str = r"\b[A-HJ-NPR-Z0-9]{8}[0-9X][A-HJ-NPR-Z0-9]{8}\b";
pub const ISO6346_RE: &str = r"\b[A-Z]{3}[UJZ]\d{7}\b";
pub const IMO_RE: &str = r"(?i)\bIMO\s?\d{7}\b";
pub const USPS_S10_RE: &str = r"\b[A-Z]{2}\d{9}US\b";
pub const ORCID_RE: &str = r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b";
pub const ISIN_RE: &str = r"\b[A-Z]{2}[A-Z0-9]{9}\d\b";

/// US/NANP: 10-digit NSN (optional `+1`), area and exchange leading
/// digit 2-9.
pub fn phone_us(s: &str) -> bool {
    let mut d = digits(s);
    if d.len() == 11 && d[0] == 1 {
        d.remove(0);
    }
    d.len() == 10 && (2..=9).contains(&d[0]) && (2..=9).contains(&d[3])
}

/// UK/+44: NSN 9-10 digits, leading 1-9 (trunk 0 already stripped).
pub fn phone_uk(s: &str) -> bool {
    let n = nsn(s, "44");
    (9..=10).contains(&n.len()) && (1..=9).contains(&n[0])
}

/// Italy/+39: NSN 9-11 digits (mobile `3x`, landline `0x` kept).
pub fn phone_it(s: &str) -> bool {
    let d = digits(s);
    if d.len() < 2 || d[..2] != [3, 9] {
        return false;
    }
    let n = &d[2..];
    (9..=11).contains(&n.len())
}

/// France/+33: NSN exactly 9 digits, leading 1-9.
pub fn phone_fr(s: &str) -> bool {
    let n = nsn(s, "33");
    n.len() == 9 && (1..=9).contains(&n[0])
}

/// Germany/+49: NSN 6-11 digits, leading 1-9 (geographic + mobile).
pub fn phone_de(s: &str) -> bool {
    let n = nsn(s, "49");
    (6..=11).contains(&n.len()) && (1..=9).contains(&n[0])
}

/// Spain/+34: NSN exactly 9 digits, leading 6-9.
pub fn phone_es(s: &str) -> bool {
    let n = nsn(s, "34");
    n.len() == 9 && (6..=9).contains(&n[0])
}

/// Brazil/+55: NSN 10 (landline) or 11 (mobile, 3rd digit `9`), 2-digit
/// area code 1-9 leading.
pub fn phone_br(s: &str) -> bool {
    let n = nsn(s, "55");
    if !(10..=11).contains(&n.len()) || n[0] == 0 {
        return false;
    }
    n.len() == 10 || n[2] == 9
}

/// India/+91: NSN exactly 10 digits, leading 6-9 (mobile).
pub fn phone_in(s: &str) -> bool {
    let n = nsn(s, "91");
    n.len() == 10 && (6..=9).contains(&n[0])
}

/// Regex-source -> post-match validator. Keyed by `pattern.regex.as_str()`,
/// unique among the checksum-gated patterns we author. Each checksum block
/// registers its pattern here; everything else is unvalidated (unchanged).
pub fn validator_for(regex_src: &str) -> Option<fn(&str) -> bool> {
    match regex_src {
        MRZ_TD3_RE => Some(mrz_td3),
        IBAN_RE => Some(iban_mod97),
        IBAN_DE_RE | IBAN_GB_RE | IBAN_FR_RE | IBAN_IT_RE | IBAN_ES_RE => Some(iban_mod97),
        CARD_VISA_RE | CARD_MASTERCARD_RE | CARD_AMEX_RE | CARD_DISCOVER_RE | CARD_DINERS_RE
        | CARD_JCB_RE | CARD_MAESTRO_RE | CARD_DANKORT_RE | CARD_MIR_RE => Some(luhn),
        SPAIN_DNI_RE => Some(spain_dni),
        BR_CPF_RE => Some(brazil_cpf),
        BR_CNPJ_RE => Some(brazil_cnpj),
        PESEL_RE => Some(pesel),
        BSN_RE => Some(bsn_11proef),
        BE_RRN_RE => Some(belgium_rrn),
        FR_NIR_RE => Some(france_nir),
        EE_ISIKUKOOD_RE => Some(estonia_isikukood),
        CZ_RC_RE => Some(czech_rc),
        RO_CNP_RE => Some(romania_cnp),
        CN_RID_RE => Some(china_rid),
        US_SSN_RE => Some(us_ssn),
        IMEI_RE => Some(luhn),
        ICCID_RE => Some(luhn),
        TR_TCKN_RE => Some(turkey_tckn),
        IL_TZ_RE => Some(israel_id),
        US_DEA_RE => Some(dea),
        UK_NHS_RE => Some(nhs_mod11),
        US_NPI_RE => Some(npi_80840),
        US_NPI_CARD_RE => Some(luhn),
        E164_RE => Some(e164),
        PHONE_US_RE => Some(phone_us),
        PHONE_UK_RE => Some(phone_uk),
        PHONE_IT_RE => Some(phone_it),
        PHONE_FR_RE => Some(phone_fr),
        PHONE_DE_RE => Some(phone_de),
        PHONE_ES_RE => Some(phone_es),
        PHONE_BR_RE => Some(phone_br),
        PHONE_IN_RE => Some(phone_in),
        VIN_LABELED_RE => Some(vin_na),
        VIN_NA_RE => Some(vin_na),
        ISO6346_RE => Some(iso6346),
        IMO_RE => Some(imo_number),
        USPS_S10_RE => Some(usps_s10),
        ORCID_RE => Some(orcid),
        ISIN_RE => Some(isin),
        GEO_URI_RE => Some(geo_coord),
        GEO_ISO6709_RE => Some(geo_coord),
        GEO_MAPLINK_RE => Some(geo_coord),
        GEO_KML_RE => Some(geo_coord),
        GEO_GEOJSON_RE => Some(geo_coord),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known_vectors() {
        assert!(luhn("4111111111111111"));
        assert!(luhn("4111-1111-1111-1111"));
        assert!(!luhn("4111111111111112"));
        assert!(!luhn("1"));
    }

    #[test]
    fn nhs_known_vectors() {
        assert!(nhs_mod11("9434765919"));
        assert!(!nhs_mod11("9434765918"));
        assert!(!nhs_mod11("943476591"));
    }

    #[test]
    fn npi_known_vectors() {
        assert!(npi_80840("1234567893"));
        assert!(!npi_80840("1234567890"));
    }

    #[test]
    fn dea_known_vectors() {
        // BB1388568: (1+8+5) + 2*(3+8+6) = 14 + 34 = 48 -> ends in 8.
        assert!(dea("BB1388568"));
        assert!(!dea("BB1388561"));
    }

    #[test]
    fn iban_known_vectors() {
        assert!(iban_mod97("GB82WEST12345698765432"));
        assert!(iban_mod97("DE89 3704 0044 0532 0130 00"));
        assert!(!iban_mod97("GB82WEST12345698765431"));
    }

    #[test]
    fn iso7064_mod97_10_core() {
        // GB82WEST12345698765432 rearranged + letter-expanded; value % 97 == 1.
        assert!(iso7064_mod97_10("3214282912345698765432161182"));
        assert!(!iso7064_mod97_10("12345"));
        assert!(!iso7064_mod97_10("abc"));
    }

    #[test]
    fn mrz_check_known_vector() {
        // ICAO 9303 worked example: passport number L898902C3 -> check 6.
        assert_eq!(mrz_check_731("L898902C3"), 6);
        // Date 740812 (12 Aug 1974) -> check 2 in the 9303 sample.
        assert_eq!(mrz_check_731("740812"), 2);
    }

    #[test]
    fn dual_pass_mod11_basic() {
        let w1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
        let w2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3];
        let r = dual_pass_mod11(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &w1, &w2);
        assert_eq!(r, 0);
    }

    #[test]
    fn validator_registry_maps_only_known_regexes() {
        assert!(validator_for(r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}").is_none());
        assert!(validator_for(MRZ_TD3_RE).is_some());
        assert!(validator_for(IBAN_RE).is_some());
        for re in [
            IBAN_DE_RE,
            IBAN_GB_RE,
            IBAN_FR_RE,
            IBAN_IT_RE,
            IBAN_ES_RE,
            CARD_VISA_RE,
            CARD_MASTERCARD_RE,
            CARD_AMEX_RE,
            CARD_DISCOVER_RE,
            CARD_DINERS_RE,
            CARD_JCB_RE,
            CARD_MAESTRO_RE,
            CARD_DANKORT_RE,
            CARD_MIR_RE,
            SPAIN_DNI_RE,
            BR_CPF_RE,
            BR_CNPJ_RE,
            PESEL_RE,
            BSN_RE,
            BE_RRN_RE,
            FR_NIR_RE,
            EE_ISIKUKOOD_RE,
            CZ_RC_RE,
            RO_CNP_RE,
            CN_RID_RE,
            US_SSN_RE,
            IMEI_RE,
            ICCID_RE,
            TR_TCKN_RE,
            IL_TZ_RE,
            US_DEA_RE,
            UK_NHS_RE,
            US_NPI_RE,
            US_NPI_CARD_RE,
            E164_RE,
            PHONE_US_RE,
            PHONE_UK_RE,
            PHONE_IT_RE,
            PHONE_FR_RE,
            PHONE_DE_RE,
            PHONE_ES_RE,
            PHONE_BR_RE,
            PHONE_IN_RE,
            VIN_LABELED_RE,
            VIN_NA_RE,
            ISO6346_RE,
            IMO_RE,
            USPS_S10_RE,
            ORCID_RE,
            ISIN_RE,
            GEO_URI_RE,
            GEO_ISO6709_RE,
            GEO_MAPLINK_RE,
            GEO_KML_RE,
            GEO_GEOJSON_RE,
        ] {
            assert!(validator_for(re).is_some());
        }
    }

    #[test]
    fn eu_govid_known_vectors() {
        assert!(pesel("PESEL: 44051401359"));
        assert!(pesel("02070803628"));
        assert!(!pesel("44051401358"));
        assert!(bsn_11proef("BSN 123456782"));
        assert!(!bsn_11proef("123456789"));
        assert!(belgium_rrn("RRN: 93051822361"));
        assert!(belgium_rrn("00000100195"));
        assert!(france_nir("NIR 1 84 01 76 451 089 64"));
        assert!(!france_nir("1 84 01 76 451 089 00"));
        assert!(spain_dni("DNI: 12345678Z"));
        assert!(spain_dni("NIE X1234567L"));
        assert!(!spain_dni("DNI: 12345678A"));
        assert!(brazil_cpf("111.444.777-35"));
        assert!(!brazil_cpf("11144477736"));
        assert!(!brazil_cpf("11111111111"));
        assert!(brazil_cnpj("11.222.333/0001-81"));
        assert!(brazil_cnpj("12ABC34DE5FG26")); // 2026 alphanumeric form
        assert!(!brazil_cnpj("11222333000182"));
        assert!(estonia_isikukood("37605030299"));
        assert!(estonia_isikukood("38001085718"));
        assert!(!estonia_isikukood("37605030298"));
        assert!(czech_rc("900101/1239"));
        assert!(czech_rc("905101/1233")); // female: month +50
        assert!(!czech_rc("900101/1230"));
        assert!(romania_cnp("1800101221144"));
        assert!(romania_cnp("1850312400012"));
        assert!(!romania_cnp("1800101221145"));
        assert!(china_rid("11010519491231002X"));
        assert!(china_rid("110101199003071233"));
        assert!(!china_rid("110101199003071234"));
        assert!(us_ssn("123-45-6789"));
        assert!(!us_ssn("000-12-3456"));
        assert!(!us_ssn("666-12-3456"));
        assert!(!us_ssn("900-12-3456"));
        assert!(!us_ssn("123-00-6789"));
        assert!(!us_ssn("123-45-0000"));
        // IMEI / ICCID are Luhn-gated (label + checksum).
        assert!(luhn("490154203237518"));
        assert!(!luhn("356938035643800"));
        assert!(luhn("8910120000000000007"));
        assert!(turkey_tckn("10000000146"));
        assert!(turkey_tckn("19191919190"));
        assert!(!turkey_tckn("12345678901"));
        assert!(!turkey_tckn("10000000140"));
        assert!(israel_id("Israel ID: 039285754"));
        assert!(israel_id("teudat zehut 123456782"));
        assert!(!israel_id("Israel ID: 039285755"));
        // E.164: assigned CC, length, repeat/sequence, special-CC reject.
        assert!(e164("+15555550123"));
        assert!(e164("+447911123456"));
        assert!(e164("+393331234567"));
        assert!(e164("+39 333 1234567")); // spaced groups
        assert!(e164("+61 412 345 678")); // spaced, CC 61
        assert!(!e164("+9991234567")); // CC 999 not assigned
        assert!(!e164("+8005551234")); // freephone CC -> non-PII
        assert!(!e164("+1111111111")); // all-same
        assert!(!e164("+12345678")); // strictly sequential
        assert!(!e164("+1234567")); // too short
                                    // Per-country phones: strict NSN length, separator-tolerant.
        assert!(phone_us("+1 415 555 0123"));
        assert!(phone_us("(415) 555-0123"));
        assert!(!phone_us("+1 015 555 0123")); // area leading 0/1
        assert!(phone_uk("+44 2079460958"));
        assert!(!phone_uk("+44 97387459")); // 8-digit NSN, too short
        assert!(phone_it("+39 3331234567"));
        assert!(phone_fr("+33 1 23 45 67 89"));
        assert!(!phone_fr("+33 1 23 45 67")); // 7-digit NSN
        assert!(phone_de("+49 301234567"));
        assert!(phone_es("+34 612345678"));
        assert!(!phone_es("+34 12345678")); // leading 1, not 6-9
        assert!(phone_br("+55 11 91234-5678"));
        assert!(phone_in("+91 9123456789"));
        assert!(!phone_in("+91 5123456789")); // leading 5, not 6-9
                                              // Vehicle / maritime / mail checksums.
        assert!(vin_na("1HGCM82633A004352"));
        assert!(vin_na("1M8GDM9AXKP042788"));
        assert!(!vin_na("1HGCM82633A004353"));
        assert!(!vin_na("11111111111111111")); // repdigit rejected
        assert!(imo_number("IMO 9074729"));
        assert!(!imo_number("IMO 9074720"));
        assert!(iso6346("CSQU3054383"));
        assert!(!iso6346("CSQU3054384"));
        assert!(usps_s10("RB123456785US"));
        assert!(!usps_s10("RB123456784US"));
        // Geo coordinate range check (order-agnostic).
        assert!(geo_coord("geo:37.786971,-122.399677"));
        assert!(geo_coord("+37.78-122.39/")); // ISO 6709 lat,lon
        assert!(geo_coord("[-122.399677, 37.786971]")); // GeoJSON lon,lat
        assert!(!geo_coord("geo:199.9,-999.9")); // out of range
        assert!(!geo_coord("geo:48.85")); // single number
        assert!(orcid("0000-0002-1825-0097"));
        assert!(!orcid("0000-0002-1825-0098"));
        assert!(isin("US0378331005"));
        assert!(isin("GB0002634946"));
        assert!(!isin("US0378331006"));
    }

    #[test]
    fn mrz_td3_known_vector() {
        // ICAO 9303 Appendix B specimen (UTOPIA, Anna Maria Eriksson).
        let ok = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n\
                  L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        assert!(mrz_td3(ok));
        // Corrupt the document-number check digit -> reject.
        let bad = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n\
                   L898902C30UTO7408122F1204159ZE184226B<<<<<10";
        assert!(!mrz_td3(bad));
    }
}
