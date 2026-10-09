//! Offline reconstruction of the transaction envelope used by the local login flow.
//! The bundle layout is explicit because the logged-out and responsive-web releases differ.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use regex::Regex;
use sha2::{Digest, Sha256};

pub const EPOCH_SECONDS: u64 = 1_682_924_400;
const HASH_SALT: &str = "obfiowerehiring";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleLayout {
    LoggedOut,
    ResponsiveWeb,
}
impl BundleLayout {
    fn selector_class(self) -> &'static str {
        match self {
            Self::LoggedOut => "r-6syc0",
            Self::ResponsiveWeb => "r-16n140",
        }
    }
    fn row_and_time(self, key: &[u8]) -> (usize, u32) {
        let nib = |i: usize| u32::from(key[i] % 16);
        match self {
            Self::LoggedOut => (nib(4) as usize, nib(32) * nib(23) * nib(45)),
            Self::ResponsiveWeb => (nib(25) as usize, nib(39) * nib(39) * nib(31)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransactionContext {
    pub verification_key: Vec<u8>,
    pub animation_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTransaction {
    pub mask: u8,
    pub verification_key: Vec<u8>,
    pub relative_seconds: u32,
    pub digest: [u8; 16],
    pub extra: Vec<u8>,
    pub version: u8,
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    // Attribute names are bounded; input comes from the supplied HTML response.
    let re = Regex::new(r#"([^\s=<>/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap();
    re.captures_iter(tag).find_map(|c| {
        if c[1].eq_ignore_ascii_case(name) {
            Some(c.get(2).or_else(|| c.get(3)).unwrap().as_str().to_owned())
        } else {
            None
        }
    })
}

fn animation_svg_body(
    html: &str,
    layout: BundleLayout,
    selected_index: usize,
) -> Result<String, String> {
    let svg_re = Regex::new(r"(?is)<svg\b([^>]*)>(.*?)</svg\s*>").unwrap();
    let svgs: Vec<(String, String)> = svg_re
        .captures_iter(html)
        .map(|capture| (capture[1].to_owned(), capture[2].to_owned()))
        .collect();

    let class_matches: Vec<&str> = svgs
        .iter()
        .filter_map(|(attributes, body)| {
            attribute(attributes, "class")
                .filter(|classes| {
                    classes
                        .split_whitespace()
                        .any(|class| class == layout.selector_class())
                })
                .map(|_| body.as_str())
        })
        .collect();

    if class_matches.len() == 4 {
        return Ok(class_matches[selected_index].to_owned());
    }
    if !class_matches.is_empty() {
        return Err(format!(
            "expected exactly 4 animation SVGs with class {}; found {} (refusing ID fallback because a partial class match is ambiguous)",
            layout.selector_class(),
            class_matches.len()
        ));
    }

    // The minified CSS class is release-specific, while these four IDs are stable
    // bootstrap contract elements. Fall back only when the complete, unambiguous
    // numbered set exists; never pick an arbitrary SVG by document position.
    let mut numbered: [Option<String>; 4] = std::array::from_fn(|_| None);
    let mut malformed = Vec::new();
    for (attributes, body) in &svgs {
        let Some(id) = attribute(attributes, "id") else {
            continue;
        };
        let Some(suffix) = id.strip_prefix("loading-x-anim-") else {
            continue;
        };
        let Ok(index) = suffix.parse::<usize>() else {
            malformed.push(id);
            continue;
        };
        if index >= numbered.len() {
            malformed.push(id);
            continue;
        }
        if numbered[index].replace(body.clone()).is_some() {
            return Err(format!("duplicate animation SVG id loading-x-anim-{index}"));
        }
    }
    if !malformed.is_empty() {
        return Err(format!(
            "malformed animation SVG ids: {}",
            malformed.join(", ")
        ));
    }
    let missing: Vec<String> = numbered
        .iter()
        .enumerate()
        .filter(|(_, body)| body.is_none())
        .map(|(index, _)| format!("loading-x-anim-{index}"))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "missing animation SVGs: expected class {} or complete IDs loading-x-anim-0..3; missing {}",
            layout.selector_class(),
            missing.join(", ")
        ));
    }
    Ok(numbered[selected_index].take().unwrap())
}

impl TransactionContext {
    /// Extracts the meta key and the second SVG path in the same order as the JS selector.
    pub fn from_html(html: &str, layout: BundleLayout) -> Result<Self, String> {
        let metas = Regex::new(r"(?is)<meta\b[^>]*>").unwrap();
        let key_b64 = metas
            .find_iter(html)
            .find_map(|m| {
                let name = attribute(m.as_str(), "name")?;
                if name.starts_with("tw") {
                    attribute(m.as_str(), "content")
                } else {
                    None
                }
            })
            .ok_or("missing verification meta element")?;
        let key = STANDARD
            .decode(key_b64)
            .map_err(|e| format!("invalid verification key: {e}"))?;
        if key.len() < 46 {
            return Err("verification key is too short for bundle indices".into());
        }
        let paths_re = Regex::new(r"(?is)<path\b[^>]*>").unwrap();
        let selected_index = usize::from(key[5] % 4);
        let selected_body = animation_svg_body(html, layout, selected_index)?;
        let path = paths_re
            .find_iter(&selected_body)
            .nth(1)
            .and_then(|m| attribute(m.as_str(), "d"))
            .ok_or_else(|| {
                format!("animation SVG {selected_index} is missing its second path d attribute")
            })?;
        let (row, time) = layout.row_and_time(&key);
        let numbers = Regex::new(r"\d+").unwrap();
        let row_text = path
            .get(9..)
            .ok_or("animation path prefix too short")?
            .split('C')
            .nth(row)
            .ok_or("animation path has too few rows")?;
        let row_values: Result<Vec<u32>, _> = numbers
            .find_iter(row_text)
            .map(|n| n.as_str().parse::<u32>())
            .collect();
        let values = row_values.map_err(|e| e.to_string())?;
        if values.len() != 11 {
            return Err(format!(
                "expected 11 animation numbers; got {}",
                values.len()
            ));
        }
        if values.iter().any(|&x| x > 255) {
            return Err("animation number exceeds byte range".into());
        }
        Ok(Self {
            verification_key: key,
            animation_key: animation_key(&values, time),
        })
    }

    /// Caller supplies the clock and random mask, making tests deterministic.
    /// For the local jf host the caller uses path="jf", method="PATCH".
    pub fn generate_at(
        &self,
        path: &str,
        method: &str,
        unix_seconds: u64,
        mask: u8,
    ) -> Result<String, String> {
        let seconds = unix_seconds
            .checked_sub(EPOCH_SECONDS)
            .ok_or("clock predates transaction epoch")?;
        let seconds = u32::try_from(seconds).map_err(|_| "clock exceeds u32 transaction range")?;
        Ok(self.generate_relative(path, method, seconds, mask))
    }

    pub fn generate_relative(&self, path: &str, method: &str, seconds: u32, mask: u8) -> String {
        let digest = Sha256::digest(
            format!("{method}!{path}!{seconds}{HASH_SALT}{}", self.animation_key).as_bytes(),
        );
        let mut bytes = Vec::with_capacity(self.verification_key.len() + 22);
        bytes.push(mask);
        bytes.extend_from_slice(&self.verification_key);
        bytes.extend_from_slice(&seconds.to_le_bytes());
        bytes.extend_from_slice(&digest[..16]);
        // The captured implementation's optional WebRTC suffix is empty.
        bytes.push(3);
        for byte in &mut bytes[1..] {
            *byte ^= mask;
        }
        STANDARD_NO_PAD.encode(bytes)
    }
}

/// Decodes the captured 48-byte verification-key envelope without asserting authenticity.
pub fn decode_transaction(token: &str) -> Result<DecodedTransaction, String> {
    let mut bytes = STANDARD_NO_PAD
        .decode(token.trim_end_matches('='))
        .map_err(|e| e.to_string())?;
    if bytes.len() < 70 {
        return Err("transaction envelope is shorter than 70 bytes".into());
    }
    let mask = bytes[0];
    for byte in &mut bytes[1..] {
        *byte ^= mask;
    }
    Ok(DecodedTransaction {
        mask,
        verification_key: bytes[1..49].to_vec(),
        relative_seconds: u32::from_le_bytes(bytes[49..53].try_into().unwrap()),
        digest: bytes[53..69].try_into().unwrap(),
        extra: bytes[69..bytes.len() - 1].to_vec(),
        version: *bytes.last().unwrap(),
    })
}

fn cubic(t: f64, p: f64, q: f64) -> f64 {
    3.0 * (1.0 - t) * (1.0 - t) * t * p + 3.0 * (1.0 - t) * t * t * q + t * t * t
}
fn easing(x: f64, points: [f64; 4]) -> f64 {
    let (mut lo, mut hi) = (0.0, 1.0);
    for _ in 0..60 {
        let t = (lo + hi) / 2.0;
        if cubic(t, points[0], points[2]) < x {
            lo = t;
        } else {
            hi = t;
        }
    }
    cubic((lo + hi) / 2.0, points[1], points[3])
}

// ECMAScript toFixed(2) rounds the exact binary64 value to the nearest decimal,
// choosing the larger absolute integer on a tie. Multiplying f64 by 100 first
// can introduce an extra rounding, so perform this step using integer bits.
fn fixed_two(value: f64) -> f64 {
    if value == 0.0 {
        return 0.0;
    }
    let bits = value.abs().to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32 - 1023 - 52;
    let significand = u128::from((bits & ((1u64 << 52) - 1)) | (1u64 << 52)) * 100;
    let rounded = if exponent >= 0 {
        significand << exponent
    } else {
        let shift = (-exponent) as u32;
        if shift >= 128 {
            0
        } else {
            let whole = significand >> shift;
            let remainder = significand & ((1u128 << shift) - 1);
            whole + u128::from(remainder >= (1u128 << (shift - 1)))
        }
    };
    (rounded as f64 / 100.0).copysign(value)
}

fn hex_without_punctuation(value: f64) -> String {
    let value = value.abs();
    let integer = value.trunc() as u64;
    let mut result = format!("{integer:x}");
    let mut fraction = value - integer as f64;
    // Every finite binary64 fraction terminates in base 16. Inputs were rounded
    // to hundredths and have magnitude <= 255, so 16 digits are sufficient.
    for _ in 0..16 {
        if fraction == 0.0 {
            break;
        }
        fraction *= 16.0;
        let digit = fraction.floor();
        result.push(char::from_digit(digit as u32, 16).unwrap());
        fraction -= digit;
    }
    result
}

fn animation_key(values: &[u32], raw_time: u32) -> String {
    let scaled = |v: u32, low: f64, high: f64| f64::from(v) * (high - low) / 255.0 + low;
    let points = std::array::from_fn(|i| {
        fixed_two(scaled(
            values[7 + i],
            if i % 2 == 0 { 0.0 } else { -1.0 },
            1.0,
        ))
    });
    let time = ((f64::from(raw_time) / 10.0).round() * 10.0) / 4096.0;
    let progress = easing(time, points);
    let angle = scaled(values[6], 60.0, 360.0).floor() * progress * std::f64::consts::PI / 180.0;
    let mut components = Vec::with_capacity(9);
    for i in 0..3 {
        components.push(
            (f64::from(values[i]) + (f64::from(values[3 + i]) - f64::from(values[i])) * progress)
                .clamp(0.0, 255.0)
                .round(),
        );
    }
    for value in [
        angle.cos(),
        angle.sin(),
        -angle.sin(),
        angle.cos(),
        0.0,
        0.0,
    ] {
        // Chromium serializes computed matrix entries with six significant digits.
        let css_value = format!("{value:.5e}").parse::<f64>().unwrap();
        components.push(fixed_two(css_value));
    }
    components
        .into_iter()
        .map(hex_without_punctuation)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_envelope_round_trips() {
        let context = TransactionContext {
            verification_key: (0_u8..48).collect(),
            animation_key: "animation".to_owned(),
        };
        let token = context.generate_relative("jf", "PATCH", 12_345, 0x5a);
        let decoded = decode_transaction(&token).unwrap();

        assert_eq!(decoded.mask, 0x5a);
        assert_eq!(decoded.verification_key, context.verification_key);
        assert_eq!(decoded.relative_seconds, 12_345);
        assert!(decoded.extra.is_empty());
        assert_eq!(decoded.version, 3);
    }

    #[test]
    fn missing_bootstrap_key_is_rejected() {
        let error =
            TransactionContext::from_html("<html></html>", BundleLayout::LoggedOut).unwrap_err();
        assert_eq!(error, "missing verification meta element");
    }

    #[test]
    fn decimal_rounding_and_hex_match_ecmascript() {
        assert_eq!(fixed_two(0.125), 0.13);
        assert_eq!(fixed_two(2.675), 2.67);
        assert_eq!(hex_without_punctuation(0.01), "0028f5c28f5c28f6");
        assert_eq!(hex_without_punctuation(-0.01), "0028f5c28f5c28f6");
    }
}
