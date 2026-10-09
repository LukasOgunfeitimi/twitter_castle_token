//! Offline Castle collector construction from typed semantic inputs.
//!
//! This module has no browser, JavaScript, HTTP, or socket code. It embeds no
//! serialized or compressed collector document. One Chrome 154 / Windows
//! semantic baseline is combined with recovered numeric, counter, timing, blob,
//! and dependency writers to rebuild all 765 fields for every invocation.

use self::wire::{Value, assemble_output, base64_encode, encode_document, encode_header, encrypt};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::DeflateEncoder};
use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

mod profile_data;
mod wire;

#[cfg(test)]
mod wire_tests;

const FIELD_COUNT: usize = 765;
const TIMING_FIRST: usize = 683;
const NUMERIC_PROBE_COUNT: usize = 287;
const CR_PROBE_COUNT: usize = 29;
const BLOB_PROBE_COUNT: usize = 5;
const DEPENDENT_PROBE_COUNT: usize = 2;
const PAGE_CACHED_TIMING_SLOTS: [usize; 17] = [
    746, 747, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764,
];
const TOKEN_PREFIX: &str = "cNz8rPYH|";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPhase {
    Begin,
    LoginPassword,
}

impl FlowPhase {
    pub const ALL: [Self; 2] = [Self::Begin, Self::LoginPassword];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Begin => "begin_login",
            Self::LoginPassword => "login_enter_password",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NumericProbe {
    pub slot: usize,
    pub producer: &'static str,
    pub raw_bits: u64,
    pub peer_raw_bits: u64,
    pub k1: u32,
    pub k2: u32,
    pub k3: u32,
    /// None is used only for source-proven scalar writers whose raw value was
    /// equal in both captures. Some contains the exact binary64 fallback masks.
    pub f64_masks: Option<(u32, u32)>,
}

impl NumericProbe {
    pub fn raw(&self) -> f64 {
        f64::from_bits(self.raw_bits)
    }

    pub fn peer_raw(&self) -> f64 {
        f64::from_bits(self.peer_raw_bits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrProbe {
    pub slot: usize,
    pub producer: &'static str,
    pub raw: u32,
    pub peer_raw: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingProbe {
    pub slot: usize,
    pub f32_bits: u32,
    pub peer_f32_bits: u32,
}

impl TimingProbe {
    pub fn milliseconds(self) -> f32 {
        f32::from_bits(self.f32_bits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobInput {
    Slot98([Vec<u8>; 3]),
    LrUtf16(Vec<u16>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobProbe {
    pub slot: usize,
    pub producer: &'static str,
    pub input: BlobInput,
    pub peer_input: BlobInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentProbe {
    pub slot: usize,
    pub producer: &'static str,
    pub dependency: &'static str,
    pub source_slot: usize,
    pub shift: u32,
    pub mask: u32,
    pub addend: u32,
}

#[derive(Debug, Clone)]
pub struct Chrome154WindowsProfile {
    phase: FlowPhase,
    baseline_values: Vec<Value>,
    numeric_probes: Vec<NumericProbe>,
    cr_probes: Vec<CrProbe>,
    timings: [TimingProbe; 82],
    blob_probes: Vec<BlobProbe>,
    dependent_probes: Vec<DependentProbe>,
}

#[derive(Debug, Clone)]
pub struct VirtualInvocation {
    pub page_seed: u64,
    pub sequence: u64,
    pub global_speed: f32,
    profile: Chrome154WindowsProfile,
}

#[derive(Debug, Clone)]
pub struct VirtualPage {
    seed: u64,
    sequence: u64,
    page_timing_bits: Option<[u32; PAGE_CACHED_TIMING_SLOTS.len()]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedToken {
    pub phase: FlowPhase,
    pub token: String,
    pub seed: String,
    pub serialized_len: usize,
    pub compressed_len: usize,
    pub cipher_len: usize,
    pub envelope_len: usize,
}

impl Chrome154WindowsProfile {
    /// Reconstruct the semantic inputs observed at one successful-flow phase.
    /// This is the exact regression baseline used by the synthetic page model.
    pub fn captured(phase: FlowPhase) -> Result<Self, String> {
        let profile = Self {
            phase,
            baseline_values: profile_data::stable_chrome154_windows(),
            numeric_probes: profile_data::numeric_probes(phase),
            cr_probes: profile_data::cr_probes(phase),
            timings: profile_data::timings(phase),
            blob_probes: profile_data::blob_probes(phase),
            dependent_probes: profile_data::dependent_probes(),
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn phase(&self) -> FlowPhase {
        self.phase
    }

    pub fn numeric_probes(&self) -> &[NumericProbe] {
        &self.numeric_probes
    }

    pub fn cr_probes(&self) -> &[CrProbe] {
        &self.cr_probes
    }

    pub fn timings(&self) -> &[TimingProbe; 82] {
        &self.timings
    }

    pub fn blob_probes(&self) -> &[BlobProbe] {
        &self.blob_probes
    }

    pub fn dependent_probes(&self) -> &[DependentProbe] {
        &self.dependent_probes
    }

    pub fn set_numeric_raw(&mut self, slot: usize, raw: f64) -> Result<(), String> {
        if !raw.is_finite() {
            return Err("numeric probe input must be finite".to_owned());
        }
        let probe = self
            .numeric_probes
            .iter_mut()
            .find(|probe| probe.slot == slot)
            .ok_or_else(|| format!("slot {slot} has no recovered numeric producer"))?;
        probe.raw_bits = raw.to_bits();
        Ok(())
    }

    pub fn set_cr_raw(&mut self, slot: usize, raw: u32) -> Result<(), String> {
        let probe = self
            .cr_probes
            .iter_mut()
            .find(|probe| probe.slot == slot)
            .ok_or_else(|| format!("slot {slot} has no recovered cr producer"))?;
        probe.raw = raw;
        Ok(())
    }

    pub fn set_timing_ms(&mut self, slot: usize, milliseconds: f32) -> Result<(), String> {
        if !milliseconds.is_finite() || milliseconds < 0.0 {
            return Err("timing must be finite and non-negative".to_owned());
        }
        let offset = slot
            .checked_sub(TIMING_FIRST)
            .filter(|offset| *offset < 82)
            .ok_or_else(|| format!("timing slot {slot} is outside 683..=764"))?;
        self.timings[offset].f32_bits = milliseconds.to_bits();
        Ok(())
    }

    pub fn set_timing_block(&mut self, milliseconds: [f32; 82]) -> Result<(), String> {
        if milliseconds
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err("all timings must be finite and non-negative".to_owned());
        }
        for (timing, value) in self.timings.iter_mut().zip(milliseconds) {
            timing.f32_bits = value.to_bits();
        }
        Ok(())
    }

    pub fn set_blob_input(&mut self, slot: usize, input: BlobInput) -> Result<(), String> {
        let probe = self
            .blob_probes
            .iter_mut()
            .find(|probe| probe.slot == slot)
            .ok_or_else(|| format!("slot {slot} has no recovered blob producer"))?;
        probe.input = input;
        Ok(())
    }

    pub fn build_values(&self) -> Result<Vec<Value>, String> {
        self.validate()?;
        let mut values = self.baseline_values.clone();

        for probe in &self.numeric_probes {
            values[probe.slot] = encode_numeric_probe(probe)?;
        }
        for probe in &self.cr_probes {
            values[probe.slot] = Value::I32(cr_pack(probe.raw) as i32);
        }
        for probe in &self.blob_probes {
            values[probe.slot] = encode_blob_probe(probe)?;
        }
        for probe in &self.dependent_probes {
            let value = encode_dependent_probe(probe, &values)?;
            values[probe.slot] = value;
        }
        for timing in self.timings {
            values[timing.slot] = Value::Base64Bytes(kd_encode_f32(timing.milliseconds()).to_vec());
        }

        Ok(values)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        Ok(encode_document(&self.build_values()?))
    }

    pub fn generate_at(&self, unix_ms: u64) -> Result<GeneratedToken, String> {
        let serialized = self.serialize()?;
        let compressed = raw_deflate(&serialized)?;
        assemble_token(self.phase, unix_ms, serialized.len(), &compressed)
    }

    fn validate(&self) -> Result<(), String> {
        if self.baseline_values.len() != FIELD_COUNT {
            return Err(format!(
                "profile has {} baseline positions",
                self.baseline_values.len()
            ));
        }
        if self.numeric_probes.len() != NUMERIC_PROBE_COUNT {
            return Err(format!(
                "profile has {} numeric producers",
                self.numeric_probes.len()
            ));
        }
        if self.cr_probes.len() != CR_PROBE_COUNT {
            return Err(format!("profile has {} cr producers", self.cr_probes.len()));
        }
        if self.blob_probes.len() != BLOB_PROBE_COUNT {
            return Err(format!(
                "profile has {} blob producers",
                self.blob_probes.len()
            ));
        }
        if self.dependent_probes.len() != DEPENDENT_PROBE_COUNT {
            return Err(format!(
                "profile has {} dependent producers",
                self.dependent_probes.len()
            ));
        }

        let mut assigned = [false; FIELD_COUNT];
        for (slot, value) in self.baseline_values.iter().enumerate() {
            assigned[slot] = !matches!(value, Value::Null);
        }

        for probe in &self.numeric_probes {
            if probe.slot >= FIELD_COUNT
                || assigned[probe.slot]
                || probe.k2 & 1 == 0
                || !probe.raw().is_finite()
                || !probe.peer_raw().is_finite()
            {
                return Err(format!("invalid or duplicate numeric slot {}", probe.slot));
            }
            assigned[probe.slot] = true;
        }
        for probe in &self.cr_probes {
            if probe.slot >= FIELD_COUNT || assigned[probe.slot] {
                return Err(format!("invalid or duplicate cr slot {}", probe.slot));
            }
            assigned[probe.slot] = true;
        }
        for probe in &self.blob_probes {
            if probe.slot >= FIELD_COUNT || assigned[probe.slot] {
                return Err(format!("invalid or duplicate blob slot {}", probe.slot));
            }
            assigned[probe.slot] = true;
        }
        for probe in &self.dependent_probes {
            if probe.slot >= FIELD_COUNT
                || probe.source_slot >= FIELD_COUNT
                || assigned[probe.slot]
                || !assigned[probe.source_slot]
                || probe.shift >= 32
            {
                return Err(format!(
                    "invalid or duplicate dependent slot {}",
                    probe.slot
                ));
            }
            assigned[probe.slot] = true;
        }
        for (offset, timing) in self.timings.iter().enumerate() {
            let expected = TIMING_FIRST + offset;
            let milliseconds = timing.milliseconds();
            if timing.slot != expected
                || assigned[timing.slot]
                || !milliseconds.is_finite()
                || milliseconds < 0.0
            {
                return Err(format!("invalid timing slot {}", timing.slot));
            }
            assigned[timing.slot] = true;
        }
        if assigned.iter().any(|assigned| !assigned) {
            return Err("semantic model does not cover all 765 slots".to_owned());
        }
        Ok(())
    }
}

impl VirtualPage {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            sequence: 0,
            page_timing_bits: None,
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn next_invocation(&mut self, phase: FlowPhase) -> Result<VirtualInvocation, String> {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);

        let mut rng = SplitMix64::new(self.seed ^ sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let global_speed = 0.97 + rng.unit_f32() * 0.06;
        let phase_progress = ((sequence % 17) as f64 + f64::from(rng.unit_f32())) / 18.0;
        let probe_latents = [
            f64::from(rng.unit_f32()),
            f64::from(rng.unit_f32()),
            f64::from(rng.unit_f32()),
            f64::from(rng.unit_f32()),
            f64::from(rng.unit_f32()),
        ];
        let timing_latents = [rng.unit_f32(), rng.unit_f32(), rng.unit_f32()];
        let mut profile = Chrome154WindowsProfile::captured(phase)?;

        if let Some(cached) = self.page_timing_bits {
            for (slot, bits) in PAGE_CACHED_TIMING_SLOTS.into_iter().zip(cached) {
                profile.timings[slot - TIMING_FIRST].f32_bits = bits;
            }
        } else {
            self.page_timing_bits = Some(
                PAGE_CACHED_TIMING_SLOTS.map(|slot| profile.timings[slot - TIMING_FIRST].f32_bits),
            );
        }

        for probe in &mut profile.numeric_probes {
            let base = probe.raw();
            let peer = probe.peer_raw();
            if base == 0.0 || base.to_bits() == peer.to_bits() {
                continue;
            }
            let latent = probe_latents[numeric_probe_bucket(probe.producer)];
            let drift = (latent - 0.5) * 0.10 + (phase_progress - 0.5) * 0.04;
            let mut candidate = base + (peer - base) * drift;
            if is_exact_scaled_i32(base) && is_exact_scaled_i32(peer) {
                candidate = (candidate * 1000.0).round() / 1000.0;
            }
            if candidate.is_finite() {
                probe.raw_bits = candidate.to_bits();
            }
        }

        for probe in &mut profile.cr_probes {
            if probe.raw == 0 || probe.raw == probe.peer_raw {
                continue;
            }
            let latent = probe_latents[numeric_probe_bucket(probe.producer)];
            let drift = (latent - 0.5) * 0.10 + (phase_progress - 0.5) * 0.04;
            let candidate =
                f64::from(probe.raw) + (f64::from(probe.peer_raw) - f64::from(probe.raw)) * drift;
            probe.raw = candidate.round().clamp(0.0, f64::from(u32::MAX)) as u32;
        }

        for timing in &mut profile.timings {
            if PAGE_CACHED_TIMING_SLOTS.contains(&timing.slot) {
                continue;
            }
            let base = timing.milliseconds();
            if base == 0.0 {
                continue;
            }
            let peer = f32::from_bits(timing.peer_f32_bits);
            let blended = if peer > 0.0 && peer.to_bits() != base.to_bits() {
                let timing_bucket = match timing.slot {
                    683..=719 => 0,
                    720..=745 => 1,
                    748..=749 => 2,
                    _ => unreachable!("page/config timing was filtered above"),
                };
                let factor = (phase_progress as f32 * 0.75 + timing_latents[timing_bucket] * 0.25)
                    .clamp(0.0, 1.0);
                base + (peer - base) * factor
            } else {
                base
            };
            timing.f32_bits = (blended * global_speed).max(0.0).to_bits();
        }

        Ok(VirtualInvocation {
            page_seed: self.seed,
            sequence,
            global_speed,
            profile,
        })
    }

    pub fn generate_at(
        &mut self,
        phase: FlowPhase,
        unix_ms: u64,
    ) -> Result<GeneratedToken, String> {
        self.next_invocation(phase)?.generate_at(unix_ms)
    }

    pub fn generate_now(&mut self, phase: FlowPhase) -> Result<GeneratedToken, String> {
        let unix_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
            .as_millis()
            .try_into()
            .map_err(|_| "Unix time does not fit in u64".to_owned())?;
        self.generate_at(phase, unix_ms)
    }
}

impl VirtualInvocation {
    pub fn profile(&self) -> &Chrome154WindowsProfile {
        &self.profile
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        self.profile.serialize()
    }

    pub fn generate_at(&self, unix_ms: u64) -> Result<GeneratedToken, String> {
        self.profile.generate_at(unix_ms)
    }
}

fn numeric_probe_bucket(producer: &str) -> usize {
    let producer = producer.to_ascii_lowercase();
    if producer.contains("canvas")
        || producer.contains("webgl")
        || producer.contains("graphic")
        || producer.contains("render")
    {
        0
    } else if producer.contains("css")
        || producer.contains("layout")
        || producer.contains("screen")
        || producer.contains("window")
    {
        1
    } else if producer.contains("storage")
        || producer.contains("cache")
        || producer.contains("database")
    {
        2
    } else if producer.contains("time")
        || producer.contains("date")
        || producer.contains("performance")
    {
        3
    } else {
        4
    }
}

fn is_exact_scaled_i32(raw: f64) -> bool {
    let scaled = raw * 1000.0;
    let signed = scaled as i32;
    scaled.is_finite() && scaled == f64::from(signed) && f64::from(signed) / 1000.0 == raw
}

fn word_value(word: u32) -> Value {
    if word <= i32::MAX as u32 {
        Value::I32(word as i32)
    } else {
        Value::U32(word)
    }
}

/// Devirtualized Castle sr hash. JavaScript's string length and charCodeAt
/// operate on UTF-16 code units, so the Rust port does the same.
pub fn sr_hash(input: &str) -> u32 {
    let code_units: Vec<u16> = input.encode_utf16().collect();
    let mut accumulator = 0x198f_b9ac ^ code_units.len() as u32;
    accumulator ^= accumulator >> 11;
    accumulator ^= accumulator >> 15;
    accumulator = accumulator.rotate_left(10);

    let mut rolling = 0u32;
    for (index, &unit) in code_units.iter().enumerate() {
        let code_unit = u32::from(unit);
        accumulator ^= 0x7f14_1a42;
        accumulator = (accumulator ^ code_unit).wrapping_mul(0xbad9_2b63);
        accumulator = accumulator.wrapping_add(code_unit.wrapping_mul(0xac4a_09a1));
        accumulator ^= accumulator >> 9;
        accumulator ^= code_unit;
        accumulator ^= 0x37ee_3c7a;
        accumulator ^= (index as u32).wrapping_mul(0x52f3_d537);
        accumulator = (accumulator ^ code_unit).wrapping_mul(0xc850_af07);
        accumulator ^= code_unit.rotate_left(29);
        accumulator = accumulator.wrapping_add(code_unit.wrapping_mul(0xeed4_d7fd));
        accumulator = accumulator.rotate_left(19);

        rolling = rolling.wrapping_add(code_unit.wrapping_mul(0x9e37_79b1));
        if index & 3 == 3 {
            accumulator ^= accumulator >> 11;
            accumulator ^= rolling.rotate_left(24);
            accumulator ^= (accumulator & 0xffff).rotate_left(11);
        }
    }

    accumulator ^= rolling;
    accumulator = (accumulator ^ rolling)
        .wrapping_mul(0xb3cb_8661)
        .wrapping_add(0x94c8_6c4c);
    accumulator ^= rolling;
    accumulator ^= (rolling & 0xffff).rotate_left(2);
    accumulator ^= accumulator >> 16;
    accumulator = accumulator.wrapping_mul(0x85eb_ca6b);
    accumulator ^= accumulator >> 13;
    accumulator = accumulator.wrapping_mul(0xc2b2_ae35);
    accumulator ^ (accumulator >> 16)
}

fn json_stringify_integer(value: &Value) -> Result<String, String> {
    match value {
        Value::U32(value) => Ok(value.to_string()),
        Value::I32(value) => Ok(value.to_string()),
        other => Err(format!(
            "dependent sr source must be an integer, got {other:?}"
        )),
    }
}

pub fn encode_dependent_probe(probe: &DependentProbe, values: &[Value]) -> Result<Value, String> {
    if probe.shift >= 32 {
        return Err(format!(
            "dependent slot {} uses invalid shift {}",
            probe.slot, probe.shift
        ));
    }
    let source = values.get(probe.source_slot).ok_or_else(|| {
        format!(
            "dependent slot {} references missing slot {}",
            probe.slot, probe.source_slot
        )
    })?;
    let json = json_stringify_integer(source)?;
    let extracted = (sr_hash(&json) >> probe.shift) & probe.mask;
    Ok(word_value(extracted.wrapping_add(probe.addend)))
}

pub fn pack_fixed_milli(scaled_milli: i32, k1: u32, k2: u32, k3: u32) -> u32 {
    ((scaled_milli as u32) ^ k1)
        .wrapping_mul(k2)
        .wrapping_add(k3)
}

pub fn encode_numeric_probe(probe: &NumericProbe) -> Result<Value, String> {
    let raw = probe.raw();
    let scaled = raw * 1000.0;
    let signed = scaled as i32;
    if is_exact_scaled_i32(raw) {
        return Ok(word_value(pack_fixed_milli(
            signed, probe.k1, probe.k2, probe.k3,
        )));
    }

    let (high_mask, low_mask) = probe.f64_masks.ok_or_else(|| {
        format!(
            "slot {} needs the binary64 fallback but its source only proved the scalar writer",
            probe.slot
        )
    })?;
    let bits = raw.to_bits();
    let high = ((bits >> 32) as u32) ^ high_mask;
    let low = (bits as u32) ^ low_mask;
    Ok(Value::Array(vec![word_value(high), word_value(low)]))
}

const fn swap_two_bit_groups(value: u32) -> u32 {
    ((value >> 2) & 0x3333_3333) | ((value & 0x3333_3333) << 2)
}

pub const fn cr_pack(raw: u32) -> u32 {
    swap_two_bit_groups(raw ^ 421).wrapping_sub(1024)
}

pub const fn cr_unpack(wire: u32) -> u32 {
    swap_two_bit_groups(wire.wrapping_add(1024)) ^ 421
}

pub fn kd_encode_f32(value: f32) -> [u8; 4] {
    value.to_be_bytes().map(|byte| {
        let mixed = byte.wrapping_mul(53) ^ 248;
        mixed.rotate_left(5) ^ 220
    })
}

pub fn kd_decode_f32(encoded: [u8; 4]) -> f32 {
    let raw = encoded.map(|byte| ((byte ^ 220).rotate_right(5) ^ 248).wrapping_mul(29));
    f32::from_be_bytes(raw)
}

/// Exact bytes emitted by Castle's lr transform before its Base64 text layer.
pub fn lr_bytes_code_units(input: &[u16], initial_word: u32) -> Vec<u8> {
    let mut state = initial_word;
    let mut output = Vec::with_capacity(input.len() * 2);
    for &unit in input {
        let mixed = (((u32::from(unit) << 1) | (state >> 15)) & 0xffff) as u16;
        let word = mixed.wrapping_add(0xc481).rotate_left(2);
        state = u32::from(word);
        output.push((word >> 8) as u8);
        output.push(word as u8);
    }
    output
}

fn push_varuint15(mut value: usize, output: &mut Vec<u16>) {
    while value >= 0x8000 {
        output.push(((value & 0x7fff) as u16) | 0x8000);
        value >>= 15;
    }
    output.push(value as u16);
}

pub fn slot98_blob(parts: &[Vec<u8>; 3]) -> Result<Vec<u8>, String> {
    let mut units = vec![3u16];
    for part in parts {
        push_varuint15(part.len(), &mut units);
    }
    for part in parts {
        units.extend(part.iter().map(|byte| u16::from(*byte)));
    }
    units
        .into_iter()
        .map(|unit| {
            u8::try_from(unit)
                .map_err(|_| "slot 98 requires a non-Latin1 framing code unit".to_owned())
        })
        .collect()
}

pub fn encode_blob_probe(probe: &BlobProbe) -> Result<Value, String> {
    match &probe.input {
        BlobInput::Slot98(parts) => Ok(Value::Latin1(slot98_blob(parts)?)),
        BlobInput::LrUtf16(units) => Ok(Value::Base64Bytes(lr_bytes_code_units(units, 0))),
    }
}

pub fn raw_deflate(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
    encoder
        .write_all(input)
        .map_err(|error| format!("raw DEFLATE write failed: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("raw DEFLATE finish failed: {error}"))
}

fn assemble_token(
    phase: FlowPhase,
    unix_ms: u64,
    serialized_len: usize,
    compressed: &[u8],
) -> Result<GeneratedToken, String> {
    let seed = unix_ms.to_string();
    let cipher = encrypt(compressed, &seed);
    let header = encode_header(&seed);
    let envelope = assemble_output(header.as_bytes(), &cipher)?;
    Ok(GeneratedToken {
        phase,
        token: format!("{TOKEN_PREFIX}{}", base64_encode(&envelope)),
        seed,
        serialized_len,
        compressed_len: compressed.len(),
        cipher_len: cipher.len(),
        envelope_len: envelope.len(),
    })
}

pub fn inspect_seed_header(token: &str) -> Result<Vec<u8>, String> {
    let encoded = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| "missing Castle token prefix".to_owned())?;
    let binary = STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid token Base64: {error}"))?;
    if binary.len() < 2 {
        return Err("truncated envelope".to_owned());
    }
    let len = usize::from(u16::from_le_bytes([binary[0], binary[1]]));
    binary
        .get(2..2 + len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "truncated seed header".to_owned())
}

#[derive(Debug, Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn unit_f32(&mut self) -> f32 {
        (self.next_u64() as f64 / u64::MAX as f64) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    #[test]
    fn model_covers_all_dynamic_slots_with_named_producers() {
        let begin = Chrome154WindowsProfile::captured(FlowPhase::Begin).unwrap();
        assert_eq!(begin.numeric_probes().len(), NUMERIC_PROBE_COUNT);
        assert_eq!(begin.cr_probes().len(), CR_PROBE_COUNT);
        assert_eq!(begin.timings().len(), 82);
        assert_eq!(begin.blob_probes().len(), BLOB_PROBE_COUNT);
        assert_eq!(begin.dependent_probes().len(), DEPENDENT_PROBE_COUNT);
        assert_eq!(
            NUMERIC_PROBE_COUNT + CR_PROBE_COUNT + 82 + BLOB_PROBE_COUNT + DEPENDENT_PROBE_COUNT,
            405
        );
    }

    #[test]
    fn sr_hash_matches_devirtualized_javascript_vectors() {
        let vectors = [
            ("3000137627", 1_208_823_564),
            ("2672163329", 952_943_726),
            ("2198929123", 2_042_444_617),
            ("4095990931", 2_468_220_525),
        ];
        for (input, expected) in vectors {
            assert_eq!(sr_hash(input), expected, "{input}");
        }
    }

    #[test]
    fn dependent_slots_track_their_current_numeric_sources() {
        let mut profile = Chrome154WindowsProfile::captured(FlowPhase::Begin).unwrap();
        let before = profile.build_values().unwrap();

        profile.set_numeric_raw(326, 1.234).unwrap();
        profile.set_numeric_raw(501, 5.678).unwrap();
        let after = profile.build_values().unwrap();

        for probe in profile.dependent_probes() {
            assert_ne!(before[probe.source_slot], after[probe.source_slot]);
            assert_ne!(before[probe.slot], after[probe.slot]);
            assert_eq!(
                after[probe.slot],
                encode_dependent_probe(probe, &after).unwrap()
            );
        }
    }

    #[test]
    fn numeric_encoder_exercises_scalar_and_f64_fallbacks() {
        let begin = Chrome154WindowsProfile::captured(FlowPhase::Begin).unwrap();
        let scalar = begin
            .numeric_probes()
            .iter()
            .find(|probe| probe.slot == 249)
            .unwrap();
        let pair = begin
            .numeric_probes()
            .iter()
            .find(|probe| probe.slot == 16)
            .unwrap();
        assert!(matches!(
            encode_numeric_probe(scalar).unwrap(),
            Value::U32(_) | Value::I32(_)
        ));
        assert!(matches!(
            encode_numeric_probe(pair).unwrap(),
            Value::Array(_)
        ));
    }

    #[test]
    fn virtual_invocations_differ_in_the_inner_document() {
        let mut page = VirtualPage::new(0x1234_5678_9abc_def0);
        let first = page.next_invocation(FlowPhase::Begin).unwrap();
        let second = page.next_invocation(FlowPhase::Begin).unwrap();
        assert_ne!(first.sequence, second.sequence);
        assert_ne!(first.serialize().unwrap(), second.serialize().unwrap());
    }

    #[test]
    fn virtual_generation_is_deterministic_for_page_seed_and_sequence() {
        let mut left = VirtualPage::new(77);
        let mut right = VirtualPage::new(77);
        for phase in FlowPhase::ALL {
            assert_eq!(
                left.next_invocation(phase).unwrap().serialize().unwrap(),
                right.next_invocation(phase).unwrap().serialize().unwrap()
            );
        }
    }

    #[test]
    fn virtual_page_preserves_cached_page_timings_and_request_zero_paths() {
        let mut page = VirtualPage::new(99);
        let begin = page.next_invocation(FlowPhase::Begin).unwrap();
        let password = page.next_invocation(FlowPhase::LoginPassword).unwrap();

        for slot in PAGE_CACHED_TIMING_SLOTS {
            assert_eq!(
                begin.profile().timings()[slot - TIMING_FIRST].f32_bits,
                password.profile().timings()[slot - TIMING_FIRST].f32_bits,
                "page/config timing slot {slot} changed within one virtual page"
            );
        }

        for (invocation, phase) in [
            (&begin, FlowPhase::Begin),
            (&password, FlowPhase::LoginPassword),
        ] {
            let captured = profile_data::timings(phase);
            for (actual, original) in invocation.profile().timings().iter().zip(captured) {
                if !PAGE_CACHED_TIMING_SLOTS.contains(&actual.slot)
                    && original.milliseconds() == 0.0
                {
                    assert_eq!(actual.milliseconds(), 0.0);
                }
            }
        }
    }

    #[test]
    fn recovered_reversible_encoders_round_trip() {
        for phase in FlowPhase::ALL {
            let profile = Chrome154WindowsProfile::captured(phase).unwrap();
            for probe in profile.cr_probes() {
                assert_eq!(cr_unpack(cr_pack(probe.raw)), probe.raw);
            }
            for timing in profile.timings() {
                let encoded = kd_encode_f32(timing.milliseconds());
                assert_eq!(kd_decode_f32(encoded).to_bits(), timing.f32_bits);
            }
        }
    }

    #[test]
    fn raw_deflate_round_trips_rebuilt_document() {
        let profile = Chrome154WindowsProfile::captured(FlowPhase::Begin).unwrap();
        let serialized = profile.serialize().unwrap();
        let compressed = raw_deflate(&serialized).unwrap();
        let mut decoder = DeflateDecoder::new(compressed.as_slice());
        let mut inflated = Vec::new();
        decoder.read_to_end(&mut inflated).unwrap();
        assert_eq!(inflated, serialized);
    }

    #[test]
    fn fresh_outer_seed_wraps_fresh_inner_document() {
        let mut page = VirtualPage::new(42);
        let first = page
            .generate_at(FlowPhase::Begin, 1_791_574_820_451)
            .unwrap();
        let second = page
            .generate_at(FlowPhase::Begin, 1_791_574_820_452)
            .unwrap();
        assert_ne!(first.token, second.token);
        assert_eq!(
            inspect_seed_header(&first.token).unwrap(),
            encode_header(&first.seed).as_bytes()
        );
    }
}
