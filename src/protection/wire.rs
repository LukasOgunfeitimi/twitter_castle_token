//! Byte-compatible reconstruction of the Castle serializer and custom cipher.
//!
//! This module is deliberately self-contained: it has no browser or network code.

const FNV_OFFSET: u32 = 0x751d_ac79;
const FNV_PRIME: u32 = 0x0100_0193;
const ZERO_HASH_FALLBACK: u32 = 0x9e37_79b9;

const FIRST_INIT_XOR: u32 = 0xba3e_7b58;
const AUX_INIT_XOR: u32 = 0xf481_53f1;
const SECOND_INIT_XOR: u32 = 0x1867_f18b;
const GLOBAL_INIT_XOR: u32 = 0x7144_1d33;
const STREAM_INIT_XOR: u32 = 0x973d_8749;

const GLOBAL_INDEX_ADD: u32 = 0x6bd6_e647;
const FIRST_SECOND_INDEX_ADD: u32 = 0x1db4_88d0;
const FIRST_SECOND_XOR: u32 = 0xd8d9_86e1;
const STREAM_INDEX_ADD: u32 = 0x7f03_9dda;
const STREAM_ADD_1: u32 = 0x973d_8749;
const STREAM_ADD_2: u32 = 0x93cf_09bd;

const WORD0_PRE_XOR: u32 = 0x6abb_c1f9;
const WORD0_MIX: u32 = 0x289b_52eb;
const WORD0_ROT_XOR: u32 = 0x2736_4664;
const WORD1_PRE_XOR: u32 = 0x01e2_f916;
const WORD1_MIX: u32 = 0x7670_7cd5;
const WORD1_ROT_XOR: u32 = 0xa055_eaba;
const WORD23_PRE_XOR: u32 = 0xfcd0_8408;
const WORD23_MIX: u32 = 0x1db4_88d1;
const WORD23_ROT_XOR: u32 = 0xd8d9_86e1;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Utf16(Vec<u16>),
    Base64Bytes(Vec<u8>),
    U32(u32),
    F64Bits(u64),
    Bool(bool),
    Array(Vec<Value>),
    JsonUtf16(Vec<u16>),
    Latin1(Vec<u8>),
    I32(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherDebug {
    pub seed_hash: u32,
    pub bounds: [usize; 4],
    pub initial: [u32; 5],
    pub after_loop: [u32; 5],
    pub tag_words: [u32; 4],
    pub tag_masks: [u32; 4],
}

fn put_varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
fn get_varint(input: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut value = 0u32;
    let mut shift = 0u32;
    loop {
        let byte = *input
            .get(*cursor)
            .ok_or_else(|| "truncated varint".to_string())?;
        *cursor += 1;
        if shift >= 32 && byte & 0x7f != 0 {
            return Err("varint overflow".to_string());
        }
        value |= ((byte & 0x7f) as u32)
            .checked_shl(shift)
            .ok_or_else(|| "varint overflow".to_string())?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn put_utf16(units: &[u16], out: &mut Vec<u8>) {
    put_varint(units.len() as u32, out);
    for &unit in units {
        out.push(unit as u8);
        out.push((unit >> 8) as u8);
    }
}

#[cfg(test)]
fn get_utf16(input: &[u8], cursor: &mut usize) -> Result<Vec<u16>, String> {
    let count = get_varint(input, cursor)? as usize;
    let bytes = count
        .checked_mul(2)
        .ok_or_else(|| "UTF-16 length overflow".to_string())?;
    let end = cursor
        .checked_add(bytes)
        .ok_or_else(|| "UTF-16 length overflow".to_string())?;
    let src = input
        .get(*cursor..end)
        .ok_or_else(|| "truncated UTF-16 string".to_string())?;
    *cursor = end;
    Ok(src
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn encode_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.push(0),
        Value::Utf16(units) => {
            out.push(1);
            put_utf16(units, out);
        }
        Value::Base64Bytes(bytes) => {
            out.push(2);
            put_varint(bytes.len() as u32, out);
            out.extend_from_slice(bytes);
        }
        Value::U32(value) => {
            out.push(3);
            out.extend_from_slice(&value.to_le_bytes());
        }
        Value::F64Bits(bits) => {
            out.push(4);
            out.extend_from_slice(&bits.to_be_bytes());
        }
        Value::Bool(value) => out.push(if *value { 6 } else { 5 }),
        Value::Array(values) => {
            out.push(7);
            put_varint(values.len() as u32, out);
            for value in values {
                encode_value(value, out);
            }
        }
        Value::JsonUtf16(units) => {
            out.push(8);
            put_utf16(units, out);
        }
        Value::Latin1(bytes) => {
            out.push(9);
            put_varint(bytes.len() as u32, out);
            out.extend_from_slice(bytes);
        }
        Value::I32(value) => {
            out.push(10);
            let zigzag = ((*value as u32) << 1) ^ ((*value >> 31) as u32);
            put_varint(zigzag, out);
        }
    }
}

#[cfg(test)]
fn decode_value(input: &[u8], cursor: &mut usize) -> Result<Value, String> {
    let tag = *input
        .get(*cursor)
        .ok_or_else(|| "missing value tag".to_string())?;
    *cursor += 1;
    match tag {
        0 => Ok(Value::Null),
        1 => Ok(Value::Utf16(get_utf16(input, cursor)?)),
        2 | 9 => {
            let count = get_varint(input, cursor)? as usize;
            let end = cursor
                .checked_add(count)
                .ok_or_else(|| "byte string length overflow".to_string())?;
            let bytes = input
                .get(*cursor..end)
                .ok_or_else(|| "truncated byte string".to_string())?
                .to_vec();
            *cursor = end;
            Ok(if tag == 2 {
                Value::Base64Bytes(bytes)
            } else {
                Value::Latin1(bytes)
            })
        }
        3 => {
            let end = cursor
                .checked_add(4)
                .ok_or_else(|| "u32 length overflow".to_string())?;
            let bytes: [u8; 4] = input
                .get(*cursor..end)
                .ok_or_else(|| "truncated u32".to_string())?
                .try_into()
                .unwrap();
            *cursor = end;
            Ok(Value::U32(u32::from_le_bytes(bytes)))
        }
        4 => {
            let end = cursor
                .checked_add(8)
                .ok_or_else(|| "f64 length overflow".to_string())?;
            let bytes: [u8; 8] = input
                .get(*cursor..end)
                .ok_or_else(|| "truncated f64".to_string())?
                .try_into()
                .unwrap();
            *cursor = end;
            Ok(Value::F64Bits(u64::from_be_bytes(bytes)))
        }
        5 => Ok(Value::Bool(false)),
        6 => Ok(Value::Bool(true)),
        7 => {
            let count = get_varint(input, cursor)? as usize;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(decode_value(input, cursor)?);
            }
            Ok(Value::Array(values))
        }
        8 => Ok(Value::JsonUtf16(get_utf16(input, cursor)?)),
        10 => {
            let zigzag = get_varint(input, cursor)?;
            let value = ((zigzag >> 1) as i32) ^ -((zigzag & 1) as i32);
            Ok(Value::I32(value))
        }
        _ => Err(format!("unknown value tag {tag}")),
    }
}

pub fn encode_document(values: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(values.len() as u32, &mut out);
    for value in values {
        encode_value(value, &mut out);
    }
    out
}

#[cfg(test)]
pub fn decode_document(input: &[u8]) -> Result<Vec<Value>, String> {
    let mut cursor = 0usize;
    let count = get_varint(input, &mut cursor)? as usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_value(input, &mut cursor)?);
    }
    if cursor != input.len() {
        return Err(format!(
            "{} trailing byte(s) after decoded document",
            input.len() - cursor
        ));
    }
    Ok(values)
}

pub fn seed_hash(seed: &str) -> u32 {
    let mut hash = FNV_OFFSET;
    for unit in seed.encode_utf16() {
        hash = (hash ^ unit as u32).wrapping_mul(FNV_PRIME);
    }
    if hash == 0 { ZERO_HASH_FALLBACK } else { hash }
}

#[inline]
fn xor_shift_13(value: u32) -> u32 {
    value ^ (value >> 13)
}

#[inline]
fn mix16(value: u32, multiplier: u32) -> u32 {
    (value ^ (value >> 16)).wrapping_mul(multiplier)
}

#[inline]
fn final_mix(value: u32) -> u32 {
    (value ^ (value >> 15)).wrapping_mul(FNV_PRIME)
}

#[inline]
fn rotated_mix(value: u32, xor_constant: u32) -> u32 {
    value.rotate_left(13) ^ xor_constant
}

fn tag_word(value: u32, mix_constant: u32, rotation_xor: u32) -> u32 {
    final_mix(rotated_mix(mix16(value, mix_constant), rotation_xor))
}

pub fn encrypt_with_debug(plain: &[u8], seed: &str) -> (Vec<u8>, CipherDebug) {
    let len = plain.len();
    let midpoint = len / 2;
    let bounds = [0, midpoint, midpoint, len];

    let hash = seed_hash(seed);
    let mut first_hash = hash ^ FIRST_INIT_XOR;
    let aux_hash = hash ^ AUX_INIT_XOR;
    let mut second_hash = hash ^ SECOND_INIT_XOR;
    let mut global_hash = hash ^ GLOBAL_INIT_XOR;
    let mut stream_state = hash ^ STREAM_INIT_XOR;
    let initial = [first_hash, aux_hash, second_hash, global_hash, stream_state];

    let mut encrypted = Vec::with_capacity(len);
    for (index, &byte) in plain.iter().enumerate() {
        let index32 = index as u32;

        let global_tweak = index32.wrapping_add(GLOBAL_INDEX_ADD) & 0xff;
        global_hash ^= (byte as u32).wrapping_add(global_tweak) ^ GLOBAL_INIT_XOR;
        global_hash = xor_shift_13(global_hash);

        if index < midpoint {
            let local_tweak = index32.wrapping_add(FIRST_SECOND_INDEX_ADD) & 0xff;
            first_hash ^= (byte as u32).wrapping_add(local_tweak) ^ FIRST_SECOND_XOR;
            first_hash = xor_shift_13(first_hash);
        } else {
            let local = (index - midpoint) as u32;
            let local_tweak = local.wrapping_add(FIRST_SECOND_INDEX_ADD) & 0xff;
            second_hash ^= (byte as u32).wrapping_add(local_tweak) ^ FIRST_SECOND_XOR;
            second_hash = xor_shift_13(second_hash);
        }

        if index & 3 == 0 {
            stream_state = stream_state
                .wrapping_add(index32)
                .wrapping_add(STREAM_INDEX_ADD)
                .wrapping_add(STREAM_ADD_1);
            stream_state ^= stream_state << 13;
            stream_state ^= stream_state >> 17;
            stream_state ^= stream_state << 5;
            stream_state = stream_state.wrapping_add(STREAM_ADD_2);
        }
        let key_byte = (stream_state >> ((index & 3) * 8)) as u8;
        encrypted.push(byte ^ key_byte);
    }

    let after_loop = [first_hash, aux_hash, second_hash, global_hash, stream_state];

    let word0_input = global_hash ^ WORD0_PRE_XOR ^ 1;
    let word1_input = global_hash ^ WORD1_PRE_XOR ^ 2;
    let word2_input = first_hash ^ WORD23_PRE_XOR ^ 3;
    let word3_input = second_hash ^ WORD23_PRE_XOR ^ 5;
    let tag_words = [
        tag_word(word0_input, WORD0_MIX, WORD0_ROT_XOR),
        tag_word(word1_input, WORD1_MIX, WORD1_ROT_XOR),
        tag_word(word2_input, WORD23_MIX, WORD23_ROT_XOR),
        tag_word(word3_input, WORD23_MIX, WORD23_ROT_XOR),
    ];

    let mut tag_masks = [0u32; 4];
    for (index, mask) in tag_masks.iter_mut().enumerate() {
        let first = (aux_hash ^ index as u32 ^ AUX_INIT_XOR).wrapping_mul(FNV_PRIME);
        *mask = (first ^ (first >> 16)).wrapping_mul(AUX_INIT_XOR);
    }

    let first_len = midpoint as u32;
    let second_len = (len - midpoint) as u32;
    let mut out = Vec::with_capacity(len + 24);
    out.extend_from_slice(&second_len.to_be_bytes());
    out.extend_from_slice(&first_len.to_be_bytes());
    for index in 0..4 {
        out.extend_from_slice(&(tag_words[index] ^ tag_masks[index]).to_be_bytes());
    }
    out.extend_from_slice(&encrypted);

    (
        out,
        CipherDebug {
            seed_hash: hash,
            bounds,
            initial,
            after_loop,
            tag_words,
            tag_masks,
        },
    )
}

pub fn encrypt(plain: &[u8], seed: &str) -> Vec<u8> {
    encrypt_with_debug(plain, seed).0
}

pub fn encode_header(seed: &str) -> String {
    let mut transformed = Vec::with_capacity(seed.encode_utf16().count() * 2);
    for unit in seed.encode_utf16() {
        let mut value = unit.rotate_left(1);
        value = value.wrapping_add(0xc481);
        value = value.rotate_left(2);
        transformed.extend_from_slice(&value.to_be_bytes());
    }
    base64_encode(&transformed)
}

pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() == 3 {
            out.push(ALPHABET[(c & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn assemble_output(header: &[u8], cipher: &[u8]) -> Result<Vec<u8>, String> {
    let key_len: u16 = header
        .len()
        .try_into()
        .map_err(|_| "header exceeds u16 length".to_string())?;
    let mut out = Vec::with_capacity(2 + header.len() + cipher.len());
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(cipher);
    Ok(out)
}
