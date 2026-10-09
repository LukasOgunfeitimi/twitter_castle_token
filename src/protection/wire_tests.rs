use super::wire::{Value, decode_document, encode_document};

#[test]
fn serializer_round_trips_every_recovered_wire_type() {
    let values = vec![
        Value::Null,
        Value::Utf16(vec![0x0041, 0x20ac]),
        Value::Base64Bytes(vec![1, 2, 3]),
        Value::U32(0x1234_5678),
        Value::F64Bits(1.5f64.to_bits()),
        Value::Bool(false),
        Value::Bool(true),
        Value::Array(vec![Value::I32(-1), Value::Latin1(b"A".to_vec())]),
        Value::JsonUtf16(vec![0x007b, 0x007d]),
        Value::Latin1(b"ascii".to_vec()),
        Value::I32(-123),
    ];
    let encoded = encode_document(&values);
    let decoded = decode_document(&encoded).expect("serializer output must decode");
    assert_eq!(decoded, values);
}
