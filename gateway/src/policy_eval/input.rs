//! Bounded, duplicate-rejecting input for the offline compiler only.

use std::{collections::HashSet, fmt};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::CompileError;

pub(super) fn parse(source: &[u8]) -> Result<Value, CompileError> {
    // serde_json also retains its default nesting limit. Diagnostics never
    // include the source, member names, or the underlying parser error.
    if source.len() > 1_048_576 {
        return Err(CompileError::InputTooLarge);
    }
    serde_json::from_slice::<UniqueValue>(source).map_err(|_| CompileError::InvalidJson)?;
    // With arbitrary_precision, serde_json presents decimal/exponent tokens to
    // generic visitors as private maps. The uniqueness pass must not reconstruct
    // values from those callbacks. A direct typed parse also ensures an actual
    // source object cannot masquerade as a numeric field through a private tag.
    serde_json::from_slice::<crate::rbac::Policy>(source)
        .map_err(|_| CompileError::InvalidPolicy)?;
    serde_json::from_slice(source).map_err(|_| CompileError::InvalidJson)
}

struct UniqueValue;

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object members")
            }

            fn visit_bool<E: de::Error>(self, _value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue)
            }

            fn visit_i64<E: de::Error>(self, _value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue)
            }

            fn visit_u64<E: de::Error>(self, _value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue)
            }

            fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Self::Value, E> {
                Ok(UniqueValue)
            }

            fn visit_str<E: de::Error>(self, _value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                while sequence.next_element::<UniqueValue>()?.is_some() {}
                Ok(UniqueValue)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut keys = HashSet::new();
                while let Some(key) = object.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate object member"));
                    }
                    object.next_value::<UniqueValue>()?;
                }
                Ok(UniqueValue)
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}
