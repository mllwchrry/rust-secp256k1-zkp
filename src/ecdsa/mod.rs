// SPDX-License-Identifier: CC0-1.0

//! Structs and functionality related to the ECDSA signature algorithm.
//!

pub mod serialized_signature;

use core::{fmt, str};

pub use self::serialized_signature::SerializedSignature;
use crate::ffi::CPtr;
use crate::{
    ffi, from_hex, Error, Message, Secp256k1, Verification,
};
use crate::key::PublicKey;

/// An ECDSA signature
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Signature(pub(crate) ffi::Signature);
impl_fast_comparisons!(Signature);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sig = self.serialize_der();
        sig.fmt(f)
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0u8; 72];
        match from_hex(s, &mut res) {
            Ok(x) => Signature::from_der(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl Signature {
    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    pub fn from_der(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {
            return Err(Error::InvalidSignature);
        }

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_der(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                data.len(),
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature
    pub fn from_compact(data: &[u8]) -> Result<Signature, Error> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::secp256k1_ecdsa_signature_parse_compact(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a "lax DER"-encoded byte slice to a signature.
    pub fn from_der_lax(data: &[u8]) -> Result<Signature, Error> {
        if data.is_empty() {
            return Err(Error::InvalidSignature);
        }

        unsafe {
            let mut ret = ffi::Signature::new();
            if ffi::ecdsa_signature_parse_der_lax(
                ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_c_ptr(),
                data.len(),
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Normalizes a signature to a "low S" form.
    pub fn normalize_s(&mut self) {
        unsafe {
            ffi::secp256k1_ecdsa_signature_normalize(
                ffi::secp256k1_context_no_precomp,
                self.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
        }
    }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der(&self) -> SerializedSignature {
        let mut data = [0u8; serialized_signature::MAX_LEN];
        let mut len: usize = serialized_signature::MAX_LEN;
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_der(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                &mut len,
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
            SerializedSignature::from_raw_parts(data, len)
        }
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self) -> [u8; 64] {
        let mut ret = [0u8; 64];
        unsafe {
            let err = ffi::secp256k1_ecdsa_signature_serialize_compact(
                ffi::secp256k1_context_no_precomp,
                ret.as_mut_c_ptr(),
                self.as_c_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }
}

impl CPtr for Signature {
    type Target = ffi::Signature;

    fn as_c_ptr(&self) -> *const Self::Target { &self.0 }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target { &mut self.0 }
}

/// Creates a new signature from a FFI signature
impl From<ffi::Signature> for Signature {
    #[inline]
    fn from(sig: ffi::Signature) -> Signature { Signature(sig) }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize_der())
        }
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public key `pk`.
    pub fn verify_ecdsa(&self, msg: &Message, sig: &Signature, pk: &PublicKey) -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ecdsa_verify(
                self.ctx.as_ptr(),
                sig.as_c_ptr(),
                msg.as_c_ptr(),
                pk.as_c_ptr(),
            ) == 0
            {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(crate::serde_util::FromStrVisitor::new(
                "a hex string representing a DER encoded Signature",
            ))
        } else {
            d.deserialize_bytes(crate::serde_util::BytesVisitor::new(
                "raw byte stream, that represents a DER encoded Signature",
                Signature::from_der,
            ))
        }
    }
}
