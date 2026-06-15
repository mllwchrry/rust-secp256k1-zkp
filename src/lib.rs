// SPDX-License-Identifier: CC0-1.0

//! Rust bindings for Pieter Wuille's secp256k1 library, which is used for
//! fast and accurate manipulation of ECDSA and Schnorr signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!
//! To minimize dependencies, some functions are feature-gated. To generate
//! random keys or to re-randomize a context object, compile with the
//! `rand` and `std` features. If you are willing to use these features, we
//! have enabled an additional defense-in-depth sidechannel protection for
//! our context objects, which re-blinds certain operations on secret key
//! data. To de/serialize objects with serde, compile with "serde".
//! **Important**: `serde` encoding is **not** the same as consensus
//! encoding!
//!
//! Where possible, the bindings use the Rust type system to ensure that
//! API usage errors are impossible. For example, the library uses context
//! objects that contain precomputation tables which are created on object
//! construction. Since this is a slow operation (10+ milliseconds, vs ~50
//! microseconds for typical crypto operations, on a 2.70 Ghz i7-6820HQ)
//! the tables are optional, giving a performance boost for users who only
//! care about signing, only care about verification, or only care about
//! parsing. In the upstream library, if you attempt to sign a message using
//! a context that does not support this, it will trigger an assertion
//! failure and terminate the program. In `rust-secp256k1`, this is caught
//! at compile-time; in fact, it is impossible to compile code that will
//! trigger any assertion failures in the upstream library.
//!
//! ```rust
//! # #[cfg(all(feature = "rand", feature = "hashes", feature = "std"))] {
//! use secp256k1::rand;
//! use secp256k1::{Secp256k1, Message};
//! use secp256k1::hashes::{sha256, Hash};
//!
//! let secp = Secp256k1::new();
//! let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());
//! let digest = sha256::Hash::hash("Hello World!".as_bytes());
//! let message = Message::from_digest(digest.to_byte_array());
//!
//! let sig = secp.sign_ecdsa(message, &secret_key);
//! assert!(secp.verify_ecdsa(message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! If the "global-context" feature is enabled you have access to an alternate API.
//!
//! ```rust
//! # #[cfg(all(feature = "global-context", feature = "hashes", feature = "rand", feature = "std"))] {
//! use secp256k1::{rand, generate_keypair, Message};
//! use secp256k1::hashes::{sha256, Hash};
//!
//! let (secret_key, public_key) = generate_keypair(&mut rand::rng());
//! let digest = sha256::Hash::hash("Hello World!".as_bytes());
//! let message = Message::from_digest(digest.to_byte_array());
//!
//! let sig = secret_key.sign_ecdsa(message);
//! assert!(sig.verify(message, &public_key).is_ok());
//! # }
//! ```
//!
//! The above code requires `rust-secp256k1` to be compiled with the `rand`, `hashes`, and `std`
//! feature enabled, to get access to [`generate_keypair`](struct.Secp256k1.html#method.generate_keypair)
//! Alternately, keys and messages can be parsed from slices, like
//!
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
//! # fn compute_hash(_: &[u8]) -> [u8; 32] { [0xab; 32] }
//!
//! let secp = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
//! let public_key = PublicKey::from_secret_key(&secp, &secret_key);
//! // If the supplied byte slice was *not* the output of a cryptographic hash function this would
//! // be cryptographically broken. It has been trivially used in the past to execute attacks.
//! let message = Message::from_digest(compute_hash(b"CSW is not Satoshi"));
//!
//! let sig = secp.sign_ecdsa(message, &secret_key);
//! assert!(secp.verify_ecdsa(message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Users who only want to verify signatures can use a cheaper context, like so:
//!
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! use secp256k1::{Secp256k1, Message, ecdsa, PublicKey};
//!
//! let secp = Secp256k1::verification_only();
//!
//! let public_key = PublicKey::from_slice(&[
//!     0x02,
//!     0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55,
//!     0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8,
//!     0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c,
//!     0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
//! ]).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
//!
//! let message = Message::from_digest([
//!     0xaa, 0xdf, 0x7d, 0xe7, 0x82, 0x03, 0x4f, 0xbe,
//!     0x3d, 0x3d, 0xb2, 0xcb, 0x13, 0xc0, 0xcd, 0x91,
//!     0xbf, 0x41, 0xcb, 0x08, 0xfa, 0xc7, 0xbd, 0x61,
//!     0xd5, 0x44, 0x53, 0xcf, 0x6e, 0x82, 0xb4, 0x50,
//! ]);
//!
//! let sig = ecdsa::Signature::from_compact(&[
//!     0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a,
//!     0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c, 0x39, 0x7a,
//!     0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94,
//!     0x0b, 0x55, 0x86, 0x82, 0x3d, 0xfd, 0x02, 0xae,
//!     0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb,
//!     0xae, 0xfd, 0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc,
//!     0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
//!     0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
//! ]).expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes");
//!
//! # #[cfg(not(secp256k1_fuzz))]
//! assert!(secp.verify_ecdsa(message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Observe that the same code using, say [`signing_only`](struct.Secp256k1.html#method.signing_only)
//! to generate a context would simply not compile.
//!
//! ## Crate features/optional dependencies
//!
//! This crate provides the following opt-in Cargo features:
//!
//! * `std` - use standard Rust library, enabled by default.
//! * `alloc` - use the `alloc` standard Rust library to provide heap allocations.
//! * `rand` - use `rand` library to provide random generator (e.g. to generate keys).
//! * `hashes` - use the `hashes` library.
//! * `recovery` - enable functions that can compute the public key from signature.
//! * `lowmemory` - optimize the library for low-memory environments.
//! * `global-context` - enable use of global secp256k1 context (implies `std`).
//! * `serde` - implements serialization and deserialization for types in this crate using `serde`.
//!   **Important**: `serde` encoding is **not** the same as consensus encoding!
//!

// Coding conventions
#![deny(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![warn(missing_docs, missing_copy_implementations, missing_debug_implementations)]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;
#[cfg(bench)]
extern crate test;

#[cfg(feature = "hashes")]
pub extern crate hashes;

#[macro_use]
mod macros;
#[macro_use]
mod secret;
mod context;
mod key;
mod from_secp256k1;

pub mod constants;
pub mod ecdsa;
pub mod scalar;
#[cfg(feature = "serde")]
mod serde_util;
mod zkp;
pub use crate::zkp::*;

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::{fmt, mem, str};

#[cfg(all(feature = "global-context", feature = "std"))]
pub use context::global::{self, SECP256K1};
#[cfg(feature = "rand")]
pub use rand;
pub extern crate secp256k1_zkp_sys;
pub use secp256k1_zkp_sys as ffi;
#[cfg(feature = "serde")]
pub use serde;

#[cfg(feature = "alloc")]
pub use crate::context::{All, SignOnly, VerifyOnly};
pub use crate::context::{
    AllPreallocated, Context, PreallocatedContext, SignOnlyPreallocated, Signing, Verification,
    VerifyOnlyPreallocated,
};
use crate::ffi::types::AlignedType;
use crate::ffi::CPtr;
pub use crate::key::{InvalidParityValue, Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey};
pub use crate::scalar::Scalar;

/// Trait describing something that promises to be a 32-byte uniformly random number.
///
/// In particular, anything implementing this trait must have neglibile probability
/// of being zero, overflowing the group order, or equalling any specific value.
///
/// Since version 0.29 this has been deprecated; users should instead implement
/// `Into<Message>` for types that satisfy these properties.
#[deprecated(
    since = "0.29.0",
    note = "Please see v0.29.0 rust-secp256k1/CHANGELOG.md for suggestion"
)]
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

/// A (hashed) message input to an ECDSA signature.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);
impl_pretty_debug!(Message);

impl Message {
    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
    /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
    /// the result of signing isn't a
    /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
    #[inline]
    #[deprecated(since = "0.28.0", note = "use from_digest instead")]
    pub fn from_slice(digest: &[u8]) -> Result<Message, Error> {
        #[allow(deprecated)]
        Message::from_digest_slice(digest)
    }

    /// Creates a [`Message`] from a `digest`.
    ///
    /// The `digest` array has to be a cryptographically secure hash of the actual message that's
    /// going to be signed. Otherwise the result of signing isn't a [secure signature].
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    pub fn from_digest(digest: [u8; 32]) -> Message { Message(digest) }

    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// The slice has to be 32 bytes long and be a cryptographically secure hash of the actual
    /// message that's going to be signed. Otherwise the result of signing isn't a [secure
    /// signature].
    ///
    /// This method is deprecated. It's best to use [`Message::from_digest`] directly with an
    /// array. If your hash engine doesn't return an array for some reason use `.try_into()` on its
    /// output.
    ///
    /// # Errors
    ///
    /// If `digest` is not exactly 32 bytes long.
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    #[deprecated(since = "0.30.0", note = "use from_digest instead")]
    pub fn from_digest_slice(digest: &[u8]) -> Result<Message, Error> {
        Ok(Message::from_digest(digest.try_into().map_err(|_| Error::InvalidMessage)?))
    }
}

#[allow(deprecated)]
impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths.
    fn from(t: T) -> Message { Message(t.into_32()) }
}

impl fmt::LowerHex for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

/// The main error type for this library.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub enum Error {
    /// Signature failed verification.
    IncorrectSignature,
    /// Bad sized message ("messages" are actually fixed-sized digests [`constants::MESSAGE_SIZE`]).
    InvalidMessage,
    /// Bad public key.
    InvalidPublicKey,
    /// Bad signature.
    InvalidSignature,
    /// Bad secret key.
    InvalidSecretKey,
    /// Bad shared secret.
    InvalidSharedSecret,
    /// Bad recovery id.
    InvalidRecoveryId,
    /// Tried to add/multiply by an invalid tweak.
    InvalidTweak,
    /// Didn't pass enough memory to context creation with preallocated memory.
    NotEnoughMemory,
    /// Bad set of public keys.
    InvalidPublicKeySum,
    /// The only valid parity values are 0 or 1.
    InvalidParityValue(key::InvalidParityValue),
    /// Bad EllSwift value
    InvalidEllSwift,
    /// Failed to produce a surjection proof because of an internal error within `libsecp256k1-zkp`
    CannotProveSurjection,
    /// Given bytes don't represent a valid surjection proof
    InvalidSurjectionProof,
    /// Given bytes don't represent a valid pedersen commitment
    InvalidPedersenCommitment,
    /// Failed to produce a range proof because of an internal error within `libsecp256k1-zkp`
    CannotMakeRangeProof,
    /// Given range proof does not prove that the commitment is within a range
    InvalidRangeProof,
    /// Bad generator
    InvalidGenerator,
    /// Tweak must of len 32
    InvalidTweakLength,
    /// Tweak must be less than secp curve order
    TweakOutOfBounds,
    /// Given bytes don't represent a valid adaptor signature
    InvalidEcdsaAdaptorSignature,
    /// Failed to decrypt an adaptor signature because of an internal error within `libsecp256k1-zkp`
    CannotDecryptAdaptorSignature,
    /// Failed to recover an adaptor secret from an adaptor signature because of an internal error within `libsecp256k1-zkp`
    CannotRecoverAdaptorSecret,
    /// Given adaptor signature is not valid for the provided combination of public key, encryption key and message
    CannotVerifyAdaptorSignature,
    /// Given bytes don't represent a valid whitelist signature
    InvalidWhitelistSignature,
    /// Invalid PAK list
    InvalidPakList,
    /// Couldn't create whitelist signature with the given data.
    CannotCreateWhitelistSignature,
    /// The given whitelist signature doesn't correctly prove inclusion in the whitelist.
    InvalidWhitelistProof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use Error::*;

        match *self {
            IncorrectSignature => f.write_str("signature failed verification"),
            InvalidMessage => f.write_str("message was not 32 bytes (do you need to hash?)"),
            InvalidPublicKey => f.write_str("malformed public key"),
            InvalidSignature => f.write_str("malformed signature"),
            InvalidSecretKey => f.write_str("malformed or out-of-range secret key"),
            InvalidSharedSecret => f.write_str("malformed or out-of-range shared secret"),
            InvalidRecoveryId => f.write_str("bad recovery id"),
            InvalidTweak => f.write_str("bad tweak"),
            NotEnoughMemory => f.write_str("not enough memory allocated"),
            InvalidPublicKeySum => f.write_str(
                "the sum of public keys was invalid or the input vector lengths was less than 1",
            ),
            InvalidParityValue(e) => write_err!(f, "couldn't create parity"; e),
            InvalidEllSwift => f.write_str("malformed EllSwift value"),
            CannotProveSurjection => f.write_str("failed to prove surjection"),
            InvalidSurjectionProof => f.write_str("malformed surjection proof"),
            InvalidPedersenCommitment => f.write_str("malformed pedersen commitment"),
            CannotMakeRangeProof => f.write_str("failed to generate range proof"),
            InvalidRangeProof => f.write_str("failed to verify range proof"),
            InvalidGenerator => f.write_str("malformed generator"),
            InvalidEcdsaAdaptorSignature => f.write_str("malformed ecdsa adaptor signature"),
            CannotDecryptAdaptorSignature => f.write_str("failed to decrypt adaptor signature"),
            CannotRecoverAdaptorSecret => f.write_str("failed to recover adaptor secret"),
            CannotVerifyAdaptorSignature => f.write_str("failed to verify adaptor signature"),
            InvalidTweakLength => f.write_str("Tweak must of size 32"),
            TweakOutOfBounds => f.write_str("Tweak must be less than secp curve order"),
            InvalidWhitelistSignature => f.write_str("malformed whitelist signature"),
            InvalidPakList => f.write_str("invalid PAK list"),
            CannotCreateWhitelistSignature => f.write_str("cannot create whitelist signature with the given data"),
            InvalidWhitelistProof => f.write_str("given whitelist signature doesn't correctly prove inclusion in the whitelist"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IncorrectSignature => None,
            Error::InvalidMessage => None,
            Error::InvalidPublicKey => None,
            Error::InvalidSignature => None,
            Error::InvalidSecretKey => None,
            Error::InvalidSharedSecret => None,
            Error::InvalidRecoveryId => None,
            Error::InvalidTweak => None,
            Error::NotEnoughMemory => None,
            Error::InvalidPublicKeySum => None,
            Error::InvalidParityValue(error) => Some(error),
            Error::InvalidEllSwift => None,
            Error::CannotProveSurjection => None,
            Error::InvalidSurjectionProof => None,
            Error::InvalidPedersenCommitment => None,
            Error::CannotMakeRangeProof => None,
            Error::InvalidRangeProof => None,
            Error::InvalidGenerator => None,
            Error::InvalidTweakLength => None,
            Error::TweakOutOfBounds => None,
            Error::InvalidEcdsaAdaptorSignature => None,
            Error::CannotDecryptAdaptorSignature => None,
            Error::CannotRecoverAdaptorSecret => None,
            Error::CannotVerifyAdaptorSignature => None,
            Error::InvalidWhitelistSignature => None,
            Error::InvalidPakList => None,
            Error::CannotCreateWhitelistSignature => None,
            Error::InvalidWhitelistProof => None,
        }
    }
}

/// The secp256k1 engine, used to execute all signature operations.
pub struct Secp256k1<C: Context> {
    ctx: NonNull<ffi::Context>,
    phantom: PhantomData<C>,
}

// The underlying secp context does not contain any references to memory it does not own.
unsafe impl<C: Context> Send for Secp256k1<C> {}
// The API does not permit any mutation of `Secp256k1` objects except through `&mut` references.
unsafe impl<C: Context> Sync for Secp256k1<C> {}

impl<C: Context> PartialEq for Secp256k1<C> {
    fn eq(&self, _other: &Secp256k1<C>) -> bool { true }
}

impl<C: Context> Eq for Secp256k1<C> {}

impl<C: Context> Drop for Secp256k1<C> {
    fn drop(&mut self) {
        unsafe {
            let size = ffi::secp256k1_context_preallocated_clone_size(self.ctx.as_ptr());
            ffi::secp256k1_context_preallocated_destroy(self.ctx);

            C::deallocate(self.ctx.as_ptr() as _, size);
        }
    }
}

impl<C: Context> fmt::Debug for Secp256k1<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context {:?}, {}>", self.ctx, C::DESCRIPTION)
    }
}

impl<C: Context> Secp256k1<C> {
    /// Getter for the raw pointer to the underlying secp256k1 context. This
    /// shouldn't be needed with normal usage of the library. It enables
    /// extending the Secp256k1 with more cryptographic algorithms outside of
    /// this crate.
    pub fn ctx(&self) -> NonNull<ffi::Context> { self.ctx }

    /// Returns the required memory for a preallocated context buffer in a generic manner(sign/verify/all).
    pub fn preallocate_size_gen() -> usize {
        let word_size = mem::size_of::<AlignedType>();
        let bytes = unsafe { ffi::secp256k1_context_preallocated_size(C::FLAGS) };

        (bytes + word_size - 1) / word_size
    }

    /// (Re)randomizes the Secp256k1 context for extra sidechannel resistance.
    ///
    /// Requires compilation with "rand" feature. See comment by Gregory Maxwell in
    /// [libsecp256k1](https://github.com/bitcoin-core/secp256k1/commit/d2275795ff22a6f4738869f5528fbbb61738aa48).
    #[cfg(feature = "rand")]
    pub fn randomize<R: rand::Rng + ?Sized>(&mut self, rng: &mut R) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        self.seeded_randomize(&seed);
    }

    /// (Re)randomizes the Secp256k1 context for extra sidechannel resistance given 32 bytes of
    /// cryptographically-secure random data;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell.
    pub fn seeded_randomize(&mut self, seed: &[u8; 32]) {
        unsafe {
            let err = ffi::secp256k1_context_randomize(self.ctx, seed.as_c_ptr());
            // This function cannot fail; it has an error return for future-proofing.
            // We do not expose this error since it is impossible to hit, and we have
            // precedent for not exposing impossible errors (for example in
            // `PublicKey::from_secret_key` where it is impossible to create an invalid
            // secret key through the API.)
            // However, if this DOES fail, the result is potentially weaker side-channel
            // resistance, which is deadly and undetectable, so we take out the entire
            // thread to be on the safe side.
            assert_eq!(err, 1);
        }
    }
}

impl<C: Signing> Secp256k1<C> {
    /// Generates a random keypair. Convenience function for [`SecretKey::new`] and
    /// [`PublicKey::from_secret_key`].
    #[inline]
    #[cfg(feature = "rand")]
    pub fn generate_keypair<R: rand::Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (key::SecretKey, key::PublicKey) {
        let sk = key::SecretKey::new(rng);
        let pk = key::PublicKey::from_secret_key(self, &sk);
        (sk, pk)
    }
}

/// Generates a random keypair using the global [`SECP256K1`] context.
#[inline]
#[cfg(all(feature = "global-context", feature = "rand"))]
pub fn generate_keypair<R: rand::Rng + ?Sized>(rng: &mut R) -> (key::SecretKey, key::PublicKey) {
    SECP256K1.generate_keypair(rng)
}

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}

/// Utility function used to encode hex into a target u8 buffer. Returns
/// a reference to the target buffer as an str. Returns an error if the target
/// buffer isn't big enough.
#[inline]
fn to_hex<'a>(src: &[u8], target: &'a mut [u8]) -> Result<&'a str, ()> {
    let hex_len = src.len() * 2;
    if target.len() < hex_len {
        return Err(());
    }
    const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

    let mut i = 0;
    for &b in src {
        target[i] = HEX_TABLE[usize::from(b >> 4)];
        target[i + 1] = HEX_TABLE[usize::from(b & 0b00001111)];
        i += 2;
    }
    let result = &target[..hex_len];
    debug_assert!(str::from_utf8(result).is_ok());
    unsafe { Ok(str::from_utf8_unchecked(result)) }
}

#[cfg(feature = "rand")]
pub(crate) fn random_32_bytes<R: rand::Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut ret = [0u8; 32];
    rng.fill(&mut ret);
    ret
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hex_lit::hex;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;


    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore] // Panicking from C may trap (SIGILL) intentionally, so we test this manually.
    #[cfg(feature = "alloc")]
    fn test_panic_raw_ctx_should_terminate_abnormally() {
        // Trying to use an all-zeros public key should cause an ARG_CHECK to trigger.
        let pk = PublicKey::from(unsafe { ffi::PublicKey::new() });
        pk.serialize();
    }


    #[test]
    fn signature_display() {
        const HEX_STR: &str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
        let byte_str = hex!(HEX_STR);

        assert_eq!(
            ecdsa::Signature::from_der(&byte_str).expect("byte str decode"),
            ecdsa::Signature::from_str(HEX_STR).expect("byte str decode")
        );

        let sig = ecdsa::Signature::from_str(HEX_STR).expect("byte str decode");
        assert_eq!(&sig.to_string(), HEX_STR);
        assert_eq!(&format!("{:?}", sig), HEX_STR);

        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4"
        )
        .is_err());
        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab"
        )
        .is_err());
        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eabxx"
        )
        .is_err());
        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45"
        )
        .is_err());

        // 71 byte signature
        let hex_str = "30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce774b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776";
        let sig = ecdsa::Signature::from_str(hex_str).expect("byte str decode");
        assert_eq!(&format!("{}", sig), hex_str);
    }

    #[test]
    fn signature_lax_der() {
        macro_rules! check_lax_sig(
            ($hex:expr) => ({
                let sig = hex!($hex);
                assert!(ecdsa::Signature::from_der_lax(&sig[..]).is_ok());
            })
        );

        check_lax_sig!("304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c");
        check_lax_sig!("304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f");
        check_lax_sig!("3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a");
        check_lax_sig!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        check_lax_sig!("3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1");
        check_lax_sig!("3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60");
        check_lax_sig!("3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf");
    }



    #[test]
    #[allow(deprecated)]
    fn test_bad_slice() {
        assert_eq!(
            ecdsa::Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE + 1]),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            ecdsa::Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE]),
            Err(Error::InvalidSignature)
        );

        assert_eq!(
            Message::from_digest_slice(&[0; constants::MESSAGE_SIZE - 1]),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            Message::from_digest_slice(&[0; constants::MESSAGE_SIZE + 1]),
            Err(Error::InvalidMessage)
        );
        assert!(Message::from_digest_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
        assert!(Message::from_digest_slice(&[1; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn test_hex() {
        use rand::RngCore;

        use super::to_hex;

        let mut rng = rand::rng();
        const AMOUNT: usize = 1024;
        for i in 0..AMOUNT {
            // 255 isn't a valid utf8 character.
            let mut hex_buf = [255u8; AMOUNT * 2];
            let mut src_buf = [0u8; AMOUNT];
            let mut result_buf = [0u8; AMOUNT];
            let src = &mut src_buf[0..i];
            rng.fill_bytes(src);

            let hex = to_hex(src, &mut hex_buf).unwrap();
            assert_eq!(from_hex(hex, &mut result_buf).unwrap(), i);
            assert_eq!(src, &result_buf[..i]);
        }

        assert!(to_hex(&[1; 2], &mut [0u8; 3]).is_err());
        assert!(to_hex(&[1; 2], &mut [0u8; 4]).is_ok());
        assert!(from_hex("deadbeaf", &mut [0u8; 3]).is_err());
        assert!(from_hex("deadbeaf", &mut [0u8; 4]).is_ok());
        assert!(from_hex("a", &mut [0u8; 4]).is_err());
        assert!(from_hex("ag", &mut [0u8; 4]).is_err());
    }

}

#[cfg(bench)]
#[cfg(all(feature = "rand", feature = "std"))]
mod benches {
    use rand::rngs::mock::StepRng;
    use test::{black_box, Bencher};

    use super::{Message, Secp256k1};

    #[bench]
    pub fn generate(bh: &mut Bencher) {
        let s = Secp256k1::new();
        let mut r = StepRng::new(1, 1);
        bh.iter(|| {
            let (sk, pk) = s.generate_keypair(&mut r);
            black_box(sk);
            black_box(pk);
        });
    }

}
