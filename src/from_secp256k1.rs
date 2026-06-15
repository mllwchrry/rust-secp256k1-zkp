// SecretKey — both crates use [u8; 32] via secret_bytes() / from_byte_array()
#[cfg(feature = "secp256k1")]
impl From<::secp256k1::SecretKey> for crate::SecretKey {
    fn from(sk: ::secp256k1::SecretKey) -> Self {
        crate::SecretKey::from_byte_array(sk.secret_bytes()).expect("same format")
    }
}
#[cfg(feature = "secp256k1")]
impl From<crate::SecretKey> for ::secp256k1::SecretKey {
    fn from(sk: crate::SecretKey) -> Self {
        ::secp256k1::SecretKey::from_byte_array(sk.secret_bytes()).expect("same format")
    }
}

// PublicKey — serialize() returns [u8; 33] compressed; from_byte_array_compressed takes [u8; 33]
#[cfg(feature = "secp256k1")]
impl From<::secp256k1::PublicKey> for crate::PublicKey {
    fn from(pk: ::secp256k1::PublicKey) -> Self {
        crate::PublicKey::from_byte_array_compressed(pk.serialize()).expect("same format")
    }
}
#[cfg(feature = "secp256k1")]
impl From<crate::PublicKey> for ::secp256k1::PublicKey {
    fn from(pk: crate::PublicKey) -> Self {
        ::secp256k1::PublicKey::from_byte_array_compressed(pk.serialize()).expect("same format")
    }
}

// XOnlyPublicKey — serialize() returns [u8; 32]; from_byte_array takes [u8; 32]
#[cfg(feature = "secp256k1")]
impl From<::secp256k1::XOnlyPublicKey> for crate::XOnlyPublicKey {
    fn from(pk: ::secp256k1::XOnlyPublicKey) -> Self {
        crate::XOnlyPublicKey::from_byte_array(pk.serialize()).expect("same format")
    }
}
#[cfg(feature = "secp256k1")]
impl From<crate::XOnlyPublicKey> for ::secp256k1::XOnlyPublicKey {
    fn from(pk: crate::XOnlyPublicKey) -> Self {
        ::secp256k1::XOnlyPublicKey::from_byte_array(pk.serialize()).expect("same format")
    }
}

// ::secp256k1::Keypair → crate::SecretKey (extract sk bytes, re-parse)
#[cfg(feature = "secp256k1")]
impl From<::secp256k1::Keypair> for crate::SecretKey {
    fn from(kp: ::secp256k1::Keypair) -> Self {
        crate::SecretKey::from_byte_array(kp.secret_bytes()).expect("same format")
    }
}
// crate::Keypair → ::secp256k1::SecretKey
#[cfg(feature = "secp256k1")]
impl From<crate::Keypair> for ::secp256k1::SecretKey {
    fn from(kp: crate::Keypair) -> Self {
        ::secp256k1::SecretKey::from_byte_array(kp.secret_bytes()).expect("same format")
    }
}