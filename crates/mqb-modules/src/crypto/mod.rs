//! Crypto implementations: AES-128-CBC, SimosXOR, DSG substitution, and no-op.

mod aes_impl;
mod dsg;
mod none;
mod simos_xor;

pub use aes_impl::AesCrypto;
pub use dsg::DsgCrypto;
pub use none::NoCrypto;
pub use simos_xor::SimosXorCrypto;

/// Encrypt/decrypt a flash block.
///
/// All implementations are symmetric over the 16-byte boundary or byte-level,
/// so `encrypt` and `decrypt` may be the same operation (SimosXOR) or inverses.
pub trait BlockCrypto: Send + Sync {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}
