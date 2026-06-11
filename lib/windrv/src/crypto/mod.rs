//! Async AES-XTS encryption pipeline for the filter data path.

pub mod aes_xts;
pub mod pipeline;

pub use aes_xts::AesXtsCipher;
pub use pipeline::CryptoPipeline;
