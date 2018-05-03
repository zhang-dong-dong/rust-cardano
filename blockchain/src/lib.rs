extern crate wallet_crypto;
pub mod types;
pub mod genesis; /* genesis block related value */
pub mod normal; /* normal block related value */
mod block;

pub use types::*;
pub use block::*;
