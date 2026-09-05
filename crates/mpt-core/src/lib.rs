#![no_std]

extern crate alloc;

pub mod hasher;
pub mod merkle;

pub use hasher::{Hasher, Keccak256};
