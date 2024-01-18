#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::redundant_field_names,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_possible_truncation,
    clippy::missing_errors_doc
)]
#![deny(unsafe_code)]

pub mod tracing;

pub mod dns;
