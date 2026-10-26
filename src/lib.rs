//! DecisionNS: a home DNS resolver that forwards to upstream resolvers
//! only after lists and decision-model rules accept the name.

pub mod admin;
pub mod app;
pub mod config;
pub mod decision;
pub mod dns;
pub mod model;
pub mod names;
pub mod policy;
pub mod store;
pub mod upstream;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
