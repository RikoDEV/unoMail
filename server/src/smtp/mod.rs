//! SMTP: server sessions, acceptance pipelines, the outbound queue and client.

pub mod client;
pub mod delivery;
pub mod dsn;
pub mod queue;
pub mod server;
pub mod sevenbit;
pub mod srs;
pub mod submit;
pub mod transport;
