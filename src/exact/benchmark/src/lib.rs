pub mod client;
pub mod config;
pub mod metrics;
pub mod server;
pub mod wire;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub fn error(message: impl std::fmt::Display) -> Error {
    std::io::Error::other(message.to_string()).into()
}
