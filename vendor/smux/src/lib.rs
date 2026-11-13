//! # smux
//!
//! A stream multiplexing library for Rust, inspired by the [Go smux library](https://github.com/xtaci/smux).
//! This crate allows you to create multiple logical streams over a single connection,
//! making it useful for protocols that need to multiplex data streams efficiently.
//!
//! ## Features
//!
//! - **Async/await support**: Built on tokio for high-performance async I/O
//! - **Multiple streams**: Create many logical streams over one connection
//! - **Flow control**: Built-in sliding window flow control
//! - **Keep-alive**: Configurable keep-alive mechanism
//! - **Interoperability**: Compatible with the Go smux protocol
//!
//! ## Quick Start
//!
//! ### Server Side
//!
//! ```rust,no_run
//! use smux::{Config, Session};
//! use tokio::net::TcpListener;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let listener = TcpListener::bind("127.0.0.1:8080").await?;
//!     
//!     while let Ok((conn, _)) = listener.accept().await {
//!         tokio::spawn(async move {
//!             let config = Config::default();
//!             let mut session = Session::new_server(conn, config).await.unwrap();
//!             
//!             while let Ok(mut stream) = session.accept_stream().await {
//!                 tokio::spawn(async move {
//!                     // Handle stream...
//!                 });
//!             }
//!         });
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### Client Side
//!
//! ```rust,no_run
//! use smux::{Config, Session};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let conn = TcpStream::connect("127.0.0.1:8080").await?;
//!     let config = Config::default();
//!     let mut session = Session::new_client(conn, config).await?;
//!     
//!     let mut stream = session.open_stream().await?;
//!     // Use stream for reading/writing...
//!     
//!     Ok(())
//! }
//! ```

mod codec;
mod command;
mod config;
mod error;
mod frame;
pub mod session;
pub mod stream;

// Re-export main public types
pub use config::{Config, ConfigBuilder};
pub use error::{Result, SmuxError};
pub use session::Session;
pub use stream::Stream;
