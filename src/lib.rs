//! Async Luna Service 2 IPC for webOS TV.
//!
//! [`Connection`] communicates with the Luna hub directly over Unix sockets.
//! Enable the `serde` feature to serialize and deserialize typed JSON payloads.
//!
//! ```no_run
//! use ls2::Connection;
//!
//! # smol::block_on(async {
//! let bus = Connection::connect().await?;
//! let time = bus.call_raw("luna://com.palm.systemservice/time/getSystemTime", "{}").await?;
//! println!("{time}");
//! # Ok::<(), ls2::Error>(())
//! # })?;
//! # Ok::<(), ls2::Error>(())
//! ```

mod address;
mod connection;
mod error;
mod profile;
mod service;
mod stream;
mod wire;

pub use connection::{Connection, ConnectionBuilder};
pub use error::{Error, ErrorKind};
pub use profile::ProtocolProfile;
pub use service::{MethodError, Reply, Request, Router, StatefulRouter};
pub use stream::{Signal, SignalFilter, SignalStream, Subscription};
