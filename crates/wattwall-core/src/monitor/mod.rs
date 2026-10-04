//! What the network monitor decides without talking to Windows: reading the
//! bytes of the system's TCP and UDP tables, telling an incoming connection
//! from an outgoing one, how far away the other end is, the short memory of
//! connections that just closed, and the cache behind host-name lookups.

mod dto;
#[cfg(test)]
mod fixtures;
mod flows;
mod hostname;
mod names;
mod reach;
mod socket;
mod tracker;
mod view;
mod wire;

pub use dto::{ConnectionDto, MonitorDto};
pub use flows::{classify, Direction, Flow, Phase};
pub use hostname::{clean_name, reverse_name};
pub use names::{Failure, NameCache};
pub use reach::{address_text, worth_resolving, Reach};
pub use socket::{Protocol, Socket, SocketKind, TcpState};
pub use tracker::{Connection, Tracker, CLOSED_KEEP_SECS};
pub use view::{connections_view, MAX_ROWS};
pub use wire::{layout, parse_table, TableKind};
