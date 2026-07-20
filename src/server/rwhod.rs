mod audit_watcher;
mod packet_receiver;
mod packet_sender;
mod rwhod_status;
mod status_registry;

pub use audit_watcher::audit_change_notifier;
pub use packet_receiver::rwhod_packet_receiver_task;
pub use packet_sender::{determine_relevant_interfaces, rwhod_packet_sender_task};
pub use rwhod_status::{generate_rwhod_status_update, generate_rwhod_user_entries};
pub use status_registry::RwhodStatusRegistry;

use std::sync::Arc;
use tokio::sync::RwLock;

pub type RwhodStatusStore = Arc<RwLock<RwhodStatusRegistry>>;
