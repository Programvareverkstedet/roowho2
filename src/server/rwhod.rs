mod packet_receiver;
mod packet_sender;
mod rwhod_status;

pub use packet_receiver::rwhod_packet_receiver_task;
pub use packet_sender::{determine_relevant_interfaces, rwhod_packet_sender_task};
pub use rwhod_status::{generate_rwhod_status_update, generate_rwhod_user_entries};

use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::proto::WhodStatusUpdate;

pub type RwhodStatusStore = Arc<RwLock<HashMap<String, WhodStatusUpdate>>>;
