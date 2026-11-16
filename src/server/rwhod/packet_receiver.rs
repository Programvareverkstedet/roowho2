use std::sync::Arc;

use anyhow::Context;
use chrono::{Timelike, Utc};
use tokio::net::UdpSocket;

use crate::{
    proto::{Whod, WhodStatusUpdate},
    server::rwhod::RwhodStatusStore,
};

pub async fn rwhod_packet_receiver_task(
    socket: Arc<UdpSocket>,
    whod_status_store: RwhodStatusStore,
) -> anyhow::Result<()> {
    let mut buf = [0u8; Whod::MAX_SIZE];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;

        tracing::debug!("Received rwhod packet of length {} bytes from {}", len, src);

        if len < Whod::HEADER_SIZE {
            tracing::error!(
                "Received too short packet from {src}: {len} bytes (needs to be at least {} bytes)",
                Whod::HEADER_SIZE
            );
            continue;
        }

        let result = Whod::from_bytes(buf.get(..len).unwrap_or_default())
            .context("Failed to parse whod packet")
            .and_then(|whod| {
                WhodStatusUpdate::try_from(whod)
                    .map_err(|e| anyhow::anyhow!("Invalid whod packet: {}", e))
            })
            .map(|mut status_update| {
                let timestamp = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());
                status_update.recvtime = Some(timestamp);
                status_update
            });

        match result {
            Ok(status_update) => {
                tracing::debug!("Processed whod packet from {src}: {:?}", status_update);

                if status_update.boot_time > status_update.sendtime {
                    tracing::warn!(
                        "Received whod packet from {src} with boot time {} after send time {}",
                        status_update.boot_time,
                        status_update.sendtime
                    );
                }

                if let Some(recvtime) = status_update.recvtime
                    && recvtime < status_update.sendtime
                {
                    tracing::warn!(
                        "Received whod packet from {src} with recv time {} before send time {}",
                        recvtime,
                        status_update.sendtime
                    );
                }

                let mut store = whod_status_store.write().await;
                store.upsert(status_update);
            }
            Err(err) => {
                tracing::error!("Error processing whod packet from {src}: {err:#}");
            }
        }
    }
}
