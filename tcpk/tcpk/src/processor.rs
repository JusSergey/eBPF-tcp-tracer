use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use tcpk_common::*;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Processor {
    send_buffer: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    recv_buffer: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            send_buffer: Arc::new(Default::default()),
            recv_buffer: Arc::new(Default::default()),
        }
    }

    async fn on_connect(&self, key: u64) {
        self.send_buffer.lock().await.insert(key, Vec::new());
        self.recv_buffer.lock().await.insert(key, Vec::new());
    }

    async fn on_payload(
        &self,
        connection: &Connection,
        payload: &Payload,
        storage: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    ) {
        if let Some(storage) = storage.lock().await.get_mut(&connection.id.tid) {
            storage.extend_from_slice(payload.get_meaningful_payload());
        }
    }

    pub async fn process_connect(&self, connection: &Connection) {
        self.on_connect(connection.id.tid).await;
    }

    pub async fn process_send(&self, connection: &Connection, payload: &Payload) {
        self.on_payload(connection, payload, self.send_buffer.clone())
            .await;
    }

    pub async fn process_recv(&self, connection: &Connection, payload: &Payload) {
        self.on_payload(connection, payload, self.recv_buffer.clone())
            .await;
    }

    pub async fn process_close(&self, connection: &Connection) {
        let out_buffer = self.send_buffer.lock().await.remove(&connection.id.tid);
        let in_buffer = self.recv_buffer.lock().await.remove(&connection.id.tid);
        if let Some(out) = out_buffer {
            info!(
                "Sent payload:\n{}",
                String::from_utf8(out).unwrap_or_default()
            );
        }
        if let Some(inb) = in_buffer {
            info!(
                "Recv payload:\n{}",
                String::from_utf8(inb).unwrap_or_default()
            );
        }
    }
}
