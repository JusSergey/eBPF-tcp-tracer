use crate::CliResult;
use aya::maps::perf::AsyncPerfEventArrayBuffer;
use aya::maps::{AsyncPerfEventArray, MapData};
use bytes::BytesMut;
use futures::FutureExt;
use libc::{AF_INET, clone};
use log::{error, info};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tcpk_common::*;
use tokio::sync::Mutex;

struct InnerProcessor {
    send_buffer: HashMap<u64, Vec<u8>>,
    recv_buffer: HashMap<u64, Vec<u8>>,
}

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

    async fn on_payload(&self, connection: &Connection, payload: &Payload, storage: Arc<Mutex<HashMap<u64, Vec<u8>>>>) {
        self.send_buffer.lock().await.insert(connection.id.tid, Vec::new());
        self.recv_buffer.lock().await.insert(connection.id.tid, Vec::new());
    }

    pub async fn process_connect(&self, connection: &Connection) -> CliResult<()> {
        self.on_connect(connection.id.tid).await;
        Ok(())
    }

    pub async fn process_send(&self, connection: &Connection, payload: &Payload) -> CliResult<()> {
        info!("Process send {:?} {:?}", connection, String::from_utf8(payload.get_meaningful_payload().to_vec()));
        self.on_payload(connection, payload, self.send_buffer.clone()).await;
        Ok(())
    }

    pub async fn process_recv(&self, connection: &Connection, payload: &Payload) -> CliResult<()> {
        info!("Process recv {:?} {:?}", connection, String::from_utf8(payload.get_meaningful_payload().to_vec()));
        self.on_payload(connection, payload, self.recv_buffer.clone()).await;
        Ok(())
    }

    pub async fn process_close(&self, connection: &Connection) -> CliResult<()> {
        info!("Process close {:?}", connection);
        self.send_buffer.lock().await.remove(&connection.id.tid);
        self.recv_buffer.lock().await.remove(&connection.id.tid);
        Ok(())
    }
}
