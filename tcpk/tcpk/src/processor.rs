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
    ctx: HashMap<u64, Vec<u8>>,
}

#[derive(Clone)]
pub struct Processor {
    inner: Arc<Mutex<InnerProcessor>>,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerProcessor {
                ctx: Default::default(),
            })),
        }
    }

    pub async fn process_connect(&self, connection: &Connection) -> CliResult<()> {
        info!("Process connect {:?}", connection);
        if self
            .inner
            .lock()
            .await
            .ctx
            .insert(connection.id.tid, Vec::new())
            .is_some()
        {
            error!("Weird, it should not be present");
        } else {
            info!("Successfully connected");
        }

        Ok(())
    }

    pub async fn process_send(&self, connection: &Connection, payload: &Payload) -> CliResult<()> {
        info!("Process send {:?} {:?}", connection, payload.get_meaningful_payload());
        if let Some(accumulator) = self.inner.lock().await.ctx.get_mut(&connection.id.tid) {
            accumulator.extend_from_slice(payload.get_meaningful_payload());
        } else {
            error!("Weird, buffer for payload not found {:?}", connection);
        }
        Ok(())
    }

    pub async fn process_recv(&self) {}

    pub async fn process_close(&self, connection: &Connection) -> CliResult<()> {
        info!("Process close {:?}", connection);
        if let Some(buffer) = self.inner.lock().await.ctx.remove(&connection.id.tid) {
            info!("Final output {:?}", String::from_utf8(buffer));
        } else {
            info!("Weird not item on close");
        }
        Ok(())
    }
}
