use core::ffi::{c_int, c_ssize_t};
use aya_bpf::cty::ssize_t;
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_buf};
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::{error, info};
use tcpk_common::TcpEvent;
use crate::states::{DUMMY_TCP_EVENT, EVENTS, TMP_TCP_EVENT};

pub fn get_tmp_event(ctx: &ProbeContext, tid: u64) -> Result<*mut TcpEvent, u32> {
    match TMP_TCP_EVENT.get_ptr_mut(&tid) {
        Some(value) => {
            Ok(value)
        },
        None => {
            if TMP_TCP_EVENT.insert(&tid, &DUMMY_TCP_EVENT, 0).is_err() {
                error!(ctx, "Failed to insert tmp-tcp event");
                return Err(0);
            }
            match TMP_TCP_EVENT.get_ptr_mut(&tid) {
                Some(v) => Ok(v),
                None => {
                    error!(ctx, "WTF? failed o find the tmp-tcp event after insertion");
                    return Err(0);
                }
            }
        }
    }
}

pub unsafe fn common_read_entry(ctx: ProbeContext, event_template: &TcpEvent) -> Result<u32, u32> {
    let tid = bpf_get_current_pid_tgid();
    match TMP_TCP_EVENT.get_ptr_mut(&tid) {
        Some(event) => {
            let origin_connection = if let Some(connection) = (*event).get_connection() {
                *connection
            } else {
                return Err(0);
            };
            let fd: c_int = ctx.arg(0).ok_or(0u32)?;

            if fd != origin_connection.id.fd || tid != origin_connection.id.tid {
                return Err(0);
            }

            let buf: *const u8 = ctx.arg(1).ok_or(0u32)?;

            *event = *event_template;

            if let Some(connection) = (*event).get_connection() {
                *connection = origin_connection;
            }
            if let Some(payload) = (*event).get_payload() {
                payload.size = 0;
                payload.kernel_ptr = buf;
            }
        }
        None => {
            return Err(0)
        },
    }

    Ok(0)
}

pub unsafe fn common_read_exit(ctx: ProbeContext) -> Result<u32, u32> {
    let ret: ssize_t = ctx.ret().ok_or(1u32)?;
    if ret <= 0 {
        return Ok(0);
    }

    let tid = bpf_get_current_pid_tgid();
    match TMP_TCP_EVENT.get_ptr_mut(&tid) {
        Some(event) => {
            let (connection, payload) = match ((*event).get_connection(), (*event).get_payload()) {
                (Some(connection), Some(payload)) => (connection, payload),
                _ => return Ok(0),
            };
            let mut processed = 0;
            let size_of_buff = core::mem::size_of_val(&payload.data);

            for i in 0..(8192 / size_of_buff) {
                let left = ret as usize - processed;
                if left == 0 {
                    break;
                }

                let current_portion = core::cmp::min(left, size_of_buff);
                payload.size = current_portion;
                bpf_probe_read_user_buf(
                    (payload.kernel_ptr as usize + processed) as *const u8,
                    &mut payload.data[0..current_portion],
                )
                    .map_err(|_| 0u32)?;
                processed += current_portion;
                EVENTS.output(&ctx, &*event, 0);
            }
        }
        _ => {}
    }
    Ok(0)
}
