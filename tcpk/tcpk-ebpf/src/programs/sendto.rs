use crate::states::{EVENTS, TMP_TCP_EVENT};
use aya_bpf::cty::{c_int, c_ulong, c_void};
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
    bpf_probe_read_user_buf,
};
use aya_bpf::maps::HashMap;
use aya_bpf::memcpy;
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::info;
use tcpk_common::{TcpEvent, TCP_EVENT_SEND_TEMPLATE, PerfDataType};

struct KernelSend {
    buf: u64,
    len: usize,
}

// unsafe impl Sync for KernelSend {}

// static SEND_CTX: HashMap<u64, u64> = HashMap::with_max_entries(32, 0);

pub unsafe fn sys_sendto_entry(ctx: ProbeContext) -> Result<u32, u32> {
    let tid = bpf_get_current_pid_tgid();
    match TMP_TCP_EVENT.get_ptr_mut(&tid) {
        Some(event) => {
            // info!(&ctx, "SET SEND TEMPLATE");
            let origin_connection = if let TcpEvent::Connect(c) = &*event {
                *c
            } else {
                return Err(0);
            };
            let fd: c_int = ctx.arg(0).ok_or(0u32)?;

            if fd != origin_connection.id.fd || tid != origin_connection.id.tid {
                return Err(0);
            }

            let buf: *const u8 = ctx.arg(1).ok_or(0u32)?;
            let len: usize = ctx.arg(2).ok_or(0u32)?;


            *event = TCP_EVENT_SEND_TEMPLATE;
            if let TcpEvent::Send {
                connection,
                payload,
            } = &mut *event
            {
                *connection = origin_connection;
                payload.size = 0; // overrides at kretprobe
                payload.kernel_ptr = buf;
                // if bpf_probe_read_user_buf(buf, &mut payload.data[0..2]).is_ok() {
                //     info!(&ctx, "IT IS OKAY");
                // }
                // SEND_CTX.insert(&tid, &buf, 0);
                // let mut processed = 0;
                // let size_of_buff: usize = core::mem::size_of_val(&payload.data);
                // // payload.data[0] = *buf.add(0);
                // // for num in 0..((64*1024)/size_of_buff) {
                // let left = len - processed;
                // let current_portion = core::cmp::min(left, size_of_buff);
                // bpf_probe_read_user_buf(
                //     (buf as usize + processed) as *const u8,
                //     &mut payload.data[0..current_portion],
                // )
                // .map_err(|_| {
                //     info!(&ctx, "sent output bytes");
                //     0u32
                // })?;
                // processed += current_portion;
                // EVENTS.output_at_index(&ctx, 0, &*event, 0);
                // info!(&ctx, "really ok {} {}", current_portion, len);
                // }
                info!(&ctx, "presend");
            } else {
                return Err(0);
            }
        }
        None => {
            return Err(0)
        },
    }

    Ok(0)
}

pub unsafe fn sys_sendto_exit(ctx: ProbeContext) -> Result<u32, u32> {
    let ret: c_int = ctx.ret().ok_or(1u32)?;
    if ret <= 0 {
        return Ok(0);
    }
    let tid = bpf_get_current_pid_tgid();
    match TMP_TCP_EVENT.get_ptr_mut(&tid) {
        Some(event) => {
            if let TcpEvent::Send {
                connection,
                payload,
            } = &mut *event
            {
                // if connection.id.tid != tid {
                //     return Ok(0);
                // }

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
                info!(&ctx, "sent {}", processed);
            }
        }
        _ => {}
    }
    Ok(0)
}
