use aya_bpf::cty::{c_int, c_ulong};
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::info;
use tcpk_common::{Identification, PerfDataType, TCP_EVENT_CLOSE_TEMPLATE, TcpEvent};
use crate::programs::utils::get_tmp_event;
use crate::states::{EVENTS, TMP_TCP_EVENT};

pub unsafe fn sys_close_entry(ctx: ProbeContext) -> Result<u32, u32> {
    // let fd: c_int = ctx.arg(0).ok_or(0u32)?;
    let tid = bpf_get_current_pid_tgid();
    let last_event = TMP_TCP_EVENT.get_ptr_mut(&tid);
    if let Some(event) = last_event {
        match *event {
            TcpEvent::Connect(_) => {}
            TcpEvent::Send { connection, .. } |
            TcpEvent::Recv { connection, .. } => {
                info!(&ctx, "expected");
                *event = TCP_EVENT_CLOSE_TEMPLATE;
                if let TcpEvent::Close(current_connection) = &mut *event {
                    current_connection.id = connection.id;
                }
                EVENTS.output(&ctx, &*event, 0);
            }
            TcpEvent::Close(_)|
            TcpEvent::Dummy => {}
        }

    }

    Ok(0)
}