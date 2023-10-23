use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::programs::ProbeContext;
use tcpk_common::{TCP_EVENT_CLOSE_TEMPLATE, TcpEvent};
use crate::states::{EVENTS, TMP_TCP_EVENT};

pub unsafe fn sys_close_entry(ctx: ProbeContext) -> Result<u32, u32> {
    let tid = bpf_get_current_pid_tgid();
    let last_event = TMP_TCP_EVENT.get_ptr_mut(&tid);
    if let Some(event) = last_event {
        if let Some(connection) = (*event).get_connection().cloned() {
            *event = TCP_EVENT_CLOSE_TEMPLATE;
            if let TcpEvent::Close(current_connection) = &mut *event {
                current_connection.id = connection.id;
            }
            EVENTS.output(&ctx, &*event, 0);
        }
    }

    Ok(0)
}