use aya_bpf::cty::c_int;
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::info;
use tcpk_common::{TCP_EVENT_RECV_TEMPLATE, TCP_EVENT_SEND_TEMPLATE, TcpEvent};
use crate::programs::common::{common_read_entry, common_read_exit};
use crate::states::TMP_TCP_EVENT;

pub unsafe fn sys_recvfrom_entry(ctx: ProbeContext) -> Result<u32, u32> {
    common_read_entry(ctx, &TCP_EVENT_RECV_TEMPLATE)
}

pub unsafe fn sys_recvfrom_exit(ctx: ProbeContext) -> Result<u32, u32> {
    common_read_exit(ctx)
}

