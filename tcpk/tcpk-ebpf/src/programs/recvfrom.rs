use aya_bpf::programs::ProbeContext;
use tcpk_common::{TCP_EVENT_RECV_TEMPLATE};
use crate::programs::common::{common_read_entry, common_read_exit};

pub unsafe fn sys_recvfrom_entry(ctx: ProbeContext) -> Result<u32, u32> {
    common_read_entry(ctx, &TCP_EVENT_RECV_TEMPLATE)
}

pub unsafe fn sys_recvfrom_exit(ctx: ProbeContext) -> Result<u32, u32> {
    common_read_exit(ctx)
}

