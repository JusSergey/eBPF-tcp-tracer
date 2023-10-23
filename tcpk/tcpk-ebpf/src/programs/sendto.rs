use crate::programs::common::{common_read_entry, common_read_exit};
use aya_bpf::programs::ProbeContext;
use tcpk_common::TCP_EVENT_SEND_TEMPLATE;

pub unsafe fn sys_sendto_entry(ctx: ProbeContext) -> Result<u32, u32> {
    common_read_entry(ctx, &TCP_EVENT_SEND_TEMPLATE)
}

pub unsafe fn sys_sendto_exit(ctx: ProbeContext) -> Result<u32, u32> {
    common_read_exit(ctx)
}

