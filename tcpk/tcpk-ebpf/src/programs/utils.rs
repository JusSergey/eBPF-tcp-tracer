use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::error;
use tcpk_common::TcpEvent;
use crate::states::{DUMMY_TCP_EVENT, TMP_TCP_EVENT};

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