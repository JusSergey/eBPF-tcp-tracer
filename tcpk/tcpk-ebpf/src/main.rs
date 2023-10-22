#![no_std]
#![no_main]
mod programs;
mod states;

use aya_bpf::{macros::kprobe, programs::ProbeContext, maps::*};
use aya_bpf::bindings::{bpf_sock_addr, sa_family_t, sockaddr};
use aya_bpf::cty::c_void;
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read};
use aya_bpf::macros::{kretprobe, map};
use aya_log_ebpf::{error, info};
use tcpk_common::*;

struct ReadInstruction {
    fd: i32,
    payload: Payload,
}

struct KernelRead {
    data: *const c_void,

}

fn handle_result(result: Result<u32, u32>) -> u32 {
    match result {
        Ok(ret) | Err(ret) => ret
    }
}

#[kprobe]
pub fn program_sys_connect_entry(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_connect_entry(ctx) })
}

#[kretprobe]
pub fn program_sys_connect_exit(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_connect_exit(ctx) })
}

#[kprobe]
pub fn program_sys_sendto_entry(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_sendto_entry(ctx) })
}

#[kretprobe]
pub fn program_sys_sendto_exit(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_sendto_exit(ctx) })
}

// #[kprobe]
// pub fn program_sys_sendto(ctx: ProbeContext) -> u32 {
//     match unsafe { sys_sendto(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }
//
// unsafe fn sys_sendto(ctx: ProbeContext) -> Result<u32, u32> {
//     Ok(0)
// }
//
// #[kprobe]
// pub fn program_sys_recvfrom(ctx: ProbeContext) -> u32 {
//     match unsafe { sys_recvfrom(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }
//
// unsafe fn sys_recvfrom(ctx: ProbeContext) -> Result<u32, u32> {
//     Ok(0)
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
