#![feature(c_size_t)]
#![no_std]
#![no_main]
mod programs;
mod states;

use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_bpf::macros::kretprobe;

fn handle_result(result: Result<u32, u32>) -> u32 {
    match result {
        Ok(ret) | Err(ret) => ret
    }
}

#[kprobe]
pub fn program_sys_connect_entry(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_connect_entry(ctx) })
}

#[kprobe]
pub fn program_sys_sendto_entry(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_sendto_entry(ctx) })
}

#[kretprobe]
pub fn program_sys_sendto_exit(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_sendto_exit(ctx) })
}

#[kprobe]
pub fn program_sys_close_entry(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_close_entry(ctx) })
}

#[kprobe]
pub fn program_sys_recvfrom_entry(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_recvfrom_entry(ctx) })
}

#[kretprobe]
pub fn program_sys_recvfrom_exit(ctx: ProbeContext) -> u32 {
    handle_result(unsafe { programs::sys_recvfrom_exit(ctx) })
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
