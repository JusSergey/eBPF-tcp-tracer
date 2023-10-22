#![no_std]
#![no_main]
mod programs;
mod states;

use aya_bpf::{macros::kprobe, programs::ProbeContext, maps::*};
use aya_bpf::bindings::{bpf_sock_addr, sa_family_t, sockaddr};
use aya_bpf::cty::c_void;
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read};
use aya_bpf::macros::map;
use aya_log_ebpf::{error, info};
use tcpk_common::*;

struct ReadInstruction {
    fd: i32,
    payload: Payload,
}

// #[map]
// static READ_INSTRUCTIONS: HashMap<i32, ReadInstruction> = HashMap::with_max_entries(64, 0);

struct KernelRead {
    data: *const c_void,

}

/// The data pipe
#[map]
pub static EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

/// Memory to write the tcp-event data because they are too big to put on the stack.
#[map]
static TMP_TCP_EVENT: HashMap<u64, TcpEvent> = HashMap::with_max_entries(32, 0);

static DUMMY_TCP_EVENT: TcpEvent = TcpEvent::Dummy;



// static BUFFERS: PerCpuHashMap<u64, [u8; 1]>

#[kprobe]
pub fn program_sys_connect(ctx: ProbeContext) -> u32 {
    match unsafe { sys_connect(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn sys_connect(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function called");
    let id = Identification {
        fd: ctx.arg(0).ok_or(0u32)?,
        tid: bpf_get_current_pid_tgid(),
    };
    let sock: *const sockaddr = ctx.arg(1).ok_or(0u32)?;

    if bpf_probe_read::<u16>(&(*sock).sa_family).map_err(|_| 0u32)? != 2 {
        return Ok(0)
    }

    let mut sock_in: sockaddr_in = bpf_probe_read(sock as *const sockaddr_in).map_err(|_| 0u32)?;
    sock_in.sin_port = u16::from_be(sock_in.sin_port);
    sock_in.sin_addr = u32::from_be(sock_in.sin_addr);

    let tmp_tcp = match TMP_TCP_EVENT.get_ptr_mut(&id.tid) {
        Some(value) => {
            value
        },
        None => {
            if TMP_TCP_EVENT.insert(&id.tid, &DUMMY_TCP_EVENT, 0).is_err() {
                error!(&ctx, "Failed to insert tmp-tcp event");
                return Ok(0);
            }
            match TMP_TCP_EVENT.get_ptr_mut(&id.tid) {
                Some(v) => v,
                None => {
                    error!(&ctx, "WTF? failed o find the tmp-tcp event after insertion");
                    return Ok(0);
                }
            }
        }
    };

    info!(&ctx, "New connection. fd={}, port={}, ip={:i}", id.fd, sock_in.sin_port, sock_in.sin_addr);

    let connection = Connection {
        id,
        ip: sock_in.sin_addr,
        port: sock_in.sin_port,
    };

    *tmp_tcp = TcpEvent::Connect(connection);

    EVENTS.output(&ctx, &*tmp_tcp, 0);
    // EVENTS.output(&ctx, &RAW_SHIT, 0);

    info!(&ctx, "The update is sent");

    Ok(0)
}

#[kprobe]
pub fn program_sys_sendto(ctx: ProbeContext) -> u32 {
    match unsafe { sys_sendto(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn sys_sendto(ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

#[kprobe]
pub fn program_sys_recvfrom(ctx: ProbeContext) -> u32 {
    match unsafe { sys_recvfrom(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn sys_recvfrom(ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
