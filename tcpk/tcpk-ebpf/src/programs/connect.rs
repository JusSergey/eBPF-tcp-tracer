#![no_std]

use core::ffi::c_int;
use aya_bpf::bindings::sockaddr;
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_get_retval, bpf_probe_read};
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::{error, info};
use tcpk_common::{Connection, Identification, PerfDataType, sockaddr_in, TcpEvent};
use crate::programs::common::get_tmp_event;
use crate::states::{DUMMY_TCP_EVENT, EVENTS, TMP_TCP_EVENT};



pub unsafe fn sys_connect_entry(ctx: ProbeContext) -> Result<u32, u32> {

    let id = Identification {
        fd: ctx.arg(0).ok_or(0u32)?,
        tid: bpf_get_current_pid_tgid(),
    };
    let sock: *const sockaddr = ctx.arg(1).ok_or(0u32)?;

    let val = bpf_probe_read::<u16>(&(*sock).sa_family).map_err(|_| 0u32)?;
    // info!(&ctx, "AF_ITEN {}", val);
    if val != 2 /* AF_INET */ {
        return Ok(0)
    }

    let mut sock_in: sockaddr_in = bpf_probe_read(sock as *const sockaddr_in).map_err(|_| 0u32)?;
    sock_in.sin_port = u16::from_be(sock_in.sin_port);
    sock_in.sin_addr = u32::from_be(sock_in.sin_addr);

    if sock_in.sin_port != 8000 {
        return Ok(0);
    }

    let connection = Connection {
        id,
        ip: sock_in.sin_addr,
        port: sock_in.sin_port,
    };

    let tmp_tcp = get_tmp_event(&ctx, id.tid)?;
    *tmp_tcp = TcpEvent::Connect(connection);
    EVENTS.output(&ctx, &*tmp_tcp, 0);

    Ok(0)
}

pub unsafe fn sys_connect_exit(ctx: ProbeContext) -> Result<u32, u32> {
    let ret:c_int = ctx.ret().unwrap_or(111);
    let tid = bpf_get_current_pid_tgid();
    if ret != 0 {
        info!(&ctx, "Connection error {} {}", ret, tid);
        return Err(ret as u32)
    }

    Ok(0)
}