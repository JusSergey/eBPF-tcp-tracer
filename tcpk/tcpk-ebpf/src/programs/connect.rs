#![no_std]

use aya_bpf::bindings::sockaddr;
use aya_bpf::helpers::{bpf_get_current_pid_tgid, bpf_get_retval, bpf_probe_read};
use aya_bpf::programs::ProbeContext;
use aya_log_ebpf::{error, info};
use tcpk_common::{Connection, Identification, sockaddr_in, TcpEvent};
use crate::programs::utils::get_tmp_event;
use crate::states::{DUMMY_TCP_EVENT, EVENTS, TMP_TCP_EVENT};



pub unsafe fn sys_connect_entry(ctx: ProbeContext) -> Result<u32, u32> {

    let id = Identification {
        fd: ctx.arg(0).ok_or(0u32)?,
        tid: bpf_get_current_pid_tgid(),
    };
    let sock: *const sockaddr = ctx.arg(1).ok_or(0u32)?;

    if bpf_probe_read::<u16>(&(*sock).sa_family).map_err(|_| 0u32)? != 2 /* AF_INET */ {
        return Ok(0)
    }

    // info!(&ctx, "function sys_connect_entry called");

    let mut sock_in: sockaddr_in = bpf_probe_read(sock as *const sockaddr_in).map_err(|_| 0u32)?;
    sock_in.sin_port = u16::from_be(sock_in.sin_port);
    sock_in.sin_addr = u32::from_be(sock_in.sin_addr);

    let connection = Connection {
        id,
        ip: sock_in.sin_addr,
        port: sock_in.sin_port,
    };

    *get_tmp_event(&ctx, id.tid)? = TcpEvent::Connect(connection);


    Ok(0)
}

pub unsafe fn sys_connect_exit(ctx: ProbeContext) -> Result<u32, u32> {
    let ret = ctx.ret().unwrap_or(111);
    // info!(&ctx, "function sys_connect_exit called {}", ret);
    if ret != 0 {
        return Err(ret)
    }

    let tid = bpf_get_current_pid_tgid();

    let tmp_tcp = get_tmp_event(&ctx, tid)?;

    // info!(&ctx, "The update is sent on exit");

    EVENTS.output(&ctx, &*tmp_tcp, 0);

    Ok(0)
}