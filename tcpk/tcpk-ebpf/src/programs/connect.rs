#![no_std]

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