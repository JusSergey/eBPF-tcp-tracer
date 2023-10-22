#![no_std]

use aya_bpf::bindings::sa_family_t;

#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: u16,
    pub sin_addr: u32,
}
#[derive(Debug, Clone, Copy)]
pub struct Identification {
    pub fd: i32,
    pub tid: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Connection {
    pub id: Identification,
    pub ip: u32,
    pub port: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Payload {
    pub size: usize,
    pub data: [u8; 128],
    pub kernel_ptr: *const u8,
}

pub static TCP_EVENT_SEND_TEMPLATE: TcpEvent = TcpEvent::Send {
    connection: Connection {
        id: Identification { fd: 0, tid: 0 },
        ip: 0,
        port: 0,
    },
    payload: Payload { size: 0, data: [0u8; 128], kernel_ptr: 0 as *const u8 },
};

#[derive(Debug, Clone, Copy)]
pub enum TcpEvent {
    Connect(Connection),
    Send {
        connection: Connection,
        payload: Payload
    },
    Recv {
        connection: Connection,
        payload: Payload,
    },
    Dummy,
}

unsafe impl Sync for TcpEvent {}
