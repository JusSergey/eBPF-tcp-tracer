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
    pub size: u16,
    pub data: [u8; 4096],
}

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
