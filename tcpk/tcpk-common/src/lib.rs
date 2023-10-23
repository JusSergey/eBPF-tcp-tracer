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
    pub data: [u8; 1500],
    pub kernel_ptr: *const u8,
}

unsafe impl Sync for Payload {}
unsafe impl Send for Payload {}

impl Payload {
    pub fn get_meaningful_payload(&self) -> &[u8] {
        &self.data[0..self.size]
    }
}

pub static TCP_CONNECTION_TEMPLATE: Connection = Connection {
    id: Identification { fd: 0, tid: 0 },
    ip: 0,
    port: 0,
};

pub static TCP_PAYLOAD_TEMPLATE: Payload = Payload {
    size: 0,
    data: [0u8; 1500],
    kernel_ptr: 0 as *const u8,
};

pub static TCP_EVENT_SEND_TEMPLATE: TcpEvent = TcpEvent::Send {
    connection: TCP_CONNECTION_TEMPLATE,
    payload: TCP_PAYLOAD_TEMPLATE,
};

pub static TCP_EVENT_RECV_TEMPLATE: TcpEvent = TcpEvent::Recv {
    connection: TCP_CONNECTION_TEMPLATE,
    payload: TCP_PAYLOAD_TEMPLATE,
};

pub static TCP_EVENT_CLOSE_TEMPLATE: TcpEvent = TcpEvent::Close(Connection {
    id: Identification { fd: 0, tid: 0 },
    ip: 0,
    port: 0,
});

#[derive(Debug, Clone, Copy)]
pub enum TcpEvent {
    Connect(Connection),
    Send {
        connection: Connection,
        payload: Payload,
    },
    Recv {
        connection: Connection,
        payload: Payload,
    },
    Close(Connection),
    Dummy,
}

impl TcpEvent {
    pub fn get_connection(&mut self) -> Option<&mut Connection> {
        match self {
            TcpEvent::Connect(connection)
            | TcpEvent::Close(connection)
            | TcpEvent::Send { connection, .. }
            | TcpEvent::Recv { connection, .. } => Some(connection),
            _ => None,
        }
    }
}

impl TcpEvent {
    pub fn get_payload(&mut self) -> Option<&mut Payload> {
        match self {
            TcpEvent::Send { payload, .. } | TcpEvent::Recv { payload, .. } => Some(payload),
            _ => None,
        }
    }
}

unsafe impl Sync for TcpEvent {}
unsafe impl Send for TcpEvent {}

pub enum PerfDataType {
    CONNECT = 0,
    SEND = 1,
    RECV = 2,
    CLOSE = 3,
}

impl Into<u32> for PerfDataType {
    fn into(self) -> u32 {
        self as u32
    }
}
