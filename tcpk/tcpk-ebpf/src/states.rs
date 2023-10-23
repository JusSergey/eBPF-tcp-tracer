use aya_bpf::macros::map;
use aya_bpf::maps::{HashMap, PerfEventArray, PerfEventByteArray};
use tcpk_common::TcpEvent;

/// The data pipe
#[map]
pub static EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

/// Memory to write the tcp-event data because they are too big to put on the stack.
#[map]
pub static TMP_TCP_EVENT: HashMap<u64, TcpEvent> = HashMap::with_max_entries(1024, 0);

pub static DUMMY_TCP_EVENT: TcpEvent = TcpEvent::Dummy;
