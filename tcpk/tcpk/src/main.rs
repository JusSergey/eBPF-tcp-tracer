mod processor;

use aya::maps::{AsyncPerfEventArray, HashMap, MapData, PerfEventArray};
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use futures::FutureExt;
use log::{debug, info, warn};
use std::sync::{Arc, Mutex};
use tcpk_common::*;
use tokio::signal;
use crate::processor::Processor;


type CliResult<T> = Result<T, anyhow::Error>;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // libc::AF_INET

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcpk"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcpk"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    init_kprobe_program(&mut bpf, "program_sys_connect_entry", "__sys_connect")?;
    init_kprobe_program(&mut bpf, "program_sys_connect_exit", "__sys_connect")?;
    init_kprobe_program(&mut bpf, "program_sys_sendto_entry", "__sys_sendto")?;
    init_kprobe_program(&mut bpf, "program_sys_sendto_exit", "__sys_sendto")?;
    init_kprobe_program(&mut bpf, "program_sys_close_entry", "__x64_sys_close")?;

    let events: AsyncPerfEventArray<&mut MapData> =
        AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap()).unwrap();

    // Just to stop compiler complains
    let events: AsyncPerfEventArray<&'static mut MapData> = unsafe { core::mem::transmute(events) };


    info!("Waiting for Ctrl-C...");
    handle_events(events).await;
    info!("Exiting...");

    Ok(())
}

fn init_kprobe_program(
    bpf: &mut Bpf,
    program_name: &str,
    fn_name: &str,
) -> Result<(), anyhow::Error> {
    let program: &mut KProbe = bpf.program_mut(program_name).unwrap().try_into()?;
    program.load()?;
    program.attach(fn_name, 0)?;
    Ok(())
}

async fn handle_events(mut events: AsyncPerfEventArray<&'static mut MapData>) {
    let processor = Processor::new();
    // let storage: Arc<Mutex<std::collections::HashMap<u64, Vec<u8>>>> =
    //     Arc::new(Mutex::new(std::collections::HashMap::new()));
    let cpus = online_cpus().unwrap();
    let buffers_handlers = cpus
        .iter()
        .map(|cpu| events.open(*cpu, None).unwrap())
        .collect::<Vec<_>>();

    let mut futs = Vec::with_capacity(buffers_handlers.len());

    info!("START");
    let cpus_num = cpus.len();
    // let st = storage.clone();
    for mut bhandler in buffers_handlers {
        // let st = st.clone();
        let processor = processor.clone();
        futs.push(
            tokio::spawn(async move {
                info!("HANDLE EVENTS");
                let mut buffers = (0..cpus_num)
                    .into_iter()
                    .map(|_| BytesMut::with_capacity(core::mem::size_of::<TcpEvent>()))
                    .collect::<Vec<_>>();
                // let st = st.clone();
                loop {
                    tokio::select! {
                        res = bhandler.read_events(&mut buffers) => {
                            let events = res.unwrap();
                            info!("Read: {}, Lost: {}", events.read, events.lost);
                            // let st = st.clone();
                            for i in 0..events.read {
                                unsafe {
                                    let a = *(buffers[i].as_ptr() as *const TcpEvent);
                                    match &a {
                                        TcpEvent::Connect(connection) => {
                                            processor.process_connect(connection).await;
                                            // info!("Connection event {:?}", connection);
                                            // st.clone().lock().unwrap().insert(connection.id.tid, vec![]);
                                        },
                                        TcpEvent::Send{
                                            connection, payload
                                        } => {
                                            processor.process_send(connection, payload).await;
                                        }
                                        TcpEvent::Close(connection) => {
                                            processor.process_close(connection).await;
                                        }
                                        _ => {
                                            info!("Another TCP EVENT");
                                        }
                                    }
                                }
                            }
                        },
                        _ = signal::ctrl_c() => {
                            info!("ABORT HANDLE");
                            return;
                        }
                    }
                }
            })
            .boxed(),
        );
    }

    futures::future::join_all(futs).await;


}
