mod processor;

use crate::processor::Processor;
use aya::maps::{AsyncPerfEventArray, MapData};
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use futures::FutureExt;
use log::{debug, info, warn};
use tcpk_common::*;
use tokio::signal;

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
    init_kprobe_program(&mut bpf, "program_sys_sendto_entry", "__sys_sendto")?;
    init_kprobe_program(&mut bpf, "program_sys_sendto_exit", "__sys_sendto")?;
    init_kprobe_program(&mut bpf, "program_sys_close_entry", "__x64_sys_close")?;
    init_kprobe_program(&mut bpf, "program_sys_recvfrom_entry", "__sys_recvfrom")?;
    init_kprobe_program(&mut bpf, "program_sys_recvfrom_exit", "__sys_recvfrom")?;

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
    let cpus = online_cpus().unwrap();
    let buffers_handlers = cpus
        .iter()
        .map(|cpu| events.open(*cpu, None).unwrap())
        .collect::<Vec<_>>();

    let mut futs = Vec::with_capacity(buffers_handlers.len());

    let cpus_num = cpus.len();
    for mut bhandler in buffers_handlers {
        let processor = processor.clone();
        futs.push(
            tokio::spawn(async move {
                let mut buffers = (0..cpus_num)
                    .into_iter()
                    .map(|_| BytesMut::with_capacity(core::mem::size_of::<TcpEvent>()))
                    .collect::<Vec<_>>();
                loop {
                    tokio::select! {
                        res = bhandler.read_events(&mut buffers) => {
                            let events = res.unwrap();
                            info!("Read: {}, Lost: {}", events.read, events.lost);
                            for i in 0..events.read {
                                unsafe {
                                    let a = *(buffers[i].as_ptr() as *const TcpEvent);
                                    match &a {
                                        TcpEvent::Connect(connection) => {
                                            processor.process_connect(connection).await;
                                        },
                                        TcpEvent::Send{
                                            connection, payload
                                        } => {
                                            processor.process_send(connection, payload).await;
                                        }
                                        TcpEvent::Recv{
                                            connection, payload
                                        } => {
                                            processor.process_recv(connection, payload).await;
                                        }
                                        TcpEvent::Close(connection) => {
                                            processor.process_close(connection).await;
                                        }
                                        _ => {
                                            unreachable!("Another TCP EVENT");
                                        }
                                    }
                                }
                            }
                        },
                        _ = signal::ctrl_c() => {
                            info!("Aborting...");
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
