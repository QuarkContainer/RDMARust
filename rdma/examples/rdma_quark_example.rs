use libc as c;
use rdmaffi::rdma_destroy_ep;
use std::io::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, mem, ptr};

use rdma::*;

static RDMA_PORT: u8 = 1;
static SOCK_PORT: u16 = 20226;
static BUFFER: [u8; 256] = [0; 256];
static BUFFER_SIZE: u16 = 256;

fn sock_connect(server_name: &str) -> i32 {
    unsafe {
        let socket = c::socket(c::AF_INET, c::SOCK_STREAM, c::IPPROTO_TCP);
        if socket < 0 {
            panic!("last OS error: {:?}", Error::last_os_error());
        }

        let mut client_socket = socket;

        let servaddr = c::sockaddr_in {
            sin_family: c::AF_INET as u16,
            sin_port: SOCK_PORT,
            sin_addr: c::in_addr {
                s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
            },
            sin_zero: mem::zeroed(),
        };

        if server_name.is_empty() {
            let result = c::bind(
                socket,
                &servaddr as *const c::sockaddr_in as *const c::sockaddr,
                mem::size_of_val(&servaddr) as u32,
            );
            if result < 0 {
                c::close(socket);
                panic!("last OS error: {:?}", Error::last_os_error());
            }

            c::listen(socket, 128);
            let mut cliaddr: c::sockaddr_storage = mem::zeroed();
            let mut len = mem::size_of_val(&cliaddr) as u32;

            client_socket = c::accept(
                socket,
                &mut cliaddr as *mut c::sockaddr_storage as *mut c::sockaddr,
                &mut len,
            );
            if client_socket < 0 {
                c::close(socket);
                panic!("last OS error: {:?}", Error::last_os_error());
            }
        } else {
            if c::connect(
                socket,
                &servaddr as *const c::sockaddr_in as *const c::sockaddr,
                mem::size_of_val(&servaddr) as u32,
            ) < 0
            {
                println!("last OS error: {:?}", Error::last_os_error());
                c::close(socket);
            }
        }

        client_socket
    }
}

// use socket to sync data.
fn sock_sync_data(
    mut sock: libc::c_int,
    mut xfer_size: libc::size_t,
    mut local_data: *mut libc::c_void,
    mut remote_data: *mut libc::c_void,
) -> libc::c_int {
    let mut rc: i32 = 0;
    let mut read_bytes: i32 = 0;
    let mut total_read_bytes: i32 = 0;
    rc = unsafe { libc::write(sock, local_data, xfer_size) as i32 };
    if !(rc < xfer_size as i32) {
        rc = 0;
    }
    while rc == 0 && total_read_bytes < xfer_size as i32 {
        read_bytes = unsafe { libc::read(sock, remote_data, xfer_size) as i32 };
        if read_bytes > 0 as libc::c_int {
            total_read_bytes += read_bytes
        } else {
            rc = read_bytes
        }
    }
    return rc;
}

#[derive(Default)]
struct QueuePairConnectInfo {
    qp_num: u32,
    lid: u16,
    gid: Gid,
    addr: u64,
    rkey: u32,
}

fn main() {
    println!("Hello rdma server.");
    let mut servername = String::new();
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        println!("The first argument is {}", args[1]);
        servername = args[1].clone();
    }

    println!("Server name is {}", servername.len());

    // create resources
    let is_client = !servername.is_empty();
    //socket_test(&servername);
    rdma(&servername);
}

fn socket_test(server_name: &str) -> i32 {
    let mut local_queue_pair_connect_info = QueuePairConnectInfo {
        qp_num: 1,
        lid: 2,
        gid: Gid::default(),
        addr: 4,
        rkey: 5,
    };

    let mut remote_queue_pair_connect_info = QueuePairConnectInfo::default();
    let sock = sock_connect(&server_name);

    sock_sync_data(
        sock,
        mem::size_of::<QueuePairConnectInfo>(),
        &mut local_queue_pair_connect_info as *mut _ as *mut c::c_void,
        &mut remote_queue_pair_connect_info as *mut _ as *mut c::c_void,
    );
    println!(
        "remote_queue_pair! qp_num: {}, lid: {}, addr: {}, rkey: {}",
        local_queue_pair_connect_info.qp_num,
        local_queue_pair_connect_info.lid,
        local_queue_pair_connect_info.addr,
        local_queue_pair_connect_info.rkey
    );
    unsafe { c::close(sock) };
    1
}

fn rdma(server_name: &str) {
    let sock = sock_connect(&server_name);
    let rdma_context = RDMAContext::default();
    rdma_context.Init("", RDMA_PORT);
    let queue_pair = rdma_context.CreateQueuePair().unwrap();

    // let memory_region = rdma_context
    //     .CreateMemoryRegion(BUFFER.as_ptr() as u64, 256)
    //     .unwrap();

    let n = 256;
    let mut data = Vec::with_capacity(n);
    data.resize(n, u32::default());
    if server_name.is_empty() {
        data[0] = 101;
        data[1] = 102;
        data[2] = 103;
        data[3] = 104;
    }
    let memory_region = rdma_context
        .CreateMemoryRegion(data.as_mut_ptr() as *mut _ as u64, 256)
        .unwrap();

    // let mut local_queue_pair_connect_info = QueuePairConnectInfo {
    //     qp_num: queue_pair.qpNum(),
    //     lid: rdma_context.Lid(),
    //     gid: rdma_context.Gid(),
    //     addr: BUFFER.as_ptr() as u64,
    //     rkey: memory_region.RKey(),
    // };

    let mut local_queue_pair_connect_info = QueuePairConnectInfo {
        qp_num: queue_pair.qpNum(),
        lid: rdma_context.Lid(),
        gid: rdma_context.Gid(),
        addr: data.as_mut_ptr() as *mut _ as u64,
        rkey: memory_region.RKey(),
    };

    let mut remote_queue_pair_connect_info = QueuePairConnectInfo::default();
    sock_sync_data(
        sock,
        mem::size_of::<QueuePairConnectInfo>(),
        &mut local_queue_pair_connect_info as *mut _ as *mut c::c_void,
        &mut remote_queue_pair_connect_info as *mut _ as *mut c::c_void,
    );

    queue_pair.ToInit(&rdma_context);
    queue_pair.ToRtr(
        &rdma_context,
        remote_queue_pair_connect_info.qp_num,
        remote_queue_pair_connect_info.lid,
        remote_queue_pair_connect_info.gid,
    );

    queue_pair.ToRts();
    if !server_name.is_empty() {
        println!(
            "Before RDMA_READ: vec 0: {}, 1: {}, 2: {}, 3: {}",
            data[0], data[1], data[2], data[3]
        );
        queue_pair.post_send(
            local_queue_pair_connect_info.addr,
            16,
            local_queue_pair_connect_info.rkey,
            remote_queue_pair_connect_info.addr,
            remote_queue_pair_connect_info.rkey,
            rdmaffi::ibv_wr_opcode::IBV_WR_RDMA_READ,
        );

        rdma_context.poll_completion();
        println!(
            "After RDMA_READ: vec 0: {}, 1: {}, 2: {}, 3: {}",
            data[0], data[1], data[2], data[3]
        );

        data[0] = 11;
        data[1] = 12;
        data[2] = 13;
        data[3] = 14;

        queue_pair.post_send(
            local_queue_pair_connect_info.addr,
            16,
            local_queue_pair_connect_info.rkey,
            remote_queue_pair_connect_info.addr,
            remote_queue_pair_connect_info.rkey,
            rdmaffi::ibv_wr_opcode::IBV_WR_RDMA_WRITE,
        );

        rdma_context.poll_completion();
    }

    sock_sync_data(
        sock,
        mem::size_of::<QueuePairConnectInfo>(),
        &mut local_queue_pair_connect_info as *mut _ as *mut c::c_void,
        &mut remote_queue_pair_connect_info as *mut _ as *mut c::c_void,
    );

    if server_name.is_empty() {
        println!(
            "After RDMA_WRITE: vec 0: {}, 1: {}, 2: {}, 3: {}",
            data[0], data[1], data[2], data[3]
        );
    }
}
