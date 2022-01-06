use libc as c;
use std::io::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, mem, ptr};

use rdma::*;

static RDMA_PORT: u8 = 168;
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

fn post_send(
    local_address: u64,
    size: u32,
    lkey: u32,
    remote_address: u64,
    rkey: u32,
    opcode: u32,
    queue_pair: QueuePair,
) -> i32 {
    let mut sge = rdmaffi::ibv_sge {
        addr: local_address,
        length: size,
        lkey: lkey,
    };

    let mut sw = rdmaffi::ibv_send_wr {
        wr_id: 0,
        next: ptr::null_mut(),
        sg_list: &mut sge,
        num_sge: 1,
        opcode: opcode,
        send_flags: rdmaffi::ibv_send_flags::IBV_SEND_SIGNALED.0,
        imm_data_invalidated_rkey_union: rdmaffi::imm_data_invalidated_rkey_union_t { imm_data: 0 }, //TODO: need double check
        qp_type: rdmaffi::qp_type_t {
            xrc: rdmaffi::xrc_t { remote_srqn: 0 },
        },
        wr: rdmaffi::wr_t {
            rdma: rdmaffi::rdma_t {
                //TODO: this is not needed when opcode is IBV_WR_SEND
                remote_addr: remote_address,
                rkey: rkey,
            },
        },
        bind_mw_tso_union: rdmaffi::bind_mw_tso_union_t {
            //TODO: need a better init solution
            tso: rdmaffi::tso_t {
                hdr: ptr::null_mut(),
                hdr_sz: 0,
                mss: 0,
            },
        },
    };

    let mut bad_wr: *mut rdmaffi::ibv_send_wr = ptr::null_mut();

    let rc = unsafe { rdmaffi::ibv_post_send(queue_pair, &mut sw, &mut bad_wr) };

    if rc != 0 {
        println!("failed to post SR\n");
    } else {
        if opcode == rdmaffi::ibv_wr_opcode::IBV_WR_SEND {
            println!("Send Request was posted");
        } else if opcode == rdmaffi::ibv_wr_opcode::IBV_WR_RDMA_READ {
            println!("RDMA Read Request was posted");
        } else if opcode == rdmaffi::ibv_wr_opcode::IBV_WR_RDMA_WRITE {
            println!("RDMA Write Request was posted");
        } else {
            println!("Unknown Request was posted");
        }
    }
    rc
}

fn post_receive(local_address: u64, size: u32, lkey: u32, queue_pair: QueuePair) -> i32 {
    let mut sge = rdmaffi::ibv_sge {
        addr: local_address,
        length: size,
        lkey: lkey,
    };

    let mut rw = rdmaffi::ibv_recv_wr {
        wr_id: 0,
        next: ptr::null_mut(),
        sg_list: &mut sge,
        num_sge: 1,
    };

    let mut bad_wr: *mut rdmaffi::ibv_recv_wr = ptr::null_mut();

    let rc = unsafe { rdmaffi::ibv_post_recv(queue_pair.0, &mut rw, &mut bad_wr) };

    if rc != 0 {
        println!("failed to post RR\n");
    } else {
        println!("Receive Request was posted\n");
    }

    rc
}

fn poll_completion(context: &RDMAContext) -> i32 {
    let mut wc = rdmaffi::ibv_wc {
        //TODO: find a better way to initialize
        wr_id: 0,
        status: rdmaffi::ibv_wc_status::IBV_WC_SUCCESS,
        opcode: rdmaffi::ibv_wc_opcode::IBV_WC_BIND_MW,
        vendor_err: 0,
        byte_len: 0,
        imm_data_invalidated_rkey_union: rdmaffi::imm_data_invalidated_rkey_union_t { imm_data: 0 }, //TODO: need double check
        qp_num: 0,
        src_qp: 0,
        wc_flags: 0,
        pkey_index: 0,
        slid: 0,
        sl: 0,
        dlid_path_bits: 0,
    };

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time Error")
        .as_millis();
    let mut poll_result = 0;
    loop {
        poll_result = unsafe { rdmaffi::ibv_poll_cq(context.lock().completion_queue, 1, &mut wc) };
        let cur_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time Error")
            .as_millis();
        if (poll_result != 0 || cur_time - start_time >= 2000) {
            break;
        }
    }

    let mut rc = 0;
    if poll_result < 0 {
        println!("poll CQ failed");
        rc = 1
    } else if poll_result == 0 {
        println!("completion wasn't found in the CQ after timeout")
    } else {
        println!("completion was found in CQ with status {}", wc.status);
        if (wc.status != rdmaffi::ibv_wc_status::IBV_WC_SUCCESS) {
            println!(
                "got bad completion with status: {}, vendor syndrome: {}",
                wc.status, wc.vendor_err
            );
            rc = 1
        }
    }

    rc
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

    let rdma_context = RDMAContext::default();
    rdma_context.Init("", RDMA_PORT);
    let queue_pair = rdma_context.CreateQueuePair().unwrap();
    let memory_region = rdma_context
        .CreateMemoryRegion(BUFFER.as_ptr() as u64, 256)
        .unwrap();

    let sock = sock_connect(&servername);
    let mut local_queue_pair_connect_info = QueuePairConnectInfo {
        qp_num: queue_pair.qpNum(),
        lid: rdma_context.Lid(),
        gid: rdma_context.Gid(),
        addr: BUFFER.as_ptr() as u64,
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
}
