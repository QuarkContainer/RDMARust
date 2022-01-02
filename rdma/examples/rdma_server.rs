use c::c_void;
use libc as c;
use rdmaffi;
use std::env;
use std::io::Error;
use std::mem;
use std::ptr;

struct CMConData {
    addr: u64,     /* Buffer address */
    rkey: u32,     /* Remote key */
    qp_num: u32,   /* QP number */
    lid: u16,      /* LID of the IB port */
    gid: [u8; 16], /* gid */
}

impl Default for CMConData {
    fn default() -> CMConData {
        CMConData {
            addr: 0,
            rkey: 0,
            qp_num: 0,
            lid: 0,
            gid: [0; 16],
        }
    }
}

// a struct to wrap all resources related to rdma, similar as rdma_cm_id
struct RDMAContext<'a> {
    //device_attr: rdmaffi::ibv_device_attr,
    /* Device attributes */
    port_attr: rdmaffi::ibv_port_attr,     /* IB port attributes */
    remote_props: &'a mut CMConData,       /* values to connect to remote side */
    ib_context: *mut rdmaffi::ibv_context, /* device handle */
    protection_domain: *mut rdmaffi::ibv_pd, /* PD handle */
    io_completion_channel: *mut rdmaffi::ibv_comp_channel, /* io completion channel */
    completion_queue: *mut rdmaffi::ibv_cq, /* CQ handle */
    queue_pair: *mut rdmaffi::ibv_qp,      /* QP handle */
    memory_region: *mut rdmaffi::ibv_mr,   /* MR handle for buf */
    buffer: Vec<u32>,
    buffer_size: u32,
    sockfd: i32,
    ib_port: u8,
}

impl RDMAContext<'_> {
    pub fn new<'a>(server_name: &'a str, device_name: &'a str) -> RDMAContext<'a> {
        let mut device_number = 0i32;
        let device_list = unsafe { rdmaffi::ibv_get_device_list(&mut device_number as *mut _) };
        if device_list.is_null() {
            // TODO: clean up
            panic!("ibv_get_device_list failed: {}", Error::last_os_error());
        }

        println!("ibv_get_device_list succeeded");

        if (device_number == 0) {
            // TODO: clean up
            panic!("IB device is not found");
        }

        println!("Found {} IB devices", device_number);
        let devices = unsafe {
            use std::slice;
            slice::from_raw_parts_mut(device_list, device_number as usize)
        };
        let mut device = devices[0];

        if !device_name.is_empty() {
            let mut found_device = false;
            for i in 0..devices.len() {
                let cur_device_name = unsafe { rdmaffi::ibv_get_device_name(devices[i]) };
                let cur_device_name = unsafe { std::ffi::CStr::from_ptr(cur_device_name) };
                let cur_device_name = cur_device_name.to_str().unwrap();
                if device_name.eq(cur_device_name) {
                    device = devices[i];
                    found_device = true;
                    break;
                }
            }
            if !found_device {
                panic!("Could not found IB device with name: {}", device_name);
            }
        }

        let ibv_context = unsafe { rdmaffi::ibv_open_device(device) };
        if ibv_context.is_null() {
            panic!("Failed to open IB device");
        }

        println!("ibv_open_device succeeded");

        /* We are now done with device list, free it */
        unsafe { rdmaffi::ibv_free_device_list(device_list) };

        let mut port_attr = unsafe {
            rdmaffi::ibv_port_attr {
                state: rdmaffi::ibv_port_state::IBV_PORT_NOP,
                max_mtu: rdmaffi::ibv_mtu::IBV_MTU_1024,
                active_mtu: rdmaffi::ibv_mtu::IBV_MTU_1024,
                gid_tbl_len: 0,
                port_cap_flags: 0,
                max_msg_sz: 0,
                bad_pkey_cntr: 0,
                qkey_viol_cntr: 0,
                pkey_tbl_len: 0,
                lid: 0,
                sm_lid: 0,
                lmc: 0,
                max_vl_num: 0,
                sm_sl: 0,
                subnet_timeout: 0,
                init_type_reply: 0,
                active_width: 0,
                active_speed: 0,
                phys_state: 0,
                link_layer: 0,
                flags: 0,
                port_cap_flags2: 0,
            }
        };

        let ib_port = 20228;
        /* query port properties */
        if (unsafe { rdmaffi::___ibv_query_port(ibv_context, ib_port, &mut port_attr) } != 0) {
            // TODO: cleanup
            panic!("___ibv_query_port on port {} failed\n", ib_port);
        }

        println!("ibv_alloc_pd succeeded");

        let pd = unsafe { rdmaffi::ibv_alloc_pd(ibv_context) };
        if pd.is_null() {
            // TODO: cleanup
            panic!("ibv_alloc_pd failed\n");
        }
        println!("ibv_alloc_pd succeeded");

        let io_completion_channel = unsafe { rdmaffi::ibv_create_comp_channel(ibv_context) };
        if io_completion_channel.is_null() {
            // TODO: cleanup
            panic!("ibv_create_comp_channel failed\n");
        }
        println!("ibv_create_comp_channel succeeded");

        let cq = unsafe {
            rdmaffi::ibv_create_cq(ibv_context, 1, ptr::null_mut(), io_completion_channel, 0)
        };

        if cq.is_null() {
            // TODO: cleanup
            panic!("ibv_create_cq failed\n");
        }

        println!("ibv_create_cq succeeded");

        // create memory region
        // TODO: should confirm size difference between C and Rust
        let size = "Send operation ".len();
        let mut data = Vec::with_capacity(size);
        data.resize(size, u32::default());
        let access = rdmaffi::ibv_access_flags::IBV_ACCESS_LOCAL_WRITE
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_WRITE
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_READ
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC;
        let mr = unsafe {
            rdmaffi::ibv_reg_mr(
                pd,
                data.as_mut_ptr() as *mut _,
                size * mem::size_of::<u32>(),
                access.0 as i32,
            )
        };

        if mr.is_null() {
            // TODO: cleanup
            panic!("ibv_reg_mr failed: {}\n", Error::last_os_error());
        }

        //create queue pair
        let mut qp_init_attr = rdmaffi::ibv_qp_init_attr {
            // TODO: offset(0), may need find some different value
            qp_context: unsafe { ptr::null::<c_void>().offset(0) } as *mut _,
            send_cq: cq as *const _ as *mut _,
            recv_cq: cq as *const _ as *mut _,
            srq: ptr::null::<rdmaffi::ibv_srq>() as *mut _,
            cap: rdmaffi::ibv_qp_cap {
                max_send_wr: 1,
                max_recv_wr: 1,
                max_send_sge: 1,
                max_recv_sge: 1,
                max_inline_data: 0,
            },
            qp_type: rdmaffi::ibv_qp_type::IBV_QPT_RC,
            sq_sig_all: 0,
        };

        let qp = unsafe { rdmaffi::ibv_create_qp(pd, &mut qp_init_attr as *mut _) };
        if qp.is_null() {
            // TODO: cleanup
            panic!("ibv_create_qp failed: {}\n", Error::last_os_error());
        }

        let sockfd = sock_connect(server_name);

        RDMAContext {
            port_attr: port_attr,
            remote_props: &mut CMConData::default(),
            ib_context: ibv_context,
            protection_domain: pd,
            io_completion_channel: io_completion_channel,
            completion_queue: cq,
            queue_pair: qp,
            memory_region: mr,
            buffer: data,
            buffer_size: size as u32,
            sockfd: sockfd,
            ib_port: ib_port,
        }
    }
}

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
struct Gid {
    raw: [u8; 16],
}
impl Gid {
    /// Expose the subnet_prefix component of the `Gid` as a u64. This is
    /// equivalent to accessing the `global.subnet_prefix` component of the
    /// `rdmaffi::ibv_gid` union.
    #[allow(dead_code)]
    fn subnet_prefix(&self) -> u64 {
        u64::from_be_bytes(self.raw[..8].try_into().unwrap())
    }

    /// Expose the interface_id component of the `Gid` as a u64. This is
    /// equivalent to accessing the `global.interface_id` component of the
    /// `rdmaffi::ibv_gid` union.
    #[allow(dead_code)]
    fn interface_id(&self) -> u64 {
        u64::from_be_bytes(self.raw[8..].try_into().unwrap())
    }
}

impl From<rdmaffi::ibv_gid> for Gid {
    fn from(gid: rdmaffi::ibv_gid) -> Self {
        Self {
            raw: unsafe { gid.raw },
        }
    }
}

impl From<Gid> for rdmaffi::ibv_gid {
    fn from(mut gid: Gid) -> Self {
        *gid.as_mut()
    }
}

impl AsRef<rdmaffi::ibv_gid> for Gid {
    fn as_ref(&self) -> &rdmaffi::ibv_gid {
        unsafe { &*self.raw.as_ptr().cast::<rdmaffi::ibv_gid>() }
    }
}

impl AsMut<rdmaffi::ibv_gid> for Gid {
    fn as_mut(&mut self) -> &mut rdmaffi::ibv_gid {
        unsafe { &mut *self.raw.as_mut_ptr().cast::<rdmaffi::ibv_gid>() }
    }
}

fn modify_qp_to_init(context: &RDMAContext) -> i32 {
    let mut attr = rdmaffi::ibv_qp_attr {
        qp_state: rdmaffi::ibv_qp_state::IBV_QPS_INIT,
        cur_qp_state: rdmaffi::ibv_qp_state::IBV_QPS_INIT,
        path_mtu: rdmaffi::ibv_mtu::IBV_MTU_1024,
        path_mig_state: rdmaffi::ibv_mig_state::IBV_MIG_ARMED,
        qkey: 0,
        rq_psn: 0,
        sq_psn: 0,
        dest_qp_num: 0,
        qp_access_flags: 0,
        cap: rdmaffi::ibv_qp_cap {
            max_send_wr: 0,
            max_recv_wr: 0,
            max_send_sge: 0,
            max_recv_sge: 0,
            max_inline_data: 0,
        },
        ah_attr: rdmaffi::ibv_ah_attr {
            grh: rdmaffi::ibv_global_route {
                dgid: *Gid::default().as_mut(), //TODO: need recheck
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 0,
                traffic_class: 0,
            },
            dlid: 0,
            sl: 0,
            src_path_bits: 0,
            static_rate: 0,
            is_global: 0,
            port_num: 0,
        },
        alt_ah_attr: rdmaffi::ibv_ah_attr {
            grh: rdmaffi::ibv_global_route {
                dgid: *Gid::default().as_mut(), //TODO: need recheck
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 0,
                traffic_class: 0,
            },
            dlid: 0,
            sl: 0,
            src_path_bits: 0,
            static_rate: 0,
            is_global: 0,
            port_num: 0,
        },
        pkey_index: 0,
        alt_pkey_index: 0,
        en_sqd_async_notify: 0,
        sq_draining: 0,
        max_rd_atomic: 0,
        max_dest_rd_atomic: 0,
        min_rnr_timer: 0,
        port_num: 0,
        timeout: 0,
        retry_cnt: 0,
        rnr_retry: 0,
        alt_port_num: 0,
        alt_timeout: 0,
        rate_limit: 0,
    };

    let mut rc = 0;
    attr.qp_state = rdmaffi::ibv_qp_state::IBV_QPS_INIT;
    attr.port_num = context.ib_port;
    attr.pkey_index = 0;
    let qp_access_flags = rdmaffi::ibv_access_flags::IBV_ACCESS_LOCAL_WRITE
        | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_READ
        | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_WRITE;
    attr.qp_access_flags = qp_access_flags.0;
    let flags = rdmaffi::ibv_qp_attr_mask::IBV_QP_STATE
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_PKEY_INDEX
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_PORT
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS;
    rc = unsafe { rdmaffi::ibv_modify_qp(context.queue_pair, &mut attr, flags.0 as i32) };
    if rc != 0 {
        println!("failed to modify QP state to INIT");
    }

    return rc;
}

fn modify_qp_to_rtr(context: &RDMAContext, remote_qpn: u32, dlid: u16, dgid: Gid) -> i32 {
    let mut attr = rdmaffi::ibv_qp_attr {
        qp_state: rdmaffi::ibv_qp_state::IBV_QPS_INIT,
        cur_qp_state: rdmaffi::ibv_qp_state::IBV_QPS_INIT,
        path_mtu: rdmaffi::ibv_mtu::IBV_MTU_1024,
        path_mig_state: rdmaffi::ibv_mig_state::IBV_MIG_ARMED,
        qkey: 0,
        rq_psn: 0,
        sq_psn: 0,
        dest_qp_num: 0,
        qp_access_flags: 0,
        cap: rdmaffi::ibv_qp_cap {
            max_send_wr: 0,
            max_recv_wr: 0,
            max_send_sge: 0,
            max_recv_sge: 0,
            max_inline_data: 0,
        },
        ah_attr: rdmaffi::ibv_ah_attr {
            grh: rdmaffi::ibv_global_route {
                dgid: *Gid::default().as_mut(), //TODO: need recheck
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 0,
                traffic_class: 0,
            },
            dlid: 0,
            sl: 0,
            src_path_bits: 0,
            static_rate: 0,
            is_global: 0,
            port_num: 0,
        },
        alt_ah_attr: rdmaffi::ibv_ah_attr {
            grh: rdmaffi::ibv_global_route {
                dgid: *Gid::default().as_mut(), //TODO: need recheck
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 0,
                traffic_class: 0,
            },
            dlid: 0,
            sl: 0,
            src_path_bits: 0,
            static_rate: 0,
            is_global: 0,
            port_num: 0,
        },
        pkey_index: 0,
        alt_pkey_index: 0,
        en_sqd_async_notify: 0,
        sq_draining: 0,
        max_rd_atomic: 0,
        max_dest_rd_atomic: 0,
        min_rnr_timer: 0,
        port_num: 0,
        timeout: 0,
        retry_cnt: 0,
        rnr_retry: 0,
        alt_port_num: 0,
        alt_timeout: 0,
        rate_limit: 0,
    };

    let mut rc = 0;
    attr.qp_state = rdmaffi::ibv_qp_state::IBV_QPS_RTR;
    attr.path_mtu = rdmaffi::ibv_mtu::IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = context.ib_port;
    let gid_idx = 0;
    if (gid_idx >= 0) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        // memcpy (&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.dgid = rdmaffi::ibv_gid::from(dgid);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }

    let flags = rdmaffi::ibv_qp_attr_mask::IBV_QP_STATE
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_AV
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_PATH_MTU
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_DEST_QPN
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_RQ_PSN
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_MAX_DEST_RD_ATOMIC
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_MIN_RNR_TIMER;
    rc = unsafe { rdmaffi::ibv_modify_qp(context.queue_pair, &mut attr, flags.0 as i32) };
    if rc != 0 {
        println!("failed to modify QP state to RTR");
    }

    return rc;
}

fn modify_qp_to_rts(context: &RDMAContext) -> i32 {
    let mut attr = rdmaffi::ibv_qp_attr {
        qp_state: rdmaffi::ibv_qp_state::IBV_QPS_INIT,
        cur_qp_state: rdmaffi::ibv_qp_state::IBV_QPS_INIT,
        path_mtu: rdmaffi::ibv_mtu::IBV_MTU_1024,
        path_mig_state: rdmaffi::ibv_mig_state::IBV_MIG_ARMED,
        qkey: 0,
        rq_psn: 0,
        sq_psn: 0,
        dest_qp_num: 0,
        qp_access_flags: 0,
        cap: rdmaffi::ibv_qp_cap {
            max_send_wr: 0,
            max_recv_wr: 0,
            max_send_sge: 0,
            max_recv_sge: 0,
            max_inline_data: 0,
        },
        ah_attr: rdmaffi::ibv_ah_attr {
            grh: rdmaffi::ibv_global_route {
                dgid: *Gid::default().as_mut(), //TODO: need recheck
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 0,
                traffic_class: 0,
            },
            dlid: 0,
            sl: 0,
            src_path_bits: 0,
            static_rate: 0,
            is_global: 0,
            port_num: 0,
        },
        alt_ah_attr: rdmaffi::ibv_ah_attr {
            grh: rdmaffi::ibv_global_route {
                dgid: *Gid::default().as_mut(), //TODO: need recheck
                flow_label: 0,
                sgid_index: 0,
                hop_limit: 0,
                traffic_class: 0,
            },
            dlid: 0,
            sl: 0,
            src_path_bits: 0,
            static_rate: 0,
            is_global: 0,
            port_num: 0,
        },
        pkey_index: 0,
        alt_pkey_index: 0,
        en_sqd_async_notify: 0,
        sq_draining: 0,
        max_rd_atomic: 0,
        max_dest_rd_atomic: 0,
        min_rnr_timer: 0,
        port_num: 0,
        timeout: 0,
        retry_cnt: 0,
        rnr_retry: 0,
        alt_port_num: 0,
        alt_timeout: 0,
        rate_limit: 0,
    };

    let mut rc = 0;
    attr.qp_state = rdmaffi::ibv_qp_state::IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    let flags = rdmaffi::ibv_qp_attr_mask::IBV_QP_STATE
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_TIMEOUT
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_RETRY_CNT
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_RNR_RETRY
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_SQ_PSN
        | rdmaffi::ibv_qp_attr_mask::IBV_QP_MAX_QP_RD_ATOMIC;
    rc = unsafe { rdmaffi::ibv_modify_qp(context.queue_pair, &mut attr, flags.0 as i32) };
    if rc != 0 {
        println!("failed to modify QP state to RTS");
    }

    return rc;
}

fn connect_qp(context: &RDMAContext) -> i32 {
    let mut local_con_data = CMConData::default();
    let mut remote_con_data = CMConData::default();
    let mut tmp_con_data = CMConData::default();
    let mut rc = 0;
    let mut gid = Gid::default();
    let ok =
        unsafe { rdmaffi::ibv_query_gid(context.ib_context, context.ib_port, 0, gid.as_mut()) };
    if ok != 0 {
        // TODO: cleanup
        panic!("ibv_query_gid failed: {}\n", Error::last_os_error());
    }

    local_con_data.addr = &context.buffer as *const _ as u64;
    local_con_data.rkey = unsafe { (*(context.memory_region)).rkey };
    local_con_data.qp_num = unsafe { (*(context.queue_pair)).qp_num };
    local_con_data.lid = context.port_attr.lid;
    local_con_data.gid = gid.raw;

    rc = sock_sync_data(
        context.sockfd,
        std::mem::size_of::<CMConData>(),
        &mut local_con_data as *mut _ as *mut c_void,
        &mut tmp_con_data as *mut _ as *mut c_void,
    );

    if rc < 0 {
        println!("failed to exchange connection data between sides");
        rc = 1;
    }

    // TODO: should I call ntohll here?
    remote_con_data.addr = tmp_con_data.addr;
    *context.remote_props = remote_con_data;

    rc = modify_qp_to_init(context);

    if rc != 0 {
        println!("change QP state to INIT failed\n");
        return rc;
    }

    let is_client = false;
    if is_client {
        println!("TODO: do client stuff line 890")
    }

    /* modify the QP to RTR */
    rc = modify_qp_to_rtr(
        context,
        remote_con_data.qp_num,
        remote_con_data.lid,
        Gid {
            raw: remote_con_data.gid,
        },
    );
    if rc != 0 {
        println!("failed to modify QP state to RTR");
    }
    println!("Modified QP state to RTR");

    rc = modify_qp_to_rts(context);
    if rc != 0 {
        println!("failed to modify QP state to RTR");
    }
    println!("QP state was change to RTS\n");

    rc
}

fn post_send(context: &RDMAContext, opcode: i32) -> i32 {
    let mut sge = rdmaffi::ibv_sge {
        addr: &context.buffer as *const _ as u64,
        length: context.buffer_size,
        lkey: unsafe { (*(context.memory_region)).lkey },
    };

    //TODO: incomplete
    1
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

fn sock_connect(server_name: &str) -> i32 {
    unsafe {
        // let hints = libc::addrinfo {
        //     ai_flags: libc::AI_PASSIVE,
        //     ai_family: libc::AF_INET,
        //     ai_socktype: libc::SOCK_STREAM
        // };

        // libc::getaddrinfo(node, service, hints, res)
        let server_socket = c::socket(c::AF_INET, c::SOCK_STREAM, c::IPPROTO_TCP);
        if server_socket < 0 {
            panic!("last OS error: {:?}", Error::last_os_error());
        }

        let servaddr = c::sockaddr_in {
            sin_family: c::AF_INET as u16,
            sin_port: 20226u16.to_be(),
            sin_addr: c::in_addr {
                s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
            },
            sin_zero: mem::zeroed(),
        };

        let result = c::bind(
            server_socket,
            &servaddr as *const c::sockaddr_in as *const c::sockaddr,
            mem::size_of_val(&servaddr) as u32,
        );
        if result < 0 {
            c::close(server_socket);
            panic!("last OS error: {:?}", Error::last_os_error());
        }

        c::listen(server_socket, 128);
        let mut cliaddr: c::sockaddr_storage = mem::zeroed();
        let mut len = mem::size_of_val(&cliaddr) as u32;

        let client_socket = c::accept(
            server_socket,
            &mut cliaddr as *mut c::sockaddr_storage as *mut c::sockaddr,
            &mut len,
        );
        if client_socket < 0 {
            c::close(server_socket);
            panic!("last OS error: {:?}", Error::last_os_error());
        }

        client_socket
    }
}

fn main() {
    unsafe {
        println!("Hello rdma server.");
        let mut servername = String::new();
        let args: Vec<_> = env::args().collect();
        if args.len() > 1 {
            println!("The first argument is {}", args[1]);
            servername = args[1].clone();
        }

        println!("Server name is {}", servername.len());

        // create resources
        let sock: i32 = -1;
    }
}
