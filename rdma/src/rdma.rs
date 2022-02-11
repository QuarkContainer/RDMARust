use core::ops::Deref;
use rdmaffi::{self, ibv_cq};
//use std::error::Error;
use libc as c;
use spin::Mutex;
use std::convert::TryInto;
use std::io::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{ptr, thread};

//use super::super::super::qlib::common::*;

const O_NONBLOCK: u64 = 0x800;

#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Gid {
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

pub struct IBContext(pub *mut rdmaffi::ibv_context);

impl Drop for IBContext {
    fn drop(&mut self) {
        if self.0 as u64 != 0 {
            // to close ibv_context
        }
    }
}

impl Default for IBContext {
    fn default() -> Self {
        return Self(0 as _);
    }
}

impl IBContext {
    pub fn New(deviceName: &str) -> Self {
        // look for device
        let mut deviceNumber = 0;
        let device_list = unsafe { rdmaffi::ibv_get_device_list(&mut deviceNumber as *mut _) };
        if device_list.is_null() {
            // TODO: clean up
            panic!("ibv_get_device_list failed: {}", errno::errno().0);
        }

        if deviceNumber == 0 {
            // TODO: clean up
            panic!("IB device is not found");
        }

        let devices = unsafe {
            use std::slice;
            slice::from_raw_parts_mut(device_list, deviceNumber as usize)
        };

        let mut device = devices[0];

        if deviceName.len() != 0 {
            let mut found = false;

            for i in 0..devices.len() {
                let cur = unsafe { rdmaffi::ibv_get_device_name(devices[i]) };
                let cur = unsafe { std::ffi::CStr::from_ptr(cur) };
                let cur = cur.to_str().unwrap();
                if deviceName.eq(cur) {
                    device = devices[i];
                    found = true;
                    break;
                }
            }

            if !found {
                panic!("Could not found IB device with name: {}", deviceName);
            }
        }

        let context = unsafe { rdmaffi::ibv_open_device(device) };
        if context.is_null() {
            panic!("Failed to open IB device error");
        }

        let mut device_attr = rdmaffi::ibv_device_attr {
            fw_ver: [0; 64],
            node_guid: 0,
            sys_image_guid: 0,
            max_mr_size: 0,
            page_size_cap: 0,
            vendor_id: 0,
            vendor_part_id: 0,
            hw_ver: 0,
            max_qp: 0,
            max_qp_wr: 0,
            device_cap_flags: 0,
            max_sge: 0,
            max_sge_rd: 0,
            max_cq: 0,
            max_cqe: 0,
            max_mr: 0,
            max_pd: 0,
            max_qp_rd_atom: 0,
            max_ee_init_rd_atom: 0,
            max_res_rd_atom: 0,
            max_ee_rd_atom: 0,
            max_qp_init_rd_atom: 0,
            atomic_cap: 0,
            max_ee: 0,
            max_rdd: 0,
            max_mw: 0,
            max_raw_ipv6_qp: 0,
            max_raw_ethy_qp: 0,
            max_mcast_grp: 0,
            max_mcast_qp_attach: 0,
            max_total_mcast_qp_attach: 0,
            max_ah: 0,
            max_fmr: 0,
            max_map_per_fmr: 0,
            max_srq: 0,
            max_srq_sge: 0,
            max_srq_wr: 0,
            max_pkeys: 0,
            local_ca_ack_delay: 0,
            phys_port_cnt: 0,
        };

        unsafe { rdmaffi::ibv_query_device(context, &mut device_attr) };

        println!("device attr: max_qp: {}", device_attr.max_qp);

        //info!("ibv_open_device succeeded");
        /* We are now done with device list, free it */
        unsafe { rdmaffi::ibv_free_device_list(device_list) };

        return Self(context);
    }

    pub fn QueryPort(&self, ibPort: u8) -> PortAttr {
        let mut port_attr = rdmaffi::ibv_port_attr {
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
        };

        /* query port properties */
        if unsafe { rdmaffi::___ibv_query_port(self.0, ibPort, &mut port_attr) } != 0 {
            // TODO: cleanup
            panic!(
                "___ibv_query_port on port {} failed, last os error: {}",
                ibPort,
                Error::last_os_error()
            );
        }

        return PortAttr(port_attr);
    }

    pub fn AllocProtectionDomain(&self) -> ProtectionDomain {
        let pd = unsafe { rdmaffi::ibv_alloc_pd(self.0) };
        if pd.is_null() {
            // TODO: cleanup
            panic!("ibv_alloc_pd failed\n");
        }

        return ProtectionDomain(pd);
    }

    pub fn CreateCompleteChannel(&self) -> CompleteChannel {
        let completionChannel = unsafe { rdmaffi::ibv_create_comp_channel(self.0) };
        if completionChannel.is_null() {
            // TODO: cleanup
            panic!("ibv_create_comp_channel failed\n");
        }

        let fd = unsafe { (*completionChannel).fd };

        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        return CompleteChannel(completionChannel);
    }

    pub fn CreateCompleteQueue(&self, cc: &CompleteChannel) -> CompleteQueue {
        let cq = unsafe { rdmaffi::ibv_create_cq(self.0, 1, ptr::null_mut(), cc.0, 0) };

        if cq.is_null() {
            // TODO: cleanup
            panic!("ibv_create_cq failed\n");
        }

        unsafe {
            rdmaffi::ibv_req_notify_cq(
                cq, /* on which CQ */
                0,  /* 0 = all event type, no filter*/
            );
        }

        return CompleteQueue(cq);
    }

    pub fn QueryGid(&self, ibPort: u8) -> Gid {
        let mut gid = Gid::default();
        let ok = unsafe { rdmaffi::ibv_query_gid(self.0, ibPort, 0, gid.as_mut()) };

        if ok != 0 {
            panic!("ibv_query_gid failed: {}\n", errno::errno().0);
        }

        return gid;
    }
}

pub struct PortAttr(pub rdmaffi::ibv_port_attr);
impl Deref for PortAttr {
    type Target = rdmaffi::ibv_port_attr;

    fn deref(&self) -> &rdmaffi::ibv_port_attr {
        &self.0
    }
}

impl Default for PortAttr {
    fn default() -> Self {
        let attr = rdmaffi::ibv_port_attr {
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
        };

        return Self(attr);
    }
}

pub struct ProtectionDomain(pub *mut rdmaffi::ibv_pd);

impl Drop for ProtectionDomain {
    fn drop(&mut self) {}
}

impl Default for ProtectionDomain {
    fn default() -> Self {
        return Self(0 as _);
    }
}

pub struct CompleteChannel(pub *mut rdmaffi::ibv_comp_channel);
impl Drop for CompleteChannel {
    fn drop(&mut self) {}
}

impl Default for CompleteChannel {
    fn default() -> Self {
        return Self(0 as _);
    }
}

pub struct CompleteQueue(pub *mut rdmaffi::ibv_cq);
impl Drop for CompleteQueue {
    fn drop(&mut self) {}
}

impl Default for CompleteQueue {
    fn default() -> Self {
        return Self(0 as _);
    }
}

#[derive(Default)]
pub struct RDMAContextIntern {
    //device_attr: rdmaffi::ibv_device_attr,
    /* Device attributes */
    portAttr: PortAttr,               /* IB port attributes */
    ibContext: IBContext,             /* device handle */
    protectDomain: ProtectionDomain,  /* PD handle */
    completeChannel: CompleteChannel, /* io completion channel */
    completeQueue: CompleteQueue,     /* CQ handle */
    ccfd: i32,
    ibPort: u8,
    gid: Gid,
}

impl RDMAContextIntern {
    pub fn New(deviceName: &str, ibPort: u8) -> Self {
        let ibContext = IBContext::New(deviceName);
        let portAttr = ibContext.QueryPort(ibPort);
        let protectDomain = ibContext.AllocProtectionDomain();
        let completeChannel = ibContext.CreateCompleteChannel();
        let completeQueue = ibContext.CreateCompleteQueue(&completeChannel);
        let ccfd = unsafe { (*completeChannel.0).fd };
        let gid = ibContext.QueryGid(ibPort);

        // unsafe {
        //     unsafe {
        //         let flags = c::fcntl(ccfd, c::F_GETFL, 0);
        //         let ret = c::fcntl(ccfd, c::F_SETFL, flags | O_NONBLOCK);
        //         assert!(ret == 0, "UnblockFd fail");
        //     }
        // }

        return Self {
            portAttr: portAttr,
            ibContext: ibContext,
            protectDomain: protectDomain,
            completeChannel: completeChannel,
            completeQueue: completeQueue,
            ccfd: ccfd,
            ibPort: ibPort,
            gid: gid,
        };
    }
}

#[derive(Default)]
pub struct RDMAContext(Mutex<RDMAContextIntern>);

unsafe impl Send for RDMAContext {}
unsafe impl Sync for RDMAContext {}

impl Deref for RDMAContext {
    type Target = Mutex<RDMAContextIntern>;

    fn deref(&self) -> &Mutex<RDMAContextIntern> {
        &self.0
    }
}

pub const MAX_SEND_WR: u32 = 1;
pub const MAX_RECV_WR: u32 = 1;
pub const MAX_SEND_SGE: u32 = 1;
pub const MAX_RECV_SGE: u32 = 1;

impl RDMAContext {
    pub fn Init(&self, deviceName: &str, ibPort: u8) {
        *self.0.lock() = RDMAContextIntern::New(deviceName, ibPort);
    }

    pub fn Lid(&self) -> u16 {
        let context = self.lock();
        return context.portAttr.0.lid;
    }

    pub fn Gid(&self) -> Gid {
        let context = self.lock();
        return context.gid;
    }

    pub fn CreateQueuePair(&self) -> Result<QueuePair, Error> {
        let context = self.lock();
        //create queue pair
        let mut qp_init_attr = rdmaffi::ibv_qp_init_attr {
            // TODO: offset(0), may need find some different value
            qp_context: 0 as *mut _,
            send_cq: context.completeQueue.0 as *const _ as *mut _,
            recv_cq: context.completeQueue.0 as *const _ as *mut _,
            srq: ptr::null::<rdmaffi::ibv_srq>() as *mut _,
            cap: rdmaffi::ibv_qp_cap {
                max_send_wr: MAX_SEND_WR,
                max_recv_wr: MAX_RECV_WR,
                max_send_sge: MAX_SEND_SGE,
                max_recv_sge: MAX_RECV_SGE,
                max_inline_data: 0,
            },
            qp_type: rdmaffi::ibv_qp_type::IBV_QPT_RC,
            sq_sig_all: 0,
        };

        let qp =
            unsafe { rdmaffi::ibv_create_qp(context.protectDomain.0, &mut qp_init_attr as *mut _) };
        if qp.is_null() {
            return Err(Error::last_os_error());
        }

        return Ok(QueuePair(Mutex::new(qp)));
    }

    pub fn CCFd(&self) -> i32 {
        let context = self.lock();
        return context.ccfd;
    }

    pub fn CreateMemoryRegion(&self, addr: u64, size: usize) -> Result<MemoryRegion, Error> {
        let context = self.lock();
        let access = rdmaffi::ibv_access_flags::IBV_ACCESS_LOCAL_WRITE
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_WRITE
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_READ
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_ATOMIC;

        println!("addr is {}", addr);
        let mr = unsafe {
            rdmaffi::ibv_reg_mr(
                context.protectDomain.0,
                addr as *mut _,
                size,
                access.0 as i32,
            )
        };

        if mr.is_null() {
            return Err(Error::last_os_error());
        }

        return Ok(MemoryRegion(mr));
    }

    pub fn CompleteQueue(&self) -> *mut rdmaffi::ibv_cq {
        return self.lock().completeQueue.0;
    }

    pub fn CompleteChannel(&self) -> *mut rdmaffi::ibv_comp_channel {
        return self.lock().completeChannel.0;
    }

    pub fn PollCompletion(&self) -> i32 {
        let mut wc = rdmaffi::ibv_wc {
            //TODO: find a better way to initialize
            wr_id: 0,
            status: rdmaffi::ibv_wc_status::IBV_WC_SUCCESS,
            opcode: rdmaffi::ibv_wc_opcode::IBV_WC_BIND_MW,
            vendor_err: 0,
            byte_len: 0,
            imm_data_invalidated_rkey_union: rdmaffi::imm_data_invalidated_rkey_union_t {
                imm_data: 0,
            }, //TODO: need double check
            qp_num: 0,
            src_qp: 0,
            wc_flags: 0,
            pkey_index: 0,
            slid: 0,
            sl: 0,
            dlid_path_bits: 0,
        };

        loop {
            let mut cq_ptr: *mut rdmaffi::ibv_cq = ptr::null_mut();
            let mut cq_context: *mut std::os::raw::c_void = ptr::null_mut();
            let mut ret = unsafe {
                rdmaffi::ibv_get_cq_event(
                    self.CompleteChannel(),
                    &mut cq_ptr, //&mut self.CompleteQueue(),
                    &mut cq_context,
                )
            };
            if ret == -1 {
                break;
            }
            println!("get completion event ****");
            //TODO: potnetial improvemnt to ack in batch
            unsafe { rdmaffi::ibv_ack_cq_events(cq_ptr, 1) };

            ret = unsafe { rdmaffi::ibv_req_notify_cq(cq_ptr, 0) };
            if ret != 0 {
                // TODO: should keep call here?
                println!("Couldn't request CQ notification\n");
            }

            loop {
                let poll_result = unsafe { rdmaffi::ibv_poll_cq(self.CompleteQueue(), 1, &mut wc) };
                if poll_result > 0 {
                    println!("Got WC {}!", wc.wr_id);
                    self.ProcessWC(&wc);
                } else if poll_result == 0 {
                    println!("No WC!");
                    let sleep_duration = Duration::from_secs(1);
                    thread::sleep(sleep_duration);
                    break;
                } else {
                    println!("Error to query CQ!")
                    // break;
                }
            }
        }
        1
    }

    pub fn poll_completion(&self) -> i32 {
        let mut wc = rdmaffi::ibv_wc {
            //TODO: find a better way to initialize
            wr_id: 0,
            status: rdmaffi::ibv_wc_status::IBV_WC_SUCCESS,
            opcode: rdmaffi::ibv_wc_opcode::IBV_WC_BIND_MW,
            vendor_err: 0,
            byte_len: 0,
            imm_data_invalidated_rkey_union: rdmaffi::imm_data_invalidated_rkey_union_t {
                imm_data: 0,
            }, //TODO: need double check
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
            poll_result = unsafe { rdmaffi::ibv_poll_cq(self.CompleteQueue(), 1, &mut wc) };
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

    // call back for
    pub fn ProcessWC(&self, wc: &rdmaffi::ibv_wc) {
        println!("work request ID is {}", wc.wr_id);
        println!("opcode is {}", wc.opcode);

        println!("Imm is {}", unsafe {
            wc.imm_data_invalidated_rkey_union.imm_data
        });

        println!("Byte len is {}", wc.byte_len);

        // let wrid = WorkRequestId(wc.wr_id);
        // let fd = wrid.Fd();
        // let typ = wrid.Type();

        // match typ {
        //     WorkRequestType::WriteImm => {
        //         println!("WriteImm: write bytes {}", wc.byte_len);
        //         //IO_MGR.ProcessRDMAWriteImmFinish(fd, wc.byte_len as _);
        //     }
        //     WorkRequestType::Recv => {
        //         let imm = unsafe { wc.imm_data_invalidated_rkey_union.imm_data };
        //         let immData = ImmData(imm);
        //         println!("immData read count: {}, write count: {}", immData.ReadCount(), immData.WriteCount());
        //         // IO_MGR.ProcessRDMARecvWriteImm(
        //         //     fd,
        //         //     immData.ReadCount() as _,
        //         //     immData.WriteCount() as _,
        //         // );
        //         println!("Receive Imm");
        //     }
        // }
    }
}

pub struct ImmData(pub u32);

impl ImmData {
    pub fn New(writeCount: u16, readCount: u16) -> Self {
        return Self(((writeCount as u32) << 16) | (readCount as u32));
    }

    pub fn ReadCount(&self) -> u16 {
        return (self.0 & 0xffff) as u16;
    }

    pub fn WriteCount(&self) -> u16 {
        return ((self.0 >> 16) & 0xffff) as u16;
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[repr(u32)]
pub enum WorkRequestType {
    WriteImm,
    Recv,
}

pub struct WorkRequestId(pub u64);

impl WorkRequestId {
    pub fn New(fd: i32, typ: WorkRequestType) -> Self {
        return Self(((fd as u64) << 32) | (typ as u32 as u64));
    }

    pub fn Fd(&self) -> i32 {
        ((self.0 >> 32) & 0xffff_ffff) as i32
    }

    pub fn Type(&self) -> WorkRequestType {
        let val = self.0 & 0xffff_ffff;
        if val == 0 {
            return WorkRequestType::WriteImm;
        } else {
            assert!(val == 1);
            return WorkRequestType::Recv;
        }
    }
}
pub struct QueuePair(pub Mutex<*mut rdmaffi::ibv_qp>);

unsafe impl Send for QueuePair {}
unsafe impl Sync for QueuePair {}

impl Drop for QueuePair {
    fn drop(&mut self) {}
}

impl QueuePair {
    pub fn Data(&self) -> *mut rdmaffi::ibv_qp {
        return *self.0.lock();
    }

    pub fn qpNum(&self) -> u32 {
        return unsafe { (*self.Data()).qp_num };
    }

    pub fn WriteImm(
        &self,
        wrId: u64,
        laddr: u64,
        len: u32,
        lkey: u32,
        raddr: u64,
        rkey: u32,
        imm: u32,
    ) -> i32 {
        let opcode = rdmaffi::ibv_wr_opcode::IBV_WR_RDMA_WRITE_WITH_IMM;
        let mut sge = rdmaffi::ibv_sge {
            addr: laddr,
            length: len,
            lkey: lkey,
        };

        let mut sw = rdmaffi::ibv_send_wr {
            wr_id: wrId,
            next: ptr::null_mut(),
            sg_list: &mut sge,
            num_sge: 1,
            opcode: opcode,
            send_flags: rdmaffi::ibv_send_flags::IBV_SEND_SIGNALED.0,
            imm_data_invalidated_rkey_union: rdmaffi::imm_data_invalidated_rkey_union_t {
                imm_data: imm,
            }, //TODO: need double check
            qp_type: rdmaffi::qp_type_t {
                xrc: rdmaffi::xrc_t { remote_srqn: 0 },
            },
            wr: rdmaffi::wr_t {
                rdma: rdmaffi::rdma_t {
                    //TODO: this is not needed when opcode is IBV_WR_SEND
                    remote_addr: raddr,
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

        let rc = unsafe { rdmaffi::ibv_post_send(self.Data(), &mut sw, &mut bad_wr) };

        rc
    }

    pub fn PostRecv(&self, wrId: u64) -> i32 {
        let mut rw = rdmaffi::ibv_recv_wr {
            wr_id: wrId,
            next: ptr::null_mut(),
            sg_list: ptr::null_mut(),
            num_sge: 1,
        };

        let mut bad_wr: *mut rdmaffi::ibv_recv_wr = ptr::null_mut();
        let rc = unsafe { rdmaffi::ibv_post_recv(self.Data(), &mut rw, &mut bad_wr) };

        println!(
            "ibv_post_recv failed: last os error: {}",
            Error::last_os_error()
        );

        rc
    }

    pub fn Setup(&self, context: &RDMAContext, remote_qpn: u32, dlid: u16, dgid: Gid) -> i32 {
        self.ToInit(context);
        self.ToRtr(context, remote_qpn, dlid, dgid);
        self.ToRts();
        0
    }

    pub fn ToInit(&self, context: &RDMAContext) -> i32 {
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

        attr.qp_state = rdmaffi::ibv_qp_state::IBV_QPS_INIT;
        attr.port_num = context.lock().ibPort;
        attr.pkey_index = 0;
        let qp_access_flags = rdmaffi::ibv_access_flags::IBV_ACCESS_LOCAL_WRITE
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_READ
            | rdmaffi::ibv_access_flags::IBV_ACCESS_REMOTE_WRITE;
        attr.qp_access_flags = qp_access_flags.0;
        let flags = rdmaffi::ibv_qp_attr_mask::IBV_QP_STATE
            | rdmaffi::ibv_qp_attr_mask::IBV_QP_PKEY_INDEX
            | rdmaffi::ibv_qp_attr_mask::IBV_QP_PORT
            | rdmaffi::ibv_qp_attr_mask::IBV_QP_ACCESS_FLAGS;
        let rc = unsafe { rdmaffi::ibv_modify_qp(self.Data(), &mut attr, flags.0 as i32) };
        // if rc != 0 {
        //     return Err(Error::SysError(errno::errno().0));
        // }

        rc
    }

    pub fn ToRtr(&self, context: &RDMAContext, remote_qpn: u32, dlid: u16, dgid: Gid) -> i32 {
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
        attr.ah_attr.port_num = context.lock().ibPort;
        let gid_idx = 0;

        // todo: configure with Qingqu
        //if gid_idx >= 0 {
        {
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
        let rc = unsafe { rdmaffi::ibv_modify_qp(self.Data(), &mut attr, flags.0 as i32) };
        rc
    }

    pub fn ToRts(&self) -> i32 {
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
        let rc = unsafe { rdmaffi::ibv_modify_qp(self.Data(), &mut attr, flags.0 as i32) };

        rc
    }

    pub fn post_send(
        &self,
        local_address: u64,
        size: u32,
        lkey: u32,
        remote_address: u64,
        rkey: u32,
        opcode: u32,
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
            imm_data_invalidated_rkey_union: rdmaffi::imm_data_invalidated_rkey_union_t {
                imm_data: 0,
            }, //TODO: need double check
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

        let rc = unsafe { rdmaffi::ibv_post_send(self.Data(), &mut sw, &mut bad_wr) };

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

    pub fn post_receive(&self, wr_id: u64, local_address: u64, size: u32, lkey: u32) -> i32 {
        let mut sge = rdmaffi::ibv_sge {
            addr: local_address,
            length: size,
            lkey: lkey,
        };

        let mut rw = rdmaffi::ibv_recv_wr {
            wr_id: wr_id,
            next: ptr::null_mut(),
            sg_list: &mut sge,
            num_sge: 1,
        };

        let mut bad_wr: *mut rdmaffi::ibv_recv_wr = ptr::null_mut();

        let rc = unsafe { rdmaffi::ibv_post_recv(self.Data(), &mut rw, &mut bad_wr) };

        if rc != 0 {
            println!("failed to post RR\n");
        } else {
            println!("Receive Request was posted\n");
        }

        rc
    }
}

pub struct MemoryRegion(pub *mut rdmaffi::ibv_mr);
impl Drop for MemoryRegion {
    fn drop(&mut self) {}
}

impl MemoryRegion {
    pub fn LKey(&self) -> u32 {
        return unsafe { (*self.0).lkey };
    }

    pub fn RKey(&self) -> u32 {
        return unsafe { (*self.0).rkey };
    }
}

unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}
