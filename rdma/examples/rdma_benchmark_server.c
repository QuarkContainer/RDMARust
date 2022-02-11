#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/types.h>
#include <infiniband/verbs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define IPADDRESS   "127.0.0.1"
#define PORT        8787
#define MAXSIZE     1024
#define LISTENQ     5
#define FDSIZE      1000
#define EPOLLEVENTS 100

#define BUFFERNUM 10000

#define MAX_POLL_CQ_TIMEOUT 2000
#define MSG "SEND operation "
#define RDMAMSGR "RDMA read operation "
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE (strlen(MSG) + 1)
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t
htonll (uint64_t x)
{
    return bswap_64 (x);
}

static inline uint64_t
ntohll (uint64_t x)
{
    return bswap_64 (x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN

static inline uint64_t
htonll (uint64_t x)
{
    return x;
}

static inline uint64_t
ntohll (uint64_t x)
{
    return x;
}
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

struct cm_con_data_t
{
    uint64_t addr;                /* Buffer address */
    uint32_t rkey;                /* Remote key */
    uint32_t qp_num;              /* QP number */
    uint16_t lid;                 /* LID of the IB port */
    uint8_t gid[16];              /* gid */
} __attribute__ ((packed));

struct resources
{
    struct ibv_device_attr device_attr;
    /* Device attributes */
    struct ibv_port_attr port_attr;       /* IB port attributes */
    struct ibv_context *ib_ctx;   /* device handle */
    struct ibv_pd *pd;            /* PD handle */
    struct queuepair **qps;
    struct ibv_cq *cq;            /* CQ handle */
    int sock;                     /* TCP socket file descriptor */
    int server_fd;
};

struct queuepair
{
    struct ibv_qp *qp;            /* QP handle */
    struct ibv_mr *mr;            /* MR handle for buf */
    char *buf;                    /* memory buffer pointer, used for RDMA and send
                                     ops */
    struct cm_con_data_t remote_props;    /* values to connect to remote side */
};

struct config_t
{
    const char *dev_name;         /* IB device name */
    char *server_name;            /* server host name */
    u_int32_t tcp_port;           /* server TCP port */
    int ib_port;                  /* local IB port to work with */
    int gid_idx;                  /* gid index to use */
    long long buffer_size;
    long long count;
    int log;
    int wrnum; //work request number
    int connectionnum; //connection number
};

struct config_t config = {
    NULL,                         /* dev_name */
    NULL,                         /* server_name */
    19875,                        /* tcp_port */
    1,                            /* ib_port */
    0,                            /* gid_idx */
    32768, //buffer size
    10000,  //count
    0, //log
    1, //wrnum
    1, //connectionnum
};

static int
sock_connect (int port, struct resources *res)
{
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(port);

    // Creating socket file descriptor 
    int server_fd;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 

    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    printf("bind successfully\n");
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 

    printf("listen successfully on port: %d\n", port);

    int socketfd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (socketfd < 0)
    {
        printf("error when accept\n");
        return;
    }
    printf("new connection is accepted, socketfd is: %d\n", socketfd);
    res->server_fd = server_fd;    

    return socketfd;
}

/******************************************************************************
 * Function: modify_qp_to_init
 *
 * Input
 * qp QP to transition
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, ibv_modify_qp failure code on failure
 *
 * Description
 * Transition a QP from the RESET to INIT state
 ******************************************************************************/
static int
modify_qp_to_init (struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset (&attr, 0, sizeof (attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = config.ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
        IBV_ACCESS_REMOTE_WRITE;
    flags =
        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    rc = ibv_modify_qp (qp, &attr, flags);
    if (rc)
        fprintf (stderr, "failed to modify QP state to INIT\n");
    return rc;
}

/******************************************************************************
 * Function: modify_qp_to_rtr
 *
 * Input
 * qp QP to transition
 * remote_qpn remote QP number
 * dlid destination LID
 * dgid destination GID (mandatory for RoCEE)
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, ibv_modify_qp failure code on failure
 *
 * Description
 * Transition a QP from the INIT to RTR state, using the specified QP number
 ******************************************************************************/
static int
modify_qp_to_rtr (struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid,
        uint8_t * dgid)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset (&attr, 0, sizeof (attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = config.ib_port;
    if (config.gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy (&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = config.gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }
    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
        IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    rc = ibv_modify_qp (qp, &attr, flags);
    if (rc)
        fprintf (stderr, "failed to modify QP state to RTR\n");
    return rc;
}

/******************************************************************************
 * Function: modify_qp_to_rts
 *
 * Input
 * qp QP to transition
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, ibv_modify_qp failure code on failure
 *
 * Description
 * Transition a QP from the RTR to RTS state
 ******************************************************************************/
static int
modify_qp_to_rts (struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset (&attr, 0, sizeof (attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    rc = ibv_modify_qp (qp, &attr, flags);
    if (rc)
        fprintf (stderr, "failed to modify QP state to RTS\n");
    return rc;
}


int
sock_sync_data (int sock, int xfer_size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;
    rc = write (sock, local_data, xfer_size);
    if (rc < xfer_size)
        fprintf (stderr, "Failed writing data during sock_sync_data\n");
    else
        rc = 0;
    while (!rc && total_read_bytes < xfer_size)
    {
        read_bytes = read (sock, remote_data, xfer_size);
        if (read_bytes > 0)
            total_read_bytes += read_bytes;
        else
            rc = read_bytes;
    }
    return rc;
}

static void
resources_init (struct resources *res)
{
    memset (res, 0, sizeof *res);
    res->sock = -1;
}

static int
resources_create (struct resources *res)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;
    size_t size;
    int i;
    int mr_flags = 0;
    int cq_size = 0;
    int num_devices;
    int rc = 0;
    /* if client side */
    if (config.server_name)
    {
        res->sock = sock_connect (config.tcp_port, res);
        if (res->sock < 0)
        {
            fprintf (stderr,
                    "failed to establish TCP connection to server %s, port %d\n",
                    config.server_name, config.tcp_port);
            rc = -1;
            goto resources_create_exit;
        }
    }
    else
    {
        fprintf (stdout, "waiting on port %d for TCP connection\n",
                config.tcp_port);
        res->sock = sock_connect (config.tcp_port, res);
        if (res->sock < 0)
        {
            fprintf (stderr,
                    "failed to establish TCP connection with client on port %d\n",
                    config.tcp_port);
            rc = -1;
            goto resources_create_exit;
        }
    }
    fprintf (stdout, "TCP connection was established\n");
    fprintf (stdout, "searching for IB devices in host\n");
    /* get device names in the system */
    dev_list = ibv_get_device_list (&num_devices);
    if (!dev_list)
    {
        fprintf (stderr, "failed to get IB devices list\n");
        rc = 1;
        goto resources_create_exit;
    }
    /* if there isn't any IB device in host */
    if (!num_devices)
    {
        fprintf (stderr, "found %d device(s)\n", num_devices);
        rc = 1;
        goto resources_create_exit;
    }
    fprintf (stdout, "found %d device(s)\n", num_devices);
    
    ib_dev = dev_list[0];

    /* if the device wasn't found in host */
    if (!ib_dev)
    {
        fprintf (stderr, "IB device %s wasn't found\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }
    /* get device handle */
    res->ib_ctx = ibv_open_device (ib_dev);
    if (!res->ib_ctx)
    {
        fprintf (stderr, "failed to open device %s\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }
    /* We are now done with device list, free it */
    ibv_free_device_list (dev_list);
    dev_list = NULL;
    ib_dev = NULL;
    /* query port properties */
    if (ibv_query_port (res->ib_ctx, config.ib_port, &res->port_attr))
    {
        fprintf (stderr, "ibv_query_port on port %u failed\n", config.ib_port);
        rc = 1;
        goto resources_create_exit;
    }
    /* allocate Protection Domain */
    res->pd = ibv_alloc_pd (res->ib_ctx);
    if (!res->pd)
    {
        fprintf (stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    cq_size = 1000; //QQ: CQSize
    res->cq = ibv_create_cq (res->ib_ctx, cq_size, NULL, NULL, 0); //QQ: use polling first
    if (!res->cq)
    {
        fprintf (stderr, "failed to create CQ with %u entries\n", cq_size);
        rc = 1;
        goto resources_create_exit;
    }
    /* each side will send only one WR, so Completion Queue with 1 entry is enough */
    res->qps = malloc(sizeof(struct queuepair*) * config.connectionnum);

    //QQ: create queue pair
    for (int i=0; i<config.connectionnum; i++)
    {
        struct queuepair *qp = malloc(sizeof(struct queuepair));
        memset(qp, 0, sizeof(struct queuepair));
        
        /* allocate the memory buffer that will hold the data */
        size = config.buffer_size;
        qp->buf = (char *) malloc (size);
        if (!qp->buf)
        {
            fprintf (stderr, "failed to malloc %Zu bytes to memory buffer\n", size);
            rc = 1;
            goto resources_create_exit;
        }
        
        /* only in the server side put the message in the memory buffer */
        if (!config.server_name)
        {
            for (int i = 0; i < size; i ++)
            {
                qp->buf[i] = 'A' + random() % 26;
            }
        }
        else
        {
            memset (qp->buf, 0, size);
        }

        /* register the memory buffer */
        mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
            IBV_ACCESS_REMOTE_WRITE;
        qp->mr = ibv_reg_mr (res->pd, qp->buf, size, mr_flags);
        if (!qp->mr)
        {
            fprintf (stderr, "ibv_reg_mr failed with mr_flags=0x%x\n", mr_flags);
            rc = 1;
            goto resources_create_exit;
        }
        fprintf (stdout,
                "MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n",
                qp->buf, qp->mr->lkey, qp->mr->rkey, mr_flags);
        /* create the Queue Pair */
        memset (&qp_init_attr, 0, sizeof (qp_init_attr));
        qp_init_attr.qp_type = IBV_QPT_RC;
        qp_init_attr.sq_sig_all = 1;
        qp_init_attr.send_cq = res->cq;
        qp_init_attr.recv_cq = res->cq;
        qp_init_attr.cap.max_send_wr = 8192; //qq: SWR
        qp_init_attr.cap.max_recv_wr = 8192;
        qp_init_attr.cap.max_send_sge = 1;
        qp_init_attr.cap.max_recv_sge = 1;
        qp->qp = ibv_create_qp (res->pd, &qp_init_attr);
        if (!qp->qp)
        {
            fprintf (stderr, "failed to create QP\n");
            rc = 1;
            goto resources_create_exit;
        }
        fprintf (stdout, "QP was created, QP number=0x%x\n", qp->qp->qp_num);
        res->qps[i] = qp;
    }
    
resources_create_exit:
    if (rc)
    {
        /* Error encountered, cleanup */
        // if (res->qp)
        // {
        //     ibv_destroy_qp (res->qp);
        //     res->qp = NULL;
        // }
        // if (res->mr)
        // {
        //     ibv_dereg_mr (res->mr);
        //     res->mr = NULL;
        // }
        // if (res->buf)
        // {
        //     free (res->buf);
        //     res->buf = NULL;
        // }
        // if (res->cq)
        // {
        //     ibv_destroy_cq (res->cq);
        //     res->cq = NULL;
        // }
        // if (res->pd)
        // {
        //     ibv_dealloc_pd (res->pd);
        //     res->pd = NULL;
        // }
        // if (res->ib_ctx)
        // {
        //     ibv_close_device (res->ib_ctx);
        //     res->ib_ctx = NULL;
        // }
        // if (dev_list)
        // {
        //     ibv_free_device_list (dev_list);
        //     dev_list = NULL;
        // }
        // if (res->sock >= 0)
        // {
        //     if (close (res->sock))
        //         fprintf (stderr, "failed to close socket\n");
        //     res->sock = -1;
        // }
        printf("resources_create_exit\n");
    }
    return rc;
}

static int
post_send (struct resources *res, int opcode, unsigned int len, unsigned int wrid, int qpindex)
{
    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;
    int rc;
    /* prepare the scatter/gather entry */
    memset (&sge, 0, sizeof (sge));
    struct queuepair *qp = res->qps[qpindex];
    sge.addr = (uintptr_t) qp->buf;
    sge.length = len;
    sge.lkey = qp->mr->lkey;
    /* prepare the send work request */
    memset (&sr, 0, sizeof (sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = opcode;
    sr.send_flags = IBV_SEND_SIGNALED;
    if (opcode != IBV_WR_SEND)
    {
        sr.wr.rdma.remote_addr = qp->remote_props.addr;
        sr.wr.rdma.rkey = qp->remote_props.rkey;
    }

    if (opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
    {
        sr.imm_data = len; //qq: temp data.
    }
    /* there is a Receive Request in the responder side, so we won't get any into RNR flow */
    rc = ibv_post_send (qp->qp, &sr, &bad_wr);
    if (rc)
        fprintf (stderr, "failed to post SR\n");
    else
    {
        if (config.log)
        {
            switch (opcode)
            {
                case IBV_WR_SEND:
                    fprintf (stdout, "Send Request was posted\n");
                    break;
                case IBV_WR_RDMA_READ:
                    fprintf (stdout, "RDMA Read Request was posted\n");
                    break;
                case IBV_WR_RDMA_WRITE:
                    fprintf (stdout, "RDMA Write Request was posted\n");
                    break;
                case IBV_WR_RDMA_WRITE_WITH_IMM:

                    fprintf (stdout, "RDMA Write with IMM Request was posted\n");
                    break;
                default:
                    fprintf (stdout, "Unknown Request was posted\n");
                    break;
            }

        }
        
    }
    return rc;
}

/******************************************************************************
 * Function: post_receive
 *
 * Input
 * res pointer to resources structure
 *
 * Output
 * none
 *
 * Returns
 * 0 on success, error code on failure
 *
 * Description
 *
 ******************************************************************************/
static int
post_receive (struct resources *res, int qpindex)
{
    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;
    int rc;
    /* prepare the scatter/gather entry */
    memset (&sge, 0, sizeof (sge));
    struct queuepair *qp = res->qps[qpindex];
    sge.addr = (uintptr_t) qp->buf;
    sge.length = MSG_SIZE;
    sge.lkey = qp->mr->lkey;
    /* prepare the receive work request */
    memset (&rr, 0, sizeof (rr));
    rr.next = NULL;
    rr.wr_id = qpindex;
    rr.sg_list = &sge;
    rr.num_sge = 1;
    /* post the Receive Request to the RQ */
    rc = ibv_post_recv (qp->qp, &rr, &bad_wr);
    if (rc)
        fprintf (stderr, "failed to post RR\n");
    else
    {
        if (config.log)
        {
            fprintf (stdout, "Receive Request was posted\n");
        }
    }
        
    return rc;
}

static int
connect_qp (struct resources *res, int qpindex)
{
    struct queuepair *qp = res->qps[qpindex];
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    int rc = 0;
    char temp_char;
    union ibv_gid my_gid;
    if (config.gid_idx >= 0)
    {
        rc =
            ibv_query_gid (res->ib_ctx, config.ib_port, config.gid_idx, &my_gid);
        if (rc)
        {
            fprintf (stderr, "could not get gid for port %d, index %d\n",
                    config.ib_port, config.gid_idx);
            return rc;
        }
    }
    else
        memset (&my_gid, 0, sizeof my_gid);
    /* exchange using TCP sockets info required to connect QPs */
    local_con_data.addr = htonll ((uintptr_t) qp->buf);
    local_con_data.rkey = htonl (qp->mr->rkey);
    local_con_data.qp_num = htonl (qp->qp->qp_num);
    local_con_data.lid = htons (res->port_attr.lid);
    memcpy (local_con_data.gid, &my_gid, 16);
    fprintf (stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);
    if (sock_sync_data
            (res->sock, sizeof (struct cm_con_data_t), (char *) &local_con_data,
             (char *) &tmp_con_data) < 0)
    {
        fprintf (stderr, "failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }
    remote_con_data.addr = ntohll (tmp_con_data.addr);
    remote_con_data.rkey = ntohl (tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl (tmp_con_data.qp_num);
    remote_con_data.lid = ntohs (tmp_con_data.lid);
    memcpy (remote_con_data.gid, tmp_con_data.gid, 16);
    /* save the remote side attributes, we will need it for the post SR */
    qp->remote_props = remote_con_data;
    fprintf (stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
    fprintf (stdout, "Remote rkey = 0x%x\n", remote_con_data.rkey);
    fprintf (stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
    fprintf (stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    if (config.gid_idx >= 0)
    {
        uint8_t *p = remote_con_data.gid;
        fprintf (stdout,
                "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
                p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    if (qp->qp == NULL)
    {
        printf("connect_qp 1");
    }
    /* modify the QP to init */
    rc = modify_qp_to_init (qp->qp);
    if (rc)
    {
        fprintf (stderr, "change QP state to INIT failed\n");
        goto connect_qp_exit;
    }

    /* modify the QP to RTR */
    rc =
        modify_qp_to_rtr (qp->qp, remote_con_data.qp_num, remote_con_data.lid,
                remote_con_data.gid);
    if (rc)
    {
        fprintf (stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }
    fprintf (stderr, "Modified QP state to RTR\n");
    rc = modify_qp_to_rts (qp->qp);
    if (rc)
    {
        fprintf (stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }
    fprintf (stdout, "QP state was change to RTS\n");
    /* sync to make sure that both sides are in states that they can connect to prevent packet loose */
    if (sock_sync_data (res->sock, 1, "Q", &temp_char))   /* just send a dummy char back and forth */
    {
        fprintf (stderr, "sync error after QPs are were moved to RTS\n");
        rc = 1;
    }
connect_qp_exit:
    return rc;
}

static int
resources_destroy (struct resources *res)
{
    int rc = 0;
    for (int i=0; i<config.connectionnum; i++)
    {
        struct queuepair *qp = res->qps[i];
        if (qp->qp)
            if (ibv_destroy_qp (qp->qp))
            {
                fprintf (stderr, "failed to destroy QP\n");
                rc = 1;
            }
        if (qp->mr)
            if (ibv_dereg_mr (qp->mr))
            {
                fprintf (stderr, "failed to deregister MR\n");
                rc = 1;
            }
        if (qp->buf)
            free (qp->buf);
    }

    if (res->cq)
    if (ibv_destroy_cq (res->cq))
    {
        fprintf (stderr, "failed to destroy CQ\n");
        rc = 1;
    }

    free(res->qps);
    
    if (res->pd)
        if (ibv_dealloc_pd (res->pd))
        {
            fprintf (stderr, "failed to deallocate PD\n");
            rc = 1;
        }
    if (res->ib_ctx)
        if (ibv_close_device (res->ib_ctx))
        {
            fprintf (stderr, "failed to close device context\n");
            rc = 1;
        }
    if (res->sock >= 0)
        if (close (res->sock))
        {
            fprintf (stderr, "failed to close socket\n");
            rc = 1;
        }
    if (res->server_fd >= 0)
    {
        if (close (res->server_fd))
        {
            fprintf (stderr, "failed to close server socket\n");
            rc = 1;
        }
    }
    return rc;
}

static int
poll_completion (struct resources *res, int qpindex)
{
    struct ibv_wc wc;
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    int poll_result;
    int rc = 0;
    /* poll the completion for a while before giving up of doing it .. */
    // gettimeofday (&cur_time, NULL);
    // start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    struct queuepair *qp = res->qps[qpindex];
    // do
    // {
    //     poll_result = ibv_poll_cq (res->cq, 1, &wc);
    //     gettimeofday (&cur_time, NULL);
    //     cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    // }
    // while ((poll_result == 0)
    //         && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));
    poll_result = ibv_poll_cq (res->cq, 1, &wc);
    if (poll_result < 0)
    {
        /* poll CQ failed */
        fprintf (stderr, "poll CQ failed\n");
        rc = 1;
    }
    else if (poll_result == 0)
    {
        /* the CQ is empty */
        if (config.log)
        {
            fprintf (stderr, "completion wasn't found in the CQ after timeout\n");
        }
        
        rc = 2;
    }
    else
    {
        /* CQE found */
        if (config.log)
        {
            fprintf (stdout, "completion was found in CQ with status 0x%x\n",
                wc.status);
        }
        
        /* check the completion status (here we don't care about the completion opcode */
        if (wc.status != IBV_WC_SUCCESS)
        {
            fprintf (stderr,
                    "got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",
                    wc.status, wc.vendor_err);
            rc = 1;
        }

        if (config.log)
        {
            printf("byte len: %d\n", wc.byte_len);
        }
    }
    return rc;
}

struct wc_res
{
    int byte_len;
    int wr_id;
};

static struct wc_res
poll_completion_loop (struct resources *res)
{
    struct ibv_wc wc;
    struct wc_res wcres = {
        0,
        -1
    };
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    int poll_result;
    int rc = 0;
    /* poll the completion for a while before giving up of doing it .. */
    gettimeofday (&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    do
    {
        poll_result = ibv_poll_cq (res->cq, 1, &wc);
        gettimeofday (&cur_time, NULL);
        cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    }
    while ((poll_result == 0)
            && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));
    if (poll_result < 0)
    {
        /* poll CQ failed */
        fprintf (stderr, "poll CQ failed\n");
        rc = -1;
    }
    else if (poll_result == 0)
    {
        /* the CQ is empty */
        fprintf (stderr, "completion wasn't found in the CQ after timeout\n");
        rc = -1;
    }
    else
    {
        if (config.log)
        {
            /* CQE found */
            fprintf (stdout, "completion was found in CQ with status 0x%x\n",
                    wc.status);
        }
        
        /* check the completion status (here we don't care about the completion opcode */
        if (wc.status != IBV_WC_SUCCESS)
        {
            fprintf (stderr,
                    "got bad completion with status: 0x%x, vendor syndrome: 0x%x\n",
                    wc.status, wc.vendor_err);
            rc = -1;
        }

        rc = 1;

        if (config.log)
        {
            printf("receive content length: %d\n", wc.byte_len);
            printf("Imm: %d\n", wc.imm_data);
        }
        
    }
    if (rc == -1)
    {
        return wcres;
    }
    else{
        wcres.byte_len = wc.byte_len;
        wcres.wr_id = wc.wr_id;
        return wcres;
    }
}


int main(int argc,char *argv[])
{
    // parse command line arguments
    int server_fd, new_socket, valread; 
    
    char *hello = "Hello from server";

    long long writeCount = 1000000;
    if (argc >= 2)
    {
        writeCount = atoi(argv[1]);
    }
    printf("writeCount: %lld\n", writeCount);
    config.count = writeCount;

    int buffernum = BUFFERNUM;
    if (argc >= 3)
    {
        buffernum = atoi(argv[2]);
    }
    printf("buffer len is %d\n", buffernum);
    config.buffer_size = buffernum;
    
    int connectionNum = 1;
    
    if (argc >= 4)
    {
        connectionNum = atoi(argv[3]);
    }
    printf("connection num is %d\n", connectionNum);
    config.connectionnum = connectionNum;
    
    if (argc >= 5)
    {
        config.wrnum = atoi(argv[4]);
    }
    printf("wrnum is %d\n", config.wrnum);

    config.tcp_port = PORT;
    if (argc >= 6)
    {
        config.tcp_port = atoi(argv[5]);
    }
    printf("sin_port is %d\n", config.tcp_port);

    int log = 0;
    if (argc >= 7)
    {
        log = strcmp(argv[6], "log") == 0 ? 1 : 0;
    }
    printf("log is %d\n", log);
    config.log = log;

    struct resources res;
    int rc = 1;
    char temp_char;

    resources_init (&res);
    /* create resources before using them */
    if (resources_create (&res))
    {
        fprintf (stderr, "failed to create resources\n");
        goto main_exit;
    }
    /* connect the QPs */
    for (int i=0; i<config.connectionnum; i++)
    {
        if (connect_qp (&res, i))
        {
            fprintf (stderr, "failed to connect QPs\n");
            goto main_exit;
        }
    }
    
    /* Sync so we are sure server side has data ready before client tries to read it */
    if (sock_sync_data (res.sock, 1, "R", &temp_char))    /* just send a dummy char back and forth */
    {
        fprintf (stderr, "sync error before RDMA ops 1\n");
        rc = 1;
        goto main_exit;
    }

    if (sock_sync_data (res.sock, 1, "R", &temp_char))    /* just send a dummy char back and forth */
    {
        fprintf (stderr, "sync error before RDMA ops 2\n");
        rc = 1;
        goto main_exit;
    }

    long long totalrecvbytes = 0;
    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    long long bytes = config.count * config.buffer_size;
    long long totalwritebytes = 0;
    for (int qpi=0; qpi<config.connectionnum; qpi++)
    {
        for (int i=0; i < config.wrnum; i++)
        {
            //if (post_send (&res, IBV_WR_RDMA_WRITE_WITH_IMM, config.buffer_size, 0, qpi))
            if (post_send (&res, IBV_WR_RDMA_WRITE, config.buffer_size, 0, qpi))
            {
                fprintf (stderr, "failed to post SR 3\n");
                rc = 1;
                goto main_exit;
            }

            if (config.log)
            {
                printf("pre insert write imm work request");
            }
        }

    }

    while (1)
    {
        struct wc_res wcres = poll_completion_loop (&res);
        if (wcres.wr_id == -1)
        {
            fprintf (stderr, "poll completion failed 3\n");
            rc = 1;
            goto main_exit;
        }

        totalwritebytes += config.buffer_size;
        if (totalwritebytes >= bytes) {
            break;
        }

        //if (post_send (&res, IBV_WR_RDMA_WRITE_WITH_IMM, config.buffer_size, 0, wcres.wr_id))
        if (post_send (&res, IBV_WR_RDMA_WRITE, config.buffer_size, 0, wcres.wr_id))
        {
            fprintf (stderr, "failed to post SR 3\n");
            rc = 1;
            goto main_exit;
        }
     }

    clock_gettime(CLOCK_MONOTONIC, &tend);
    double ws = (double)(tend.tv_sec - tstart.tv_sec) * 1.0e6 + (double)(tend.tv_nsec - tstart.tv_nsec)/1.0e3;
    printf("time used: %lf\n", ws);
    //double speed = ((double)buffernum * (double)readCount) / (ns);
    printf("recv bytes: %lld\n", totalwritebytes);
    double speed = ((double)totalwritebytes) / (ws);
    printf("speed is %lf\n", speed);
    

    // if (sock_sync_data (res.sock, 1, "W", &temp_char))    /* just send a dummy char back and forth */
    // {
    //     fprintf (stderr, "sync error after RDMA ops\n");
    //     rc = 1;
    //     goto main_exit;
    // }

main_exit:
    sleep(1); //dummy wait
    if (resources_destroy (&res))
    {
        fprintf (stderr, "failed to destroy resources\n");
        rc = 1;
    }
    if (config.dev_name)
        free ((char *) config.dev_name);
    fprintf (stdout, "\ntest result is %d\n", rc);
    return rc;
}