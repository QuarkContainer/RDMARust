use std::env;

mod rdma;
use rdma::*;

static RDMA_PORT: u8 = 20882;

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
        let is_client = !servername.is_empty();

        let rdma_context = RDMAContext::default();
        rdma_context.Init("", RDMA_PORT);
    }
}
