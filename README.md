# rloris

`rloris` is an implementation of RSnake's SlowLoris attack, along with some other attacks, in Rust.
Currently it only supports SlowLoris in a single thread.

### Examples

* Perform an attack in plaintext against localhost: `rloris localhost`
* Perform an attack against localhost, port 8000: `rloris localhost --port=8000`
* Perform an SSL attack against example.com, port 443: `rloris example.com --ssl`
* Perform an SSL attack against 127.0.0.1, with domain name example.com: `rloris 127.0.0.1 --ssl --domain=example.com`
* Perform a repeated attack against localhost: `rloris localhost --repeat`
* Perform a parallelized attack against localhost: `rloris localhost --threads 4`