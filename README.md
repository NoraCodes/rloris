# rloris

`rloris` is an implementation of RSnake's SlowLoris attack and the SlowRead attack in Rust, with other attacks on the way.

You can download the source code and build it - you'll need: 
* the OpenSSL or LibreSSL dev headers
* a working Rust compiler, stable/beta/nightly all work
* `pkg-config`

You can also download a working binary for Linux x64 from the [releases directory](https://github.com/SilverWingedSeraph/rloris/releases).

## Attacks

* SlowLoris GET, based on [RSnake's original attack](https://web.archive.org/web/20090822001255/http://ha.ckers.org/slowloris/), simply opens a lot of connections
    asking to GET resources and then takes its time sending the other headers and the final double `\r\n`.
* SlowLoris POST, similar to the above but using POST requests. Activate with `rloris loris <target> --post`.
* SlowRead, which connects to the server and tries to read bytes slowly, tying up a connection (depending on the underlying OS).

## Functionality

Optional functionality is available by giving flags to the `rloris` binary. Currently, `rloris` supports SSL (`-ssl`), 
setting custom timeouts for SlowLoris and SlowRead (`--timeout=<timeout>`) and SlowLoris cycle counts (`--cycle=<cycles>`),
multithreading (`--thread=<threads>`), and infinite repetition (`--repeat`). 

WARNING: using `--repeat` can create a real honest to goodness DoS condition on the target!

## Advice

The more threads you can get away with, the higher the impact on the target. To see what your server can handle, 
keep raising the number of threads until you get "Connection reset by peer" errors; at that point, your server is dropping connections due to over-load.
Note that a DoS condition probably will arise before this happens.

`rloris` uses `env_logger` to log messages to the console; set the environment variable `RUST_LOG` to `info` for additional data about your attacks, or `debug` if you're 
hacking on the code.

### Examples

* Perform an attack against localhost, port 8000, using the POST verb: `rloris loris localhost --port=8000 --post`
* Perform an SSL attack against example.com, port 443: `rloris loris example.com --ssl`
* Perform an SSL attack against 127.0.0.1, with domain name example.com: `rloris loris 127.0.0.1 --ssl --domain=example.com --repeat`
* Perform a parallelized SlowRead attack against localhost, trying for 1000 connections: `rloris read localhost --threads 1000`