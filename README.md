# v6synth-dns

A DNS forwarder which attempts to synthesise AAAA records for websites that use a
dual-stacked CDN.

The synthesis of AAAA occurs in a script (check it out [here](./config/scripts)).

Inspired by https://gitlab.com/miyurusankalpa/IPv6-dns-server.

## Building

```
cargo build --release
```

The binary is located inside `./target/release/`.

## Running

Assuming your configuration TOML is located at `./config/named.toml`,
the root directory of your zones is `./config/`, and you want the server
to listen on port 15353:

```bash
./hickory-dns-v6synth -c ./config/named.toml -z ./config/ -p 15353
```

Available CLI arguments:

```
Options:
  -q, --quiet                    Disable INFO messages, WARN and ERROR will remain
  -d, --debug                    Turn on `DEBUG` messages (default is only `INFO`)
  -c, --config <NAME>            Path to configuration file of named server, by default `/etc/named.toml` [default: /etc/named.toml]
  -z, --zonedir <DIR>            Path to the root directory for all zone files, see also config toml
  -s, --scriptdir <DIR>          Path to the root directory for all script files. By default it points to the scripts directory in zonedir
  -p, --port <PORT>              Listening port for DNS queries, overrides any value in config file
      --tls-port <TLS-PORT>      Listening port for DNS over TLS queries, overrides any value in config file
      --https-port <HTTPS-PORT>  Listening port for DNS over HTTPS queries, overrides any value in config file
      --quic-port <QUIC-PORT>    Listening port for DNS over QUIC queries, overrides any value in config file
  -h, --help                     Print help
  -V, --version                  Print version
```

## Writing a script

The scripting language used by `v6synth-dns` is [Rhai](https://rhai.rs/book).

Each script must contain two functions: `main` and `init`, with following
function signatures:

```rust
fn init() -> InitInfo;
// InitInfo is a map containing:
//
// - priority: Scripts with a higher priority are executed earlier.
//             The execution is short-circuiting, thus only one of the
//             scripts will be executed for a given DNS query.
//             Default: `priority: 0`
//
// - ipv4_ranges: IPv4 ranges wanted by this script.
//                This is a required field. The value can be `[]`, though.
//                Example: `ipv4_ranges: [ "192.168.0.0/24", "192.168.10.0/24" ]`
//
// - cname_filter: If the upstream DNS returns multiple CNAME records, the first
//                 record ending with this variable will be passed to main().
//                 Example: `cname_filter: ".example.com."` (note the ending dot!) 
//                 Default: `cname_filter: ""`
//
// `ipv4_ranges` and `cname_filter` CANNOT both be empty.

fn main(hostname, ipv4, prefix_size, cname) -> String;
// Arguments:
// - hostname (String) is the queried name.
// - ipv4 (String) is the IPv4 address 
// - prefix_size (int) is the size of the matched range
// - cname (String) is the content of the matching CNAME record
// 
// Return value (String): any IPv6 address
```

### Debugging

For debugging, set the environment variable `RUST_LOG=warn` to show error messages.
`v6synth-dns` will **not** panic or crash once it is in operation, if the AAAA
synthesis fails, it simply replies nothing to an AAAA query much like a normal DNS
forwarder.

## License

Being a fork of the [`hickory-dns` binary](https://github.com/hickory-dns/hickory-dns/tree/main/bin),
this repo is similarly dual-licensed under either of:

* Apache License, Version 2.0
* MIT license
