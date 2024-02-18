# v6synth-dns

A DNS server which attempts to synthesise AAAA records for websites that use a
dual-stacked CDN.

The synthesis of AAAA occurs in the scripts (check them out [here](./config/scripts)).

Inspired by https://gitlab.com/miyurusankalpa/IPv6-dns-server.

# Building

```
cargo build --release
```

The binary is located inside `./target/release/`.

# Running

Assuming your configuration TOML is located at `./config/named.toml`,
the root directory of your zones is `./config/`, and you want the server
to listen on port 15353:

```
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

