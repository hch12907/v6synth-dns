fn init() {
    return #{
        priority: 0,
        ipv4_ranges: [
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "141.101.64.0/18",
            "108.162.192.0/18",
            "190.93.240.0/20",
            "188.114.96.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
            "162.158.0.0/15",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "131.0.72.0/22",
        ],
    }
}

fn main(hostname, ipv4) {
    let octets = ipv4.split('.');
    let first = to_hex(parse_int(octets[0]) * 256 + parse_int(octets[1]));
    let second = to_hex(parse_int(octets[2]) * 256 + parse_int(octets[3]));
    return "2600:4700::" + first + ":" + second;
}
