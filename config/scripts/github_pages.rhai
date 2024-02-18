fn init() {
    return #{
        priority: 0,
        ipv4_ranges: [
            "185.199.108.0/22",
        ],
    }
}

fn main(hostname, ipv4, prefix_size, cname) {
    let octets = ipv4.split('.');

    // Technically 8000 to 8003 are all accepted
    return "2606:50c0:8000::" + octets[3];
}
