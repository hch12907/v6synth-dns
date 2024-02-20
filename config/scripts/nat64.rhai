fn init() {
    return #{
        // The priority is set very low we don't want traffic to go through NAT64
        priority: -10000,
        ipv4_ranges: [
            "0.0.0.0/0"
        ],
    }
}

fn main(hostname, ipv4, prefix_size, cname) {
    const NAT64_PREFIX = "64:ff9b::";

    // uncomment to enable this script
    //return NAT64_PREFIX + ipv4;
}
