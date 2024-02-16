fn init() {
    return #{
        priority: 0,
        ipv4_ranges: [
            "23.235.32.0/20",
            "43.249.72.0/22",
            "103.244.50.0/24",
            "103.245.222.0/23",
            "103.245.224.0/24",
            "104.156.80.0/20",
            "151.101.0.0/16",
            "157.52.64.0/18",
            "172.111.64.0/18",
            "185.31.16.0/22",
            "199.27.72.0/21",
            "199.232.0.0/16",
        ],
        cname_filter: "map.fastly.net.",
    }
}

fn main(hostname, ipv4, prefix_size, cname) {
    let map = "";

    // if CNAME is not empty, that means we already have gotten *.map.fastly.net.
    if !cname.is_empty() {
        map = cname;
    }

    // if the domain is without www, try to resolve for CNAME using it
    else if !hostname.starts_with("www.") && hostname.split('.').len() == 3 {
        let cname = resolve("www." + hostname, "CNAME");

        if cname.ends_with("map.fastly.net.") && !cname.starts_with("ipv4") {
            map = cname;
        }
    }

    let dualstack_aaaa = "";

    if !map.is_empty() {
        let ds_cname = "dualstack." + map;
        dualstack_aaaa = resolve(ds_cname, "AAAA");
    }

    if !dualstack_aaaa.is_empty() {
        return dualstack_aaaa;
    }

    // this algorithm is incompatible with the smaller ranges
    // limit it to 151.101.0.0/16 and 199.232.0.0/16 for now
    if prefix_size == 16 {
        let fastly_v6 = resolve("dualstack.g.shared.global.fastly.net", "AAAA");
        let fastly_v6_prefix = fastly_v6.split("::")[0];

        if !fastly_v6_prefix.is_empty() {
            let octets = ipv4.split('.');
            let v6_suffix = ((parse_int(octets[2]) & 0x3F) << 8) + parse_int(octets[3]);

            // Yes, we reinterpret the decimal number as hex. Thus, 396 becomes 0x396.
            // What the hell, fastly?
            return fastly_v6_prefix + "::" + v6_suffix;
        } else {
            return "";
        }
    }
}
