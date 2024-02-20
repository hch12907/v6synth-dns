fn init() {
    return #{
        priority: 0,
        ipv4_ranges: [
            // the ranges are not exhaustive.
            "2.16.0.0/13",
            "23.32.0.0/11",
            "23.192.0.0/11",
            "45.79.0.0/16",
            "69.192.0.0/16",
            "72.246.0.0/15",
            "88.221.0.0/16",
            "92.122.0.0/15",
            "95.100.0.0/15",
            "96.6.0.0/15",
            "96.16.0.0/15",
            "104.64.0.0/10",
            "118.214.0.0/15",
            "139.144.0.0/16",
            "139.162.0.0/16",
            "143.42.0.0/16",
            "172.104.0.0/15",
            "172.224.0.0/12",
            "173.222.0.0/15",
            "184.24.0.0/13",
            "184.50.0.0/15",
            "184.84.0.0/14",
        ],
        cname_filter: ".akamaiedge.net.",
    }
}

fn main(hostname, ipv4, prefix_size, cname) {
    if cname.is_empty() && !hostname.starts_with("www.") {
        cname = resolve("www." + hostname, "CNAME_CHAIN");
    }

    cname.remove(".akamaiedge.net."); // obtain the customer string

    let customer = cname.split('.');
    let customer_name = customer[0]; // customer name
    let customer_unk = customer[1]; // unknown, but appending "ds" means dualstacking

    let ds_cname = customer_name + "." + "dsc" + customer_unk + ".akamaiedge.net.";

    return resolve(ds_cname, "AAAA");
}
