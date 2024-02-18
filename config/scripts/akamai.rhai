fn init() {
    return #{
        priority: 0,
        ipv4_ranges: [],
        cname_filter: ".akamaiedge.net.",
    }
}

fn main(hostname, ipv4, cname) {
    cname.remove(".akamaiedge.net."); // obtain the customer string

    let customer = cname.split('.');
    let customer_name = customer[0]; // customer name
    let customer_unk = customer[1]; // unknown, but appending "ds" means dualstacking

    let ds_cname = customer_name + "." + "dsc" + customer_unk + ".akamaiedge.net.";

    return resolve(ds_cname, "AAAA");
}
