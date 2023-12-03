def get_tcp_udp_ports(ports_arguments):
    min_port = 1
    max_port = 65535
    tcp_ports = set()
    udp_ports = set()

    for subargument in ports_arguments:
        if subargument == "tcp":
            tcp_ports.update(range(min_port, max_port + 1))
        elif subargument == "udp":
            udp_ports.update(range(min_port, max_port + 1))
        else:
            protocol, raw_range = subargument.split("/")
            rangee = get_range(raw_range)
            if protocol == "tcp":
                tcp_ports.update(rangee)
            elif protocol == "udp":
                udp_ports.update(rangee)
            else:
                raise ValueError("Incorrect protocol")

    return tcp_ports, udp_ports


def get_range(ranges):
    result = set()
    if ',' in ranges:
        for rang in ranges.split(','):
            result.update(get_single_range(rang))
        return result
    return get_single_range(ranges)


def get_single_range(rang):
    if "-" in rang:
        start, end = map(int, rang.split("-"))
        return set(range(start, end + 1))
    else:
        return {int(rang)}


print(get_tcp_udp_ports(["tcp/80", "tcp/12-15", "udp/3-4,6,10-20"]))
