import threading
from scapy.all import *
from collections import namedtuple
import time
from socket import getservbyport
import argparse

SinglePortScanResult = namedtuple('SinglePortScanResult', [
                                  'protocol', 'port', 'respone_time_miliseconds', 'guess_protocol'])


class PortScan:
    def __init__(self, ip_address: str, timeout: float, verbose: bool, guess: bool, ports_tcp: list[int], ports_udp: list[int]):
        self.ip_address = ip_address
        self.timeout = timeout
        self.verbose = verbose
        self.guess = guess
        self.ports_tcp = ports_tcp
        self.ports_udp = ports_udp
        self.all_positive_scan_results = set()

    def scan_single_port_udp(self, port: int) -> SinglePortScanResult | None:
        packet = IP(dst=self.ip_address) / UDP(dport=port)
        start_time = time.time()
        responce = sr1(packet, timeout=self.timeout, verbose=False)
        end_time = time.time()
        if responce is not None:
            respone_time_miliseconds = PortScan.to_miliseconds(
                end_time - start_time)
            guess = PortScan.get_service_name(port)
            return SinglePortScanResult("UDP", port, respone_time_miliseconds, guess)
        return None

    def scan_single_port_tcp(self, port: int) -> SinglePortScanResult | None:
        SYN_packet = IP(dst=self.ip_address) / TCP(dport=port, flags="S")
        start_time = time.time()
        responce = sr1(SYN_packet, timeout=self.timeout, verbose=False)
        end_time = time.time()
        if responce is None or not responce.haslayer(TCP):
            return None
        TCP_flags = responce[TCP].flags
        if TCP_flags == "SA":
            respone_time_miliseconds = PortScan.to_miliseconds(
                end_time - start_time)
            guess = PortScan.get_service_name(port)

            # Closing connection here
            RST_packet = IP(dst=self.ip_address) / TCP(dport=port, flags="R")
            send(RST_packet, verbose=False)
            return SinglePortScanResult("TCP", port, respone_time_miliseconds, guess)

    @staticmethod
    def get_service_name(port: int) -> str:
        try:
            return socket.getservbyport(port)
        except OSError:
            return '-'

    @staticmethod
    def to_miliseconds(time_seconds: int) -> int:
        return time_seconds * 1000

    def scan_all_udp(self):
        for udp_port in self.ports_udp:
            scan_result = self.scan_single_port_udp(udp_port)
            if scan_result:
                self.all_positive_scan_results.add(scan_result)

    def scan_all_tcp(self):
        for tcp_port in self.ports_tcp:
            scan_result = self.scan_single_port_udp(tcp_port)
            if scan_result:
                self.all_positive_scan_results.add(scan_result)

    def get_all_scan_results(self):
        self.scan_all_tcp()
        self.scan_all_udp()
        return self.all_positive_scan_results


class AnswerFormatter:
    @staticmethod
    def print_formated_answer(scan_results: SinglePortScanResult, verbose: bool, guess: bool):
        for result in scan_results:
            st = f"{scan_results.protocol}  {scan_results.port}"
            if verbose:
                st += f"  {scan_results.respone_time_miliseconds}"
            if guess:
                st += f"  {scan_results.guess_protocol}"
            print(st)


parser = argparse.ArgumentParser(
    description="Simple TCP and UDP Ports Scanner")

parser.add_argument("ip_address", help="Server IP address")
parser.add_argument("ports", nargs="+",
                    help="Ports list as 'tcp[/port]' or 'udp[/port|port-range]'")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose mode")
parser.add_argument("-g", "--guess", action="store_true",
                    help="Get possible service on port")
parser.add_argument("--timeout", type=float, default=2,
                    help="Responce timeout (default 2 seconds)")


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
