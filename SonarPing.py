#!/usr/bin/env python3

#   SonarPing
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   Licence   : https://www.gnu.org/licenses/gpl-3.0.en.html

from re import S
import sys
import time
import socket
import struct
import select
import random
import json
import signal
import concurrent.futures
import argparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError


NAME = "SonarPING"
VER = 0.3

formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=64)
parser = argparse.ArgumentParser(prog=f"{NAME}", formatter_class=formatter)

parser.add_argument(
    "--file",
    "-f",
    type=argparse.FileType("r"),
    help="Send ICMP packets through IP file",
)
parser.add_argument("--ping", "-p", nargs="+", metavar="IP", help="Send ICMP packets.")
parser.add_argument(
    "--cidr",
    "-r",
    nargs="+",
    metavar="IP",
    help="Send ICMP packets through CIDR range",
)

parser.add_argument(
    "--cidrfile",
    "-cf",
    type=argparse.FileType("r"),
    help="Send ICMP packets with CIDR file",
)


option = parser.add_argument_group("ICMP Options")
option.add_argument(
    "--delay",
    "-d",
    type=float,
    metavar="",
    help="ICMP requests delay for sending each packet",
)
option.add_argument(
    "--timeout", "-t", type=int, metavar="", help="ICMP request timeout"
)
option.add_argument(
    "--count",
    "-c",
    type=int,
    metavar="",
    help="Stop current IP after sending (and receiving) count response packets",
)
option.add_argument(
    "--bytes",
    "-b",
    type=int,
    metavar="",
    help="Total Bytes to be Send with ICMP header",
)
option = parser.add_argument_group("CDN Scan")
option.add_argument(
    "--fastly",
    "--fastly-cdn",
    action="store_true",
    help="scan fastly cdn ip ranges",
)


args = parser.parse_args()

# Color Format
green = "\u001b[32m"
yellow = "\u001b[33m"
blue = "\u001b[34m"
error = "\u001b[31m"
reset = "\u001b[0m"


def banner(t=0.0005):
    data = """{} ____                                     ____                            
/\  _`\                                  /\  _`\   __                     
\ \,\L\_\    ___     ___      __     _ __\ \ \L\ \/\_\    ___      __     
 \/_\__ \   / __`\ /' _ `\  /'__`\  /\`'__\ \ ,__/\/\ \ /' _ `\  /'_ `\   
   /\ \L\ \/\ \L\ \/\ \/\ \/\ \L\.\_\ \ \/ \ \ \/  \ \ \/\ \/\ \/\ \L\ \  
   \ `\____\ \____/\ \_\ \_\ \__/.\_\\  \_\  \ \_\   \ \_\ \_\ \_\ \____ \ 
    \/_____/\/___/  \/_/\/_/\/__/\/_/ \/_/   \/_/    \/_/\/_/\/_/\/___L\ \\
                                                                   /\____/
                                                                   \_/__/ 

{}Starting Engine {} {}...
                                                        """.format(
        blue, green, VER, reset
    )
    for char in data:
        sys.stdout.write(char)
        time.sleep(t)
    sys.stdout.write("\n")


def sigint_handler(signal, frame):
    "Signal interrupt handler"
    print("Process Interrupted")
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)

# From /usr/include/linux/icmp.h.
ICMP_ECHO_REQUEST = 8

ICMP_CODE = socket.getprotobyname("icmp")
ERROR_DESCR = {
    1: " - Note that ICMP messages can only be " "sent from processes running as root.",
    10013: " - Note that ICMP messages can only be sent by"
    " users or processes with administrator rights.",
}

__all__ = ["create_packet", "do_one", "verbose_ping", "PingQuery"]


def checksum(source_string) -> int:
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = (source_string[count + 1]) * 256 + (source_string[count])
        sum = sum + this_val
        sum = sum & 0xFFFFFFFF
        count = count + 2
    if count_to < len(source_string):
        sum = sum + (source_string[len(source_string) - 1])
        sum = sum & 0xFFFFFFFF
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    # Swap bytes.
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer


def create_packet(id, byte: int):
    """Create a new echo request packet based on the given "id"."""
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = bytes(struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1))
    # Total Bytes to be Send with ICMP header
    data = bytes(byte)
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1
    )
    return header + data


def do_one(dest_addr, timeout=1):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.
    Returns either the delay (in seconds) or None on timeout and an invalid
    address, respectively.
    """
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.error as e:
        if e.errno in ERROR_DESCR:
            # Operation not permitted
            raise socket.error("".join((e.args[1], ERROR_DESCR[e.errno])))
        raise  # raise the original error
    try:
        host = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        return

    # Maximum for an unsigned short int c object counts to 65535 so
    # we have to sure that our packet id is not greater than that.
    packet_id = int((id(timeout) * random.random()) % 65535)
    packet = create_packet(packet_id, args.bytes)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]
    delay = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return delay


def receive_ping(my_socket, packet_id, time_sent, timeout):
    # Receive the ping from the socket.
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []:  # Timeout
            return
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", icmp_header)
        if p_id == packet_id:
            return time_received - time_sent
        time_left -= time_received - time_sent
        if time_left <= 0:
            return


def verbose_ping(dest_addr, wait: float, timeout, count: int):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.
    "wait" wait seconds between sending each packet.
    "count" specifies how many pings will be sent.
    Displays the result on the screen.

    """
    if not wait:
        wait = 1.0
    for i in range(count):
        # print('ping {}...'.format(dest_addr))
        delay = do_one(dest_addr, timeout)
        if delay == None:
            print("failed. (Timeout within {} seconds.)".format(timeout))
        else:
            delay = round(delay * 1000.0, 4)
            print(
                "{} Bytes from {}{}{} time={} ms.".format(
                    args.bytes, green, dest_addr, reset, delay
                )
            )
            time.sleep(wait)
    print("")


class PingQuery(concurrent.futures.ProcessPoolExecutor):
    def __init__(self, host, p_id, timeout=0.5, ignore_errors=True):
        """
        "host" represents the address under which the server can be reached.
        "timeout" is the interval which the host gets granted for its reply.
        "p_id" must be any unique integer or float except negatives and zeros.
        """
        concurrent.futures.ProcessPoolExecutor.__init__(self)
        try:
            self.create_socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        except socket.error as e:
            if e.errno in ERROR_DESCR:
                # Operation not permitted
                raise socket.error("".join((e.args[1], ERROR_DESCR[e.errno])))
            raise  # raise the original error
        self.time_received = 0
        self.time_sent = 0
        self.timeout = timeout
        # Maximum for an unsigned short int c object counts to 65535 so
        # we have to sure that our packet id is not greater than that.
        self.packet_id = int((id(timeout) / p_id) % 65535)
        self.host = host
        self.packet = create_packet(self.packet_id, args.bytes)
        if ignore_errors:
            # If it does not care whether an error occured or not.
            self.handle_error = self.do_not_handle_errors
            self.handle_expt = self.do_not_handle_errors

    def writable(self):
        return self.time_sent == 0

    def handle_write(self):
        self.time_sent = time.time()
        while self.packet:
            # The icmp protocol does not use a port, but the function
            # below expects it, so we just give it a dummy port.
            sent = self.sendto(self.packet, (self.host, 1))
            self.packet = self.packet[sent:]

    def readable(self):
        # As long as we did not sent anything, the channel has to be left open.
        if (
            not self.writable()
            # Once we sent something, we should periodically check if the reply
            # timed out.
            and self.timeout < (time.time() - self.time_sent)
        ):
            self.close()
            return False
        # If the channel should not be closed, we do not want to read something
        # until we did not sent anything.
        return not self.writable()

    def handle_read(self):
        read_time = time.time()
        packet, addr = self.recvfrom(1024)
        header = packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack("bbHHh", header)
        if p_id == self.packet_id:
            # This comparison is necessary because winsocks do not only get
            # the replies for their own sent packets.
            self.time_received = read_time
            self.close()

    def get_result(self):
        """Return the ping delay if possible, otherwise None."""
        if self.time_received > 0:
            return self.time_received - self.time_sent

    def get_host(self):
        """Return the host where to the request has or should been sent."""
        return self.host

    def do_not_handle_errors(self):
        # Just a dummy handler to stop traceback printing, if desired.
        pass

    def create_socket(self, family, type, proto):
        # Overwritten, because the original does not support the "proto" arg.
        sock = socket.socket(family, type, proto)
        sock.setblocking(0)
        self.set_socket(sock)
        # Part of the original but is not used. (at least at python 2.7)
        # Copied for possible compatiblity reasons.
        self.family_and_type = family, type

    # If the following methods would not be there, we would see some very
    # "useful" warnings from asyncore, maybe. But we do not want to, or do we?
    def handle_connect(self):
        pass

    def handle_accept(self):
        pass

    def handle_close(self):
        self.close()


class Country:
    def __init__(self, IP):
        countrycode = "http://ip-api.com/json/{}".format(IP)

        self.httprequest = Request(countrycode, headers={"Accept": "application/json"})

        with urlopen(self.httprequest) as response:
            self.data = json.loads(response.read().decode())

    def query(self):
        return self.data["query"]

    def regionname(self):
        return self.data["regionName"]

    def city(self):
        return self.data["city"]

    def org(self):
        return self.data["org"]

    def asdata(self):
        return self.data["as"]


def ipfile():
    ips = []
    with open(f"{args.file.name}", "r") as ip_file:

        for ip in ip_file.readlines():
            ips.append(ip.strip())
    return ips


class Cidr(concurrent.futures.ProcessPoolExecutor):
    "Unpack cidr ips"

    def __init__(self, iprange):
        self.ips = []
        self.iplist = []

        # read cidr trough file
        if args.cidrfile:
            with open(f"{args.cidrfile.name}", "r") as ip_file:
                for ips in ip_file.readlines():
                    self.iplist.append(ips.strip())
            (ip, cidr) = self.iplist[0].split("/")
        # read cidr trough stdin
        if args.cidr:
            (ip, cidr) = iprange[0].split("/")
            
        cidr = int(cidr)
        host_bits = 32 - cidr
        self.i = struct.unpack(">I", socket.inet_aton(ip))[0]  # note the endianness
        self.start = (self.i >> host_bits) << host_bits  # clear the host bits
        self.end = self.start | ((1 << host_bits) - 1)

    def cidrout(self):
        for i in range(self.start, self.end):
            self.ips.append(socket.inet_ntoa(struct.pack(">I", i)))
        return self.ips


class CDNList:
        #CloudFlare = 'https://www.cloudflare.com/ips-v4'
        Fastly = 'https://api.fastly.com/public-ip-list'
        MaxCDN = 'https://support.maxcdn.com/hc/en-us/article_attachments/360051920551/maxcdn_ips.txt'
        CacheFly = 'https://cachefly.cachefly.net/ips/rproxy.txt'

def cdnranges(url):
        data = f"{url}"

        httprequest = Request(data, headers={"Accept": "text/plain"})

        with urlopen(httprequest) as response:
            return response.read().decode()


def main():
    """
    the main file using the concurrent module for running ping in multi-thread mode
    threads are automatically optimized with ProcessPoolExecutor so there is no need to specify threads manually
    """
    while True:
        with concurrent.futures.ProcessPoolExecutor() as excuter:
            try:
                for args.method in method:
                    for ping in method:
                        country = excuter.map(
                            print(
                                blue
                                + str(ping)
                                + reset
                                + " "
                                + Country(str(ping)).asdata()
                                + " "
                                + Country(str(ping)).city()
                                + "/"
                                + Country(str(ping)).regionname()
                            )
                        )
                        run = excuter.map(
                            verbose_ping(ping, args.delay, args.timeout, args.count)
                        )

                        excuter.submit(country)
                        excuter.submit(run)
            except HTTPError:
                pass


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        sys.exit(parser.print_help())

    banner()

    # Bytes
    if args.bytes == None:
        args.bytes = 64

    # Default timeout
    if args.timeout == None:
        args.timeout = 2

    # ICMP delay
    if args.delay == None:
        args.delay = 1

    # ICMP Count
    if args.count == None:
        args.count = 4

    ## Ping method
    # file : read ips trough file
    # ping : read ip trough stdin
    # cidr : read ips with cidr
    # cidrfile : read ips with cidr file
    with concurrent.futures.ProcessPoolExecutor() as exec:
        if args.file:
            method = ipfile()
            exec.map(method)
        if args.ping:
            method = args.ping
            exec.map(method)

        if args.cidr:
            method = Cidr(args.cidr).cidrout()
            exec.map(method)
        if args.cidrfile:
            method = Cidr(args.cidrfile.name).cidrout()
            exec.map(method)
        if args.fastly :
            method = Cidr(cdnranges(CDNList.MaxCDN)).cidrout()
            exec.map(method)

    # run main
    exec.submit(main())
