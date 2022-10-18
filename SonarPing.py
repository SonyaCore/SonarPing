#!/usr/bin/env python3

import os , sys
import time
import socket
import struct
import select
import random
import json
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import argparse

NAME = 'SonarPING'

formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=64)
parser = argparse.ArgumentParser(prog=f"{NAME}", formatter_class=formatter)


parser.add_argument('--file','-f',type=argparse.FileType('r'),help='send ICMP packets to networks trough file')
parser.add_argument('--ping','-p', nargs='+', help='send ICMP packets to network hosts')

option = parser.add_argument_group('ICMP Options')
option.add_argument('--delay','-d',type=int, help='ICMP requests delay for sending each packet')
option.add_argument('--timeout','-t',type=int, help='ICMP request timeout')
option.add_argument('--count','-c',type=int, help='Stop current IP after sending (and receiving) count packets.')


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

{}Starting Engine...{}
                                                        """.format(
                                                        blue,
                                                        green,
                                                        reset)
    for char in data:
        sys.stdout.write(char)
        time.sleep(t)
    sys.stdout.write('\n')


# From /usr/include/linux/icmp.h.
ICMP_ECHO_REQUEST = 8

ICMP_CODE = socket.getprotobyname("icmp")
ERROR_DESCR = {
    1: " - Note that ICMP messages can only be " "sent from processes running as root.",
    10013: " - Note that ICMP messages can only be sent by"
    " users or processes with administrator rights.",
}

__all__ = ["create_packet", "do_one", "verbose_ping", "PingQuery"]


def checksum(source_string) -> str:
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


def create_packet(id):
    """Create a new echo request packet based on the given "id"."""
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = bytes(struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1))
    # Total Bytes to be Send with ICMP header
    data = bytes(192)
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
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
    packet = create_packet(packet_id)
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


def verbose_ping(dest_addr, wait : float , timeout , count : int):
    """
    Sends one ping to the given "dest_addr" which can be an ip or hostname.
    "timeout" can be any integer or float except negatives and zero.
    "wait" wait seconds between sending each packet.
    "count" specifies how many pings will be sent.
    Displays the result on the screen.

    """
    if not wait :
        wait = 1.0
    for i in range(count):
        # print('ping {}...'.format(dest_addr))
        delay = do_one(dest_addr, timeout)
        if delay == None:
            print("failed. (Timeout within {} seconds.)".format(timeout))
        else:
            delay = round(delay * 1000.0, 4)
            print("PING {}{}{} {} ms.".format(green, dest_addr, reset, delay))
            time.sleep(wait)
    print("")


class PingQuery():
    def __init__(self, host, p_id, timeout=0.5, ignore_errors=False):
        """
        "host" represents the address under which the server can be reached.
        "timeout" is the interval which the host gets granted for its reply.
        "p_id" must be any unique integer or float except negatives and zeros.

        If "ignore_errors" is True, the default behaviour of asyncore
        will be     overwritten with a function which does just nothing.
        """
        socket.__init__(self)
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
        self.packet = create_packet(self.packet_id)
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

def COUNTRY(IP):

    countrycode = "http://ip-api.com/json/{}".format(IP)

    httprequest = Request(countrycode, headers={"Accept": "application/json"})

    with urlopen(httprequest) as response:
        data = json.loads(response.read().decode())
    return data["query"] + \
        ' ' + data["regionName"]  +  \
        '/' + data["city"]

def IPFILE():
    ips = []
    with open(f"{args.file.name}", "r") as ip_file:

        for ip in ip_file.readlines():
            ips.append(ip.strip())
    return ips

if __name__ == "__main__":
    banner()

    # Default timeout
    if args.timeout == None :
        args.timeout = 2

    # ICMP delay
    if args.delay == None :
        args.delay = 1

    # ICMP Count
    if args.count == None :
        args.count = 4

    ## Ping method
    # file : read ips trough file
    # ping : read ip trough stdin
    if args.file :
        method = IPFILE()
    if args.ping :
        method = args.ping

    while True:
        try:
            for ping in method:
                print(blue +
                str(ping)
                + reset + " " 
                + COUNTRY(str(ping)))

                verbose_ping(
                ping,
                args.delay,
                args.timeout,
                args.count)
        except HTTPError:
            pass
            

        # Requset sleep
        time.sleep(1.0)