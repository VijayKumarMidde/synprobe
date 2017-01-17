#! /usr/bin/env python
"""
Since scapy does not use Linux Kernel services, Linux Kernel might
issue RST for SYN packets created by Scapy. To supress RST packets 
from Kernel excecute the following comand with your IP:
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {SRC_IP} -j DROP
"""

import argparse
import logging
from scapy.all import *

def scan_one(ip, port):
    sport = random.randint(1024,65535)
    seq_no = random.randint(1000, 50000)

    # Send SYN
    tcp = TCP(sport=sport, dport=port, flags="S", seq=seq_no)
    synack_pkt = send_pkt(ip / tcp)

    # Host not reachable
    if synack_pkt is None:
        return

    # Port is closed
    if not is_port_open(synack_pkt):
        return ("closed", "")

    # Send ACK
    tcp = TCP(sport=sport, dport=port, flags="A", seq=synack_pkt["TCP"].ack + 1, ack=synack_pkt["TCP"].seq + 1)
    ans_pkt = send_pkt(ip / tcp)
    raw_data = parse_raw_data(ans_pkt)

    if not raw_data:
        # send random payload
        payload = Raw("GET /index.html HTTP/1.1\r\n\r\n")
        tcp = TCP(sport=sport, dport=port, flags="PA", seq=synack_pkt["TCP"].ack + 1, ack=synack_pkt["TCP"].seq + 1)
        ans_pkt = send_pkt(ip / tcp / payload)
        raw_data = parse_raw_data(ans_pkt, hex_str=True)

    # send FIN
    if ans_pkt is None:
        ans_pkt = synack_pkt
    tcp = TCP(sport=sport, dport=port, flags="F", seq=ans_pkt["TCP"].ack + 1, ack=ans_pkt["TCP"].seq + 1)
    send_pkt(ip / tcp)
    return ("open", raw_data)

def send_pkt(pkt):
    return sr1(pkt, timeout=1, verbose=0)

def is_port_open(pkt):
    return pkt.sprintf("%TCP.flags%") == "SA"

def parse_raw_data(pkt, hex_str=False):
    if pkt is None:
        return False
    if pkt.haslayer("Raw"):
        return pkt.getlayer("Raw").load
    if hex_str:
        return hexdump(str(pkt))
    return False

# https://gist.github.com/sbz/1080258
def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return '\t\t'.join(lines)

def scan(ips, ports):
    for ip in ips:
        print "***** SynProbe report for %s *****" % ip.dst
        print "Port\tStatus\tService"
        print "---------------------------------------------------------------------------"
        open_port_count = 0
        for port in ports:
            try:
                status = scan_one(ip, port)
                if status is None:
                    print "%s is not reachable\n" % ip.dst
                    break
                if status[0] is "open":
                    open_port_count += 1
                print "%d\t%s\t%s" % (port, status[0], status[1])
            except Exception as e:
                print "Failed to establish TCP handshake. Error: {}".format(e)
        print "%d/%d ports are open." % (open_port_count, len(ports))
    print "SynProbe completed scanning!"

def main():
    parser = argparse.ArgumentParser(description="SynProbe is a small reconnaissance tool for service fingerprinting")
    parser.add_argument("-p", help="port range to scan. Ex: 0-100")
    parser.add_argument("target", help="target ip or subnet to scan. Ex: 192.168.0.0/24")
    args = parser.parse_args()
    
    try:
        ip = IP(dst=args.target)
    except Exception as e:
        print "Invalid IP/subnet. Error: {}".format(e)
        return
    ports = args.p
   
    # Default tcp port list (Most commonly used 300 tcp ports)
    # https://svn.nmap.org/nmap/nmap-services
    if ports is None:
        ports = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060,179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1048, 1049, 1053, 1054, 1056, 1064, 1065, 2967, 3703, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102, 1039, 2869, 4001, 5120, 8010, 9000, 2105, 636, 1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280, 254, 4000, 1761, 5003, 2002, 1998, 2005, 1032, 1050, 6112, 3690, 1521, 2161, 1080, 6002, 2401, 902, 4045, 787, 7937, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555, 10001, 1494, 3, 593, 2301, 3268, 7938, 1022, 1234, 1035, 1036, 1037, 1074, 8002, 9001, 464, 497, 1935, 2003, 6666, 6543, 24, 1352, 3269, 1111, 407, 500, 20, 2006, 1034, 1218, 3260, 15000, 4444, 264, 33, 2004, 1042, 42510, 999, 3052, 1023, 222, 1068, 888, 7100, 563, 1717, 992, 2008, 32770, 7001, 32772, 2007, 8082, 5550, 512, 1043, 2009, 5801, 1700, 2701, 7019, 50001, 4662, 2065, 42, 2010, 161, 2602, 3333, 9535, 5100, 2604, 4002, 5002, 1047, 1051, 1052, 1055, 1060, 1062, 1311, 2702, 3283, 4443, 5225, 5226, 6059, 6789, 8089, 8192, 8193, 8194, 8651, 8652, 8701, 9415, 9593, 9594, 9595, 16992, 16993, 20828, 23502, 32769, 33354, 35500, 52869, 55555, 55600, 64623, 64680, 65000, 65389, 1067, 13782, 366, 5902, 9050, 85, 1002]

    # Port range
    try:
        if "-" in ports:
            ports = ports.split("-")
            ports = range(int(ports[0]), int(ports[1]) + 1)
        if type(ports) is str:
            ports = [int(ports)]
    except:
        print "Invalid arguments. Type `python synprobe.py -h` for help."
        return
     
    #logging.getLogger("scapy").setLevel(2)
    scan(ip, ports)

if __name__ == "__main__":
    main()


