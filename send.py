#!/usr/bin/env python2
import random
import argparse
import socket
from time import sleep

from scapy.all import IP, TCP, UDP, Ether, get_if_hwaddr, get_if_list, sendp

# this function sends packets sequence according to a given flow
def send_packet(proto,message = None):
    """
    this function sends one packet to the outsode world.
    input:
        "start/end/none" -> start is the first message, end is the last massege, none is all the rest
    output:
        True/False if packet sent to the host
    """
    # parse flow var
    ip_dst_addr             = '10.0.1.1'

    if message != "Start" and message != "End":
        metadata = "A"
    else:
        metadata = message

    # build params for packet
    #metadata    = "hello world " + str(random.randint(0,15)) # todo hard coded
    iface       = get_if()
    src_hw_addr = get_if_hwaddr(iface)
    dst_hw_addr = 'ff:ff:ff:ff:ff:ff'
    # build packet
    pkt =  Ether(src = src_hw_addr, dst = dst_hw_addr) 
    pkt =  pkt / IP(dst = ip_dst_addr) 

    if proto == "udp":
        pkt =  pkt / UDP(dport=1234, sport=random.randint(49152,65535))
    else:
        pkt =  pkt / TCP(dport=1234, sport=random.randint(49152,65535))   

    pkt =  pkt / metadata
    # sending the pkt
    sendp(pkt, iface=iface, verbose=False)
    #pkt.show2()
    #print "sending on interface {} to IP addr {}".format(iface, str(addr))



# returns eth0 interface for the running host
def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    # sending the packets
    # the first- "Start", the last "End"
    send_packet("tcp","Start")
    for i in range(500):
        send_packet("udp")
        send_packet("tcp")

    sleep(3)
    for i in range(5):
        send_packet("tcp","End")
    

if __name__ == '__main__':
    main()
