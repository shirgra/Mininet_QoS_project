#!/usr/bin/env python2

######################################################################################################################################## Imports

import argparse
import grpc
import os
import sys
import time
import socket
import random
import struct
import csv
import threading    
from time import sleep

# Import P4Runtime lib from parent utils dir Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

# scapy logger - this remove the IPv6 warning from the terminal prints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# scapy
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR

# using time module
import time
import pickle as pkl

######################################################################################################################################## Global Varriables

FLAG = True

TIME_INTERVAL_BAR = 10
current_time_interval = 0
off_time = 0
PACKET_THRESHOLD = 10
OFF_TIME_INTERVAL = 3

result = []
time_start = time.time()
tcp_counter = 0
udp_counter = 0
udp_th = 0
diffserv_flag = False



######################################################################################################################################## Class CacheSwitch

class CacheSwitch:
    def __init__(self, name, localhost_port, device_id):
        self.name_str = name
        # topology properties
        self.localhost_port = localhost_port
        self.address =  '127.0.0.1:' + str(localhost_port)
        self.device_id = device_id
        self.obj = self.initiate_bmv2_switch()
        # cache properties
        self.tables = {}

    def initiate_bmv2_switch(self):
        ## Set initial definition the the smart switches
        obj = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=self.name_str,
            address=self.address,
            device_id=self.device_id,
            proto_dump_file='logs/' + self.name_str + '-p4runtime-requests.txt')         
        # Send master arbitration update message to establish this controller as
        obj.MasterArbitrationUpdate()
        # Install the P4 program on the switches
        obj.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print("Connected %s to controller." % self.name_str)
        return obj

    def insert_rule(self, dst_mac_addr, dst_ip_addr, mask, sw_exit_port, action = "MyIngress.ipv4_forward"):

        if action == "MyIngress.ipv4_forward":
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
                },
                action_name="MyIngress.ipv4_forward",
                action_params={
                    "dstAddr": dst_mac_addr,
                    "port": sw_exit_port
                })

        if action == "MyIngress.drop":
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
                },
                action_name="MyIngress.drop",
                action_params={
                }) 

        self.obj.WriteTableEntry(table_entry)
        print 'Added a new rule in %s:  %s / %d.' % (self.name_str, dst_ip_addr, mask)


######################################################################################################################################## Functions

""" P4RUNTIME FUNCTIONS """

def p4runtime_init():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='../utils/build_dependencies/basic_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='../utils/build_dependencies/basic_tunnel.json')
    args = parser.parse_args()
    # if does not exist -> exit
    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    # Instantiate a P4Runtime helper from the p4info file
    bmv2_file_path = args.bmv2_json
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(args.p4info)   
    # return values
    return bmv2_file_path, p4info_helper


""" LISTENING TO SWITCHES FUNCTIONS (THREADS) """

def handle_pkt(pkt):

    global result, time_start,udp_counter, tcp_counter, current_time_interval, udp_th, diffserv_flag, off_time, FLAG

    # parse packet 
    dst   = pkt[IP].dst 
    src   = pkt[IP].src 


    ### TCP ###

    if TCP in pkt and pkt[TCP].dport == 1234:

        # begining or end:
        if pkt[TCP].load == 'Start':
            time_start = time.time()
            print('Starting...')
        if pkt[TCP].load == 'End':
            print("Finished receiver.")

            with open('3_500_results_'+str(PACKET_THRESHOLD)+'_'+str(TIME_INTERVAL_BAR)+'.pkl','wb') as f:
                pkl.dump(result, f)

            FLAG = False


        tmp = [time.time()-time_start, 'TCP', tcp_counter]
        result.append(tmp)
        tcp_counter += 1
        sys.stdout.flush()

        print tmp
        return None


    ### CHECK big traffic of udp

    current_time_interval = time.time() - current_time_interval

    if current_time_interval > TIME_INTERVAL_BAR:

        current_time_interval = 0
        udp_th += 1

        if udp_th > PACKET_THRESHOLD:

            udp_th = 0

            #except only TCP
            diffserv_flag = True
            off_time = time.time()

            None

        None

    off_time = time.time() - off_time

    if off_time > OFF_TIME_INTERVAL:
        # except all packets
        diffserv_flag = False

    ### only if we except udp

    if UDP in pkt and pkt[UDP].dport == 1234 and not diffserv_flag:

        tmp = [time.time()-time_start, 'UDP', udp_counter]
        result.append(tmp)
        udp_counter += 1
        sys.stdout.flush()

        print tmp
        None


    

######################################################################################################################################## MAIN

"""MAIN"""

print("\n********************************************")
print("Starting Controller Program")
print("********************************************")

################################################################################################################ Connect Switches to controller - p4runtime

## Retriving information about the envirunment:
bmv2_file_path, p4info_helper = p4runtime_init()
print("Uploaded p4-runtime system parameters.")

## connect to switches s1-s6
s2 = CacheSwitch(name= 's2', localhost_port= 50052, device_id=1)
s3 = CacheSwitch(name= 's3', localhost_port= 50053, device_id=2)
s4 = CacheSwitch(name= 's4', localhost_port= 50054, device_id=3)

print("Connected to all switches in the topology.")
print("********************************************")

################################################################################################################ Insert basic forwarding rules

# Write the beasic rules - triangle topology

s2.insert_rule("08:00:00:00:02:22", "10.0.2.2", 32, 1)
s2.insert_rule("08:00:00:00:01:00", "10.0.1.1", 32, 2)

s3.insert_rule("08:00:00:00:03:33", "10.0.3.3", 32, 1)
s3.insert_rule("08:00:00:00:01:00", "10.0.1.1", 32, 2)

s4.insert_rule("08:00:00:00:04:44", "10.0.4.4", 32, 1)
s4.insert_rule("08:00:00:00:01:00", "10.0.1.1", 32, 2)


print("Inserted basic forwarding rules to switches.")
print("********************************************")

################################################################################################################ Open threads - listen to hit counts and act on it


while FLAG:
    sniff(count = 1, iface = "s1-eth1", prn = lambda pkt: handle_pkt(pkt))

print("********************************************")

################################################################################################################ Ending main


# close the connection
ShutdownAllSwitchConnections()
print("\nController Program Terminated.")  