#!/usr/bin/python
from pack2 import *
class Ethernet(ARP,IPv4):
    'This represents Ehternet part of packet'
    NumOfPackets = 0
    
    def __init__(self,eth_proto,dest_mac,src_mac,protocol_type,raw):
        self.packetNumber = Ethernet.NumOfPackets+1
        self.eth_proto = eth_proto
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.protocol_type = protocol_type
        self.raw = raw
        #self.json = {'eth_proto':eth_proto,'dest_mac':dest_mac,'src_mac':src_mac,'protocol_type':protocol_type}

        self.level1_packet_type="Ethernet"
        self.level2_packet_type=""
        self.level3_packet_type=""
        self.level4_packet_type=""
        Ethernet.NumOfPackets +=1
