#!/usr/bin/python
from pack3 import *

class IPv4(IGMP,ICMP,UDP,TCP):
    'This represents IPv4 part of whole packet'

    NumOfIPv4Packets = 0

    def setIPv4(self,proto,version,headerLength,tos,totalLength,identification,reservedBit,dontFragment,moreFragments,fragmentOffset,ttl,protocol,headerChecksum,source,destination):
        self.proto = proto
        self.version = version
        self.headerLength = headerLength
        self.typeOfService = tos
        self.totalLength = totalLength
        self.identification = identification
        self.reservedBit = reservedBit
        self.dontFragment = dontFragment
        self.moreFragment = moreFragments
        self.fragmentOffset = fragmentOffset
        self.timeToLeave = ttl
        self.protocol = protocol
        self.headerChecksum = headerChecksum
        self.source = source
        self.destination = destination
        #self.json['proto'],self.json['version'],self.json['headerLength'],self.json['typeOfService'],self.json['totalLength'],self.json['identification'],self.json['reservedBit'],self.json['dontFragment'],self.json['moreFragment'],self.json['fragmentOffset'],self.json['timeToLeave'],self.json['protocol'],self.json['headerChecksum'],self.json['source'],self.json['destination'] = proto,version,headerLength,tos,totalLength,identification,reservedBit,dontFragment,moreFragments,fragmentOffset,ttl,protocol,headerChecksum,source,destination

        self.level2_packet_type="IPv4"
        IPv4.NumOfIPv4Packets +=1


class ARP():
    'This represents ARP part of whole packet'

    NumOfARPPackets = 0

    def setARP(self,hardwareType,protocolType,hardwareSize,protocolSize,opcode,senderMACAddr,senderIPAddr,targetMACAddr,targetIPAddr):
        self.hardwareType = hardwareType
        self.protocolType = protocolType
        self.hardwareSize = hardwareSize
        self.protocolSize = protocolSize
        self.opcode = opcode
        self.senderMACAddr = senderMACAddr
        self.senderIPAddr = senderIPAddr
        self.targetMACAddr = targetMACAddr
        self.targetIPAddr = targetIPAddr
        #self.json['hardwareType'],self.json['protocolType'],self.json['hardwareSize'],self.json['protocolSize'],self.json['opcode'],self.json['senderMACAddr'],self.json['senderIPAddr'],self.json['targetMACAddr'],self.json['targetIPAddr'] = hardwareType,protocolType,hardwareSize,protocolSize,opcode,senderMACAddr,senderIPAddr,targetMACAddr,targetIPAddr

        self.level2_packet_type="ARP"
        ARP.NumOfARPPackets +=1

