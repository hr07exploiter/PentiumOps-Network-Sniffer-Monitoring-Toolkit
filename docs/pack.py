#!/usr/bin/python

class Ethernet:
    'This represents Ehternet part of packet'
    NumOfPackets = 0
    
    def __init__(self,dest_mac,src_mac,protocol_type):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.protocol_type = protocol_type

        self.level1_type = "Ethernet"
        Ethernet.NumOfPackets +=1




class IPv4(Ethernet):
    'This represents IPv4 part of whole packet'

    NumOfIPv4Packets = 0

    def __init__(self,version,headerLength,tos,totalLength,identification,reserverdBit,dontFragment,moreFragments,fragmentOffset,ttl,protocol,headerChecksum,source,destination):
        self.version = version
        self.headerLength = headerLength
        self.typeOfService = tos
        self.totalLength = totalLength
        self.identification = identification
        self.reservedBit = reservedBit
        self.dontFragment = dontFragment
        self.moreFragment = moreFragment
        self.fragmentOffset = fragmentOffset
        self.timeToLeave = ttl
        self.protocol = protocol
        self.headerChecksum = headerChecksum
        self.source = source
        self.destination = destination
        
        self.level2_type="IPv4"
        IPv4.NumOfIPv4Packets +=1


class ARP(Ethernet):
    'This represents ARP part of whole packet'

    NumOfARPPackets = 0

    def __init__(self,hardwareType,protocolType,hardwareSize,protocolSize,opcode,senderMACAddr,senderIPAddr,targetMACAddr,targetIPAddr):
        self.hardwareType = hardwareType
        self.protocolType = protocolType
        self.hardwareSize = hardwareSize
        self.protocolSize = protocolSize
        self.opcode = opcode
        self.senderMACAddr = senderMACAddr
        self.senderIPAddr = senderIPAddr
        self.targetMACAddr = targetMACAddr
        self.targetIPAddr = targetIPAddr
        
        self.level2_type="ARP"
        ARP.NumOfARPPackets +=1




class IGMP(IPv4):
    NumOfIGMPPackets = 0

    def __init__(self,Type,Max_Resp_Time,Checksum,Group_address,other_data):
        self.Type = Type
        self.Max_Resp_Time = Max_Resp_Time
        self.Checksum = Checksum
        self.Group_address = Group_address
        self.other_data = other_data

        self.leve2_type="IGMP"
        IGMP.NumOfIGMPPackets += 1

class ICMP(IPv4):
    NumOfICMPPackets = 0

    def __init__(self,ICMP_type,Code,Checksum,other_data):
        self.ICMP_type = ICMP_type
        self.Code = Code
        self.Checksum = Checksum
        self.other_data = other_data

        self.level2_type="ICMP"
        ICMP.NumOfICMPPackets+=1
