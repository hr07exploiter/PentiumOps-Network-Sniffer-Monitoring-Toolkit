#!/usr/bin/python
from pack4 import *

class IGMP():
    NumOfIGMPPackets = 0

    def setIGMP(self,Type,Max_Resp_Time,Checksum,Group_address,other_data):
        self.Type = Type
        self.Max_Resp_Time = Max_Resp_Time
        self.Checksum = Checksum
        self.Group_address = Group_address
        self.other_data = other_data
        #self.json['Type'],self.json['Max_Resp_Time'],self.json['Checksum'],self.json['Group_address'],self.json['other_data'] = Type,Max_Resp_Time,Checksum,Group_address,other_data

        self.level3_packet_type="IGMP"
        IGMP.NumOfIGMPPackets += 1

class ICMP():
    NumOfICMPPackets = 0

    def setICMP(self,ICMP_type,Code,Checksum,other_data):
        self.ICMP_type = ICMP_type
        self.Code = Code
        self.Checksum = Checksum
        self.other_data = other_data
        #self.json['ICMP_type'],self.json['Code'],self.json['Checksum'],self.json['other_data']=ICMP_type,Code,Checksum,other_data

        self.level3_packet_type="ICMP"
        ICMP.NumOfICMPPackets+=1

class UDP(SSDP,DHCP,DNS):
    NumOfUDPPackets = 0

    def setUDP(self,Source_Port,Destination_Port,Length,Checksum):
        self.Source_Port = Source_Port
        self.Destination_Port = Destination_Port
        self.Length = Length
        self.Checksum = Checksum
        #self.json['Source_Port'],self.json['Destination_Port'],self.json['Length'],self.json['Checksum'] = Source_Port,Destination_Port,Length,Checksum

        self.level3_packet_type="UDP"
        UDP.NumOfUDPPackets+=1

class TCP(HTTP):
    NumOfTCPPackets = 0

    def setTCP(self,Source_Port,Destination_Port,Seq_Num,Ack_Num,Header_Length,Res_Flag,Nonce_Flag,CWR_Flag,ECN_Flag,Urgent_Flag,Ack_Flag,Push_Flag,Reset_Flag,Syn_Flag,Fin_Flag,Window_Size,Checksum,Urgent_Pointer,Options):
        self.tcp_Source_Port=Source_Port
        self.tcp_Destination_Port = Destination_Port
        self.tcp_Seq_Num = Seq_Num
        self.tcp_Ack_Num = Ack_Num
        self.tcp_Header_Length = Header_Length
        self.tcp_Res_Flag = Res_Flag
        self.tcp_Nounce_Flag = Nonce_Flag
        self.tcp_CWR_Flag = CWR_Flag
        self.tcp_ECN_Flag = ECN_Flag
        self.tcp_Urgent_Flag = Urgent_Flag
        self.tcp_Ack_Flag = Ack_Flag
        self.tcp_Push_Flag = Push_Flag
        self.tcp_Reset_Flag = Reset_Flag
        self.tcp_Syn_Flag = Syn_Flag
        self.tcp_Fin_Flag = Fin_Flag
        self.tcp_Window_Size = Window_Size
        self.tcp_Checksum = Checksum
        self.tcp_Urgent_Pointer = Urgent_Pointer
        self.tcp_Options = Options
        
        self.level3_packet_type="TCP"
        TCP.NumOfTCPPackets+=1
