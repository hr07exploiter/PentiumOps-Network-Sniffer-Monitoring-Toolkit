from lib.usefull import *
from lib.tcp import *
from lib.udp import *
from docs.pack1 import *
from lib.packFilter import * 

import socket,struct,textwrap
import sys,os
import time


#Reference: https://tools.ietf.org/html/rfc1340
eth_type = {'8':'IPv4(0x0800)','1544':'ARP (0x0806)','#': 'EEE 802.1Q (0x8100)','56710':'IPv6 (0x86DD)'}
protocol_no = {'1':'ICMP','2':'IGMP','3':'GGP','4':'IPV4','5':'ST','6':'TCP','7':'CBT','8':'EGP','9':'IGP','17':'UDP','41':'IPv6','58':'IPv6-ICMP','121':'SMP'}




# Unpack EtherNet Frame
# SYNC[8 BYTES] RECEIVER[6 BYTES] SENDER[6 BYTES] TYPE[2 BYTES] PAYLOAD[ IP/ARP frame + padding) CTC[4 BYTES]
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
	return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]


def ipv4_packet(newObject,data):
	version_header_length = ord(data[0])
	version = version_header_length>>4
	header_length = (version_header_length & 15)*4
	#ttl,proto,src,dest = struct.unpack("! 8x B B 2x 4s 4s",data[:20])
	tos,total_length,identification,flags_frag_offset,ttl,proto,header_checksum,src,dest = struct.unpack("! B H H H B B H 4s 4s",data[1:20])
	flags = flags_frag_offset
	x_flag =flags&(2**15)>>15
	d_flag = flags&(2**14)>>14
	m_flag =flags&(2**13)>>13
	frag_offset = flags_frag_offset&(2**13-1)
	src = ipv4(src)
	dest = ipv4(dest)

        newObject.setIPv4(proto,version,header_length,"0x%x(%d)"%(tos,tos),total_length,identification,x_flag,d_flag,m_flag,frag_offset,ttl,"{}({})".format(protocol_no["%d"%proto],proto),header_checksum,src,dest)
	return proto,data[header_length:],newObject



#unpack icmp packet
def icmp_packet(other_data,newObject):
        icmp_type_conv = {'0':'Echo (Ping) Reply','1':'Unassigned','2':'Unassigned','3':'Destination_Unreachable','4':'Source_Quench','5':'Redirect','6':'Alternate_Host_Address','7':'Unassigned','8':'Echo (Ping) Request','9':'Router_Advertisement','10':'Router_Selection','11':'Time_Exceeded','12':'Parameter_Problem','13':'Timestamp','14':'Timestamp_Replay','15':'Information_Request','16':'Information_Reply','17':'Address_Mask_Request','18':'Address_Mask_Reply','19':'Reserved(for Security)',('20','21','22','23','24','25','26','27','28','29'):'Reserved','30':'Traceroute','31':'Datagram_Conversion_Error','32':'Mobile_Host_Redirect','33':'IPv6_Where-Are-You','34':'IPv6 I-Am-Here','35':'Moblie_Registration_Request','36':'Mobile_Registration_Reply','37':'Domain_Name_Request','38':'Domain_Name_Reply','39':'SKIP','40':'Photuris','41':'ICMP_message_utilized_by_experimental_mobility_protocols_such_as_Seamoby'}
	icmp_type,code,checksum = struct.unpack("! B B H",other_data[:4])
        icmp_type,checksum = icmp_type_conv[str(icmp_type)],"0x%x"%checksum
#        outfile.write(blue_color+"[*]Internet Control Message Protocol[ICMP]:"+end_color)
#	outfile.write("\tICMP_type:",icmp_type,"  Code:",code,"  Checksum:",checksum)
        newObject.setICMP(icmp_type,code,checksum,str(other_data[4:]))
        return other_data[4:],newObject




#unpack IGMP Packet
def igmp_packet(data_2,newObject):
	igmp_type = {"11":"Membership Query (0x11)","16":"Membership Report(0x16)","17":"Leave Group (0x17)"}
	Type,max_resp_time,checksum,group_addr = struct.unpack("! B B H 4s",data_2[:8])
#        outfile.write(blue_color+"[*]Internet Group Management Protocol[IGMP]:"+end_color)
#	outfile.write("\tType:%s"%igmp_type["%x"%Type]+"  Max_Resp_Time:%.2fsec"%(max_resp_time/10)+"  Checksum:0x%x"%checksum+"  Group_address:"+ipv4(group_addr))
        newObject.setIGMP("%s"%igmp_type["%x"%Type],"%.2fsec"%(max_resp_time/10),"0x%x"%checksum,ipv4(group_addr),data_2[:8])
	return data_2[8:],newObject

def arp_packet(data_1,newObject):   #   //https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
	arp_hardware_type = {"1":"Ethernet(1)"}
	arp_op_code_type = {"1":"REQUEST(1)","2":"REPLY(2)"}
	hrd_type,proto_type,hrd_len,proto_len,opcode,sender_mac,sender_ip,dest_mac,dest_ip=struct.unpack("!HHBBH6s4s6s4s",data_1[:28])
#        outfile.write(blue_color,"[*]Address Resolution Protocol[",blue_color,"ARP]:",end_color)
#	outfile.write("\tHardware_type:",arp_hardware_type["%d"%hrd_type],"  Protocol_type:",eth_type["%d"%socket.htons(proto_type)],"  Hardware_size:",hrd_len,"  Protocol_size:",proto_len,"  Opcode:",arp_op_code_type["%d"%opcode]," Sender_Mac_addr:",get_mac_addr(sender_mac),"  Sender_IP:",yellow_color,ipv4(sender_ip),end_color,"  Target_Mac_addr:",get_mac_addr(dest_mac)," Target_IP:",yellow_color,ipv4(dest_ip),end_color)
        newObject.setARP(arp_hardware_type["%d"%hrd_type],eth_type["%d"%socket.htons(proto_type)],hrd_len,proto_len,arp_op_code_type["%d"%opcode],get_mac_addr(sender_mac),ipv4(sender_ip),get_mac_addr(dest_mac),ipv4(dest_ip))
        return newObject

def unpackEthernetPack(raw_data,doPrint,seloption):
   
    #raw = b' '.join(["%0X"%(ord(x)) for x in raw_data])
    #print "Raw data [hex] :", raw
    #binraw = b' '.join(["%s"%bin(int(ord(x)))[2:] for x in raw_data])
    #print "Raw dat [bin] :",binraw
    #print len(raw_data)
    dest_mac,src_mac,eth_proto,data_1 = ethernet_frame(raw_data)
    newObject = Ethernet(eth_proto,dest_mac,src_mac,eth_type["%d"%eth_proto],raw_data)
    #   outfile.write("-"*120)
#   outfile.write(blue_color+'\n[*]Ethernet Frame:\t'+end_color+'['+pink_color+src_mac+" ==> "+dest_mac+end_color+']')
    #eth_proto_conv = "%d"%eth_proto
#   outfile.write('\tProtocol:{}   Destination:{}   Source: {}'.format(eth_type["%d"%eth_proto],dest_mac,src_mac))
    if eth_proto == 8: #ipv4
	proto,data_2,newObject = ipv4_packet(newObject,data_1)
	if proto==1: #icmp -- ipv4
            data_3,newObject = icmp_packet(data_2,newObject)
	elif proto==2: #IGMP --ipv4
	    useless,newObject =  igmp_packet(data_2,newObject)
	    data_3 = ""
	elif proto==6:  #tcp -- ipv4
	    
            tcp_segment(data_2,newObject)
             
	elif proto==17: #udp -- ipv4
	    data_3,src_port,dest_port,length = udp_packet(data_2,newObject)
	    check_udp(data_3,src_port,dest_port,length,newObject)
                               
	else:
	    data_3 =data_2
		#	    print format_multi_line("\t\t",data_3)
    elif eth_proto == 1544: #ARP
        newObject = arp_packet(data_1,newObject)	
                       
    elif eth_proto == 56710: #ipv6
	    #       outfile.write(red_color+"This is IPv6 packet..!You haven't Implemented yet!"+end_color)
        pass
    else:
        pass
    if doPrint==1:
        printPacket(newObject,seloption)
            
    sys.stdout.flush()
    packets.append(newObject)


def filter(firstVisit=1):
    global Depth,Num,Type
    if firstVisit:
        print pink_color,"\n-----------------------PACKET FILTER----------------------",end_color
        print "[*]",yellow_color,"Here you can filter the captured packets. Type 'help' for more info.",end_color
    loop=1
    flag=1
    while loop :
        Depth='1'
        Num=[]
        Type=[]
        filterKey = raw_input(red_color+"filter"+blue_color+"@PentiumOps >"+end_color).strip()
        if(len(filterKey)!=0):
            loop=0
            if filterKey.find('help')!=-1:
                flag=0
                loop=1
                print "[*]",pink_color,"FILTER OPTIONS:",end_color
                filterOptions = open('./banners/filterOptions.txt','r')
                print filterOptions.read()
            if filterKey.find("num")!=-1:
                flag=0
                try:
                    valueIndex=filterKey.find("num")
                    valueIndex+=4
                    index=valueIndex
                    loopIt=1
                    while(index<len(filterKey) and loopIt):
                        while(index<len(filterKey) and filterKey[index]!=" " and filterKey[index]!=","): 
                            index+=1
                        value=filterKey[valueIndex:index]
                        if(index<len(filterKey) and filterKey[index]==" "): loopIt=0
                        index+=1
                        if len(value)!=0:
                            Num.append(int(value))
                        else:
                            print "[-]",red_color,"num is invalid...",end_color
                            loop=1
                        valueIndex=index
                except:
                    print red_color,"There should not be any space around \"=\" and \",\"",end_color
                    loop=1
            if filterKey.find("depth")!=-1:
                flag=0
                try:
                    valueIndex=filterKey.find("depth")
                    valueIndex+=6
                    if valueIndex<len(filterKey):
                        value = filterKey[valueIndex]
                        
                    if value=='1' or value=='2' or value=='3':
                        Depth = value
                    else:
                        print "[-]",red_color,"depth is Invalid...",end_color
                        loop=1
                except:
                    print red_color,"There should not be any space around \"=\"",end_color
            if filterKey.find("shell")!=-1:
                flag=0
                os.system(filterKey[filterKey.find("shell")+6:])
            if filterKey.find("type")!=-1:
                flag=0
                
                try:
                    valueIndex=filterKey.find("type")
                    valueIndex+=5
                    index=valueIndex
                    loopIt=1
                    while(index<len(filterKey) and loopIt):
                        while(index<len(filterKey) and filterKey[index]!=" " and filterKey[index]!=","): 
                            index+=1
                        value=filterKey[valueIndex:index]
                        if(index<len(filterKey) and filterKey[index]==" "): loopIt=0
                        index+=1
                        if len(value)!=0:
                            Type.append(value)
                        else:
                            print "[-]",red_color,"type is invalid...",end_color
                            loop=1
                        valueIndex=index
                except:
                    print red_color,"There should not be any space around \"=\" and \",\"",end_color
                    loop=1
            
            
            if flag:
                loop=1
                print "[-]",red_color,"Sorry...This filter is invalid",end_color


def staticFilter(startIndex=0):
    global Depth,Num,Type
    if len(Num)!=0:
        if Num[0]!=0:
            for number in Num:
                if number-1<len(packets) and number-1>=0 and number-1>=startIndex:
                    printPacket(packets[number-1],Depth)
        else:
            for number in range(startIndex,len(packets)):
                printPacket(packets[number],Depth)
    if len(Type)!=0:
        
        if Type[0]=='all':
            for typePacket in packets:
                printPacket(typePacket,Depth)
        else:
            for single_packet in packets:
                level_packet_types = single_packet.level1_packet_type+" "+single_packet.level2_packet_type+" "+single_packet.level3_packet_type+" "+single_packet.level4_packet_type
                for oneType in Type:
                    if level_packet_types.lower().find(oneType.lower())!=-1:
                        printPacket(single_packet,Depth)
                        break

        



sys.stderr = open("errorLog",'w')

packets = []
Num = []
Type = []
Depth ='1'

if __name__ == '__main__':
    
    fd = open('sniffingdepth','r')
    loading = open('loading','r')
    
    seloption = fd.read()[0]
    loadoption = loading.read()[0]
    

    if loadoption == '0':    
        conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
        while True:
            try:
                
	        raw_data,addr=  conn.recvfrom(65535)
                unpackEthernetPack(raw_data,1,seloption)
                start  = "-"*20
                raw = open('output.raw','a')
                raw.write(raw_data+start)
                raw.close()
            except KeyboardInterrupt:
                raw.write('pentiumopsend')
                print green_color,"Exiting Network Sniffer.....:)",end_color
                sys.exit(0)
        raw.close()
    elif loadoption == '1':
        isfile = open('fromFile','r')
        fromFile = isfile.read()[0]
        if fromFile=='1':
            print "[*]",purple_color,"File has been loaded...!Now you can filter packets for analysis...:)",end_color
        startindex = 0
        lastindex = -1
        index = 0
        data=''
        doloop=1
        firstTime=1
        while doloop:
            

            if(fromFile=='1'):
                doloop=0;
            try:
                raw = open('output.raw','r')
                data = raw.read()
                raw.close()
                
                while(index<=len(data)):
                    if data[index:index+6]=='pentiumopsend':
                         break
                    
                    if data[index:index+20]=='-'*20:
                        
                        lastindex = index
                        try:
                            unpackEthernetPack(data[startindex:lastindex],0,Depth)
                        except:
                            junk = "Best sona"
                        startindex = lastindex+20
                    index+=1

            except:
                print green_color,"\nExiting Filter....",end_color
                #sys.exit(0)
                break
            filter(firstTime)
            firstTime=0
            staticFilter()
    
        if(fromFile=='1'):
            try:
                while True:
                    filter(0)
                    staticFilter()
            except:
                print green_color,"\nExiting Filter....",end_color

                
        

            
        
