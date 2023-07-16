#variables
show_dns = 1
import struct
import textwrap

#colors
end_color = "\033[0;38;49m\033[39;49m "
green_color = "\033[1;32;49m"
blue_color = "\033[1;36;49m"
red_color = "\033[1;31;49m"
yellow_color = "\033[1;33;49m"
pink_color = "\033[1;35;49m"
purple_color = "\033[1;34;49m"


#Return properly formatted MAC address AA:BB:CC:DD:EE:FF
def get_mac_addr(bytes_addr):
#	bytes_str = map('{:02x}'.format,bytes_addr)
	bytes_str = b':'.join(["%02X"%(ord(x)) for x in bytes_addr])
	return bytes_str.upper()

def ipv4(addr):
	return '.'.join(str(ord(x)) for x in addr)

def ipv6(addr):
	return ':'.join(["%02x%02x"%(ord(addr[i]),ord(addr[i+1])) for i in range(0,16,2)])


#format multi-line data
def format_multi_line(prefix,string,size=40):
	#size-=len(prefix)
        hex_f=""
        text_f=""
	if isinstance(string,bytes):
		hex_f =  ' '.join([r"%02x"%ord(byte) for byte in string])
		text_f = ''.join([r"%s"%x if 32<=ord(x)<=128 else "." for x in string])
		if size%2:
			size-=1
	len_t = 0
	req = ""
	for line in textwrap.wrap(hex_f,size):
		req+= "\n\t%s     %s"%(line,text_f[len_t:len_t+13])
		len_t+=13
	return req

def is_bit_set(value,pos,no_bits):
	#print value,"by",pos
	#print len(bin(value)[2:])
	if value&(2**(no_bits-pos))>0:
		return 1
	else:
		return 0


def printPacket(Object,option):
    packet_type="NULL"
    if(Object.level1_packet_type!=""):
        packet_type=Object.level1_packet_type
        if(Object.level2_packet_type!=""):
            packet_type=Object.level2_packet_type
            if(Object.level3_packet_type!=""):
                packet_type=Object.level3_packet_type
                if(Object.level4_packet_type!=""):
                    packet_type=Object.level4_packet_type

    #print 'packet print'
    
    if option == '3':   #print packet in hex format
        print "--",Object.packetNumber,"-"*100
        print format_multi_line("\t\t",Object.raw)
    elif option == '2':   #print whole packet
        
        print "--",Object.packetNumber,"-"*100
	print blue_color,'\n[*]Ethernet Frame:\t',end_color,'[',pink_color,Object.src_mac," ==> ",Object.dest_mac,end_color,']' 
	print '\tProtocol:{}   Destination:{}   Source: {}'.format(Object.protocol_type,Object.dest_mac,Object.src_mac)
        eth_proto = Object.eth_proto
        if eth_proto == 8:     #ipv4
            proto = Object.proto
	    print blue_color,"[*]Internet Protocol Version 4[IPv4]",end_color,":  [",pink_color,Object.source," ==> ",Object.destination,end_color,"]"
            print "\tversion:{}  header_length:{}Bytes".format(Object.version,Object.headerLength)," Type_of_Service[TOS]:",Object.typeOfService," Total_Length:{}".format(Object.totalLength)," Identification:",Object.identification," Reserverd_bit[x]:",Object.reservedBit," Don't_fragment[d]:",Object.dontFragment," More_fragments[m]:",Object.moreFragment," Fragment_offset:",Object.fragmentOffset," time_to_leave[TTL]:",Object.timeToLeave," protocol:",Object.protocol," Header_Checksum:0x%x"%Object.headerChecksum," source:",Object.source," destination:",Object.destination
	    if proto==1:     #icmp -- ipv4
	        print blue_color,"[*]Internet Control Message Protocol[ICMP]:",end_color
                print "\tICMP_type:",Object.ICMP_type,"  Code:",Object.Code,"  Checksum:",Object.Checksum
	    elif proto==2:		#IGMP --ipv4
                print blue_color,"[*]Internet Group Management Protocol[IGMP]:",end_color
                print "\tType:",Object.Type,"  Max_Resp_Time:",Object.Max_Resp_Time,"  Checksum:",Object.Checksum,"  Group_address:",Object.Group_address 
	    
	    elif proto==6:	 #tcp -- ipv4
                print blue_color,"[*]Transmission control Protocol[TCP]",end_color,": [",pink_color,Object.tcp_Source_Port," ==> ",Object.tcp_Destination_Port,end_color,"]"
                InitData = "\tSrc Port:"+str(Object.tcp_Source_Port)+"  Dest Port:"+str(Object.tcp_Destination_Port)+"  Seq Num:"+str(Object.tcp_Seq_Num)+"  Ack Num:"+str(Object.tcp_Ack_Num)+"  Header Len:"+str(Object.tcp_Header_Length)
                tcp_flags = blue_color+"  FLAGS:- "+end_color
                
                if(Object.tcp_Res_Flag): tcp_flags+=green_color+" RESERVED:"+str(Object.tcp_Res_Flag)+end_color 
                else: tcp_flags+=" RESERVED:"+str(Object.tcp_Res_Flag)
                if(Object.tcp_Nounce_Flag): tcp_flags+=green_color+" NOUNCE:1"+end_color 
                else: tcp_flags+=" NOUNCE:0"
                if(Object.tcp_CWR_Flag): tcp_flags+=green_color+" CWR:1"+end_color 
                else: tcp_flags+=" CWR:0"
                if(Object.tcp_ECN_Flag): tcp_flags+=green_color+" ECN:1"+end_color 
                else: tcp_flags+=" ECN:0"
                if(Object.tcp_Urgent_Flag): tcp_flags+=green_color+" URG:1"+end_color 
                else: tcp_flags+=" URG:0"
                if(Object.tcp_Ack_Flag): tcp_flags+=green_color+" ACK:1"+end_color 
                else: tcp_flags+=" ACK:0"
                if(Object.tcp_Push_Flag): tcp_flags+=green_color+" PUSH:1"+end_color 
                else: tcp_flags+=" PUSH:0"
                if(Object.tcp_Reset_Flag): tcp_flags+=green_color+" RESET:1"+end_color 
                else: tcp_flags+=" RESET:0"
                if(Object.tcp_Syn_Flag): tcp_flags+=green_color+" SYN:1"+end_color 
                else: tcp_flags+=" SYN:0"
                if(Object.tcp_Fin_Flag): tcp_flags+=green_color+" FIN:1"+end_color 
                else: tcp_flags+=" FIN:0"
                print InitData,tcp_flags,"  Wnd Size:",Object.tcp_Window_Size,"  Checksum:",Object.tcp_Checksum,"  Urg Pointer:",Object.tcp_Urgent_Pointer
                if(Object.tcp_Options!=""): print Object.tcp_Options

                if Object.level4_packet_type=="HTTP":
                    print blue_color,"[*] HyperText Trasfer Protocol[HTTP]:",end_color
                    print "\t",Object.http_data
	    elif proto==17:   #udp -- ipv4
	        if Object.Source_Port=='1900' or Object.Destination_Port == '1900':  #SSDP
                    print blue_color+"[*]Simple Service Discovery Protocol[SSDP]:"+end_color 
                    ssdpdata = ""
                    for line in Object.ssdpdata.split("\t"):
                        print line
                elif Object.Source_Port in ['67','68'] or Object.Destination_Port in ['67','68']:#DHCP
                    
                    print blue_color,"[*]BootStrap Protocol [DHCP]:\t",end_color,Object.msg_type,Object.hrdwr_type,Object.hrdwr_addr_len,Object.hops,Object.trans_id,Object.sec_elapsed,Object.boot_flags,Object.client_ip,Object.your_ip,Object.next_server_ip,Object.relay_agent,Object.client_mac,Object.client_hrdwr_addr_pad,Object.server_hostname,Object.bootfile_name,Object.magic_cookie,Object.options

                elif Object.Source_Port in ['546','547'] or Object.Destination_Port in ['546','547']:
                    print '{:<6} '.format('DHCPV6 Not Implement yet!')
                elif Object.Source_Port =='53' or Object.Destination_Port =='53': #DNS
                    #data+='{:<6} '.format('DNS')
                    print blue_color+"[*]Domain Name System[DNS]:"+end_color
                    print '\t',Object.Response,Object.OpCode,Object.Authoritative,Object.Truncated,Object.Recursion,Object.AvailRecursion,Object.Z,Object.AnsAuth,Object.NonAuth,Object.Transaction_ID,Object.Reply_code,Object.Queries_count,Object.Answers_count,Object.Authority_count,Object.Additional_info_count,Object.queries,Object.answers,Object.auth_answers,Object.addi_answers

                else:
                    print red_color+"data to this udp port haven't been implemented yet!"+end_color

	    else:
		data_3 =data_2
#		print format_multi_line("\t\t",data_3)
	elif eth_proto == 1544:  #ARP
            print blue_color,"[*]Address Resolution Protocol[",blue_color,"ARP]:",end_color
	    print "\tHardware_type:",Object.hardwareType,"  Protocol_type:",Object.protocolType,"  Hardware_size:",Object.hardwareSize,"  Protocol_size:",Object.protocolSize,"  Opcode:",Object.opcode," Sender_Mac_addr:",Object.senderMACAddr,"  Sender_IP:",yellow_color,Object.senderIPAddr,end_color,"  Target_Mac_addr:",Object.targetMACAddr," Target_IP:",yellow_color,Object.targetIPAddr,end_color
        elif eth_proto == 56710:  #ipv6 
	    print red_color+"This is IPv6 packet..!You haven't Implemented yet!"+end_color
	else: 	#EEE 802.1Q (0x8100)
	    print red_color+"This is EEE 802.1Q packet...!You haven't Implemented yet!"+end_color


    elif option == '1':   #print  packet in single line
    
        data = "{} ".format(Object.packetNumber).rjust(6)
        #eth_data="{} {} ==> {}".format(Object.protocol_type.split('(')[0],Object.dest_mac,Object.src_mac)
        eth_proto = Object.eth_proto
        if eth_proto == 8:     #ipv4
            proto = Object.proto
            data+='{:<17} ==> {:<17} '.format(Object.source,Object.destination)
            
	    if proto==1:     #icmp -- ipv4
                data+='{:<6} {} {} {}'.format(packet_type,Object.ICMP_type,Object.Code,Object.Checksum)
	    elif proto==2:		#IGMP --ipv4
                data+='{:<6} {} checksum:{} Multicast_Address:{}'.format(packet_type+"v2",Object.Type,Object.Checksum,Object.Group_address)
	    
	    elif proto==6:	 #tcp -- ipv4
                data+='{:<6}'.format(packet_type)
                if packet_type=='TCP':
                    tcp_flags=green_color
                    if(Object.tcp_Res_Flag): tcp_flags+="[RESERVED]"
                    if(Object.tcp_Nounce_Flag): tcp_flags+="[NOUNCE]"
                    if(Object.tcp_CWR_Flag): tcp_flags+="[CWR]"
                    if(Object.tcp_ECN_Flag): tcp_flags+="[ECN]"
                    if(Object.tcp_Urgent_Flag): tcp_flags+="[URG]"
                    if(Object.tcp_Ack_Flag): tcp_flags+="[ACK]"
                    if(Object.tcp_Push_Flag): tcp_flags+="[PUSH]"
                    if(Object.tcp_Reset_Flag): tcp_flags+="[RESET]"
                    if(Object.tcp_Syn_Flag): tcp_flags+="[SYN]"
                    if(Object.tcp_Fin_Flag): tcp_flags+="[FIN]"
                    tcp_flags+=end_color
                    data+=tcp_flags
                    data+=" Seq="+str(Object.tcp_Seq_Num)+" Ack="+str(Object.tcp_Ack_Num)+" Wnd="+str(Object.tcp_Window_Size)
                elif packet_type=='HTTP':
                    data_tmp=Object.http_data.split('\r\n')[0]
                    if len(data_tmp)>20 :
                        data+=data_tmp[:15]
                    else:
                        data+=data_tmp
                    #dataTemp =Object.http_data.split('\r\n')[0]
                    #data+=dataTemp[:min(30,len(dataTemp))]
                
	    elif proto==17:   #udp -- ipv4
                #print 'src_port = ',Object.Source_Port,'Dest',Object.Destination_Port
                if Object.Source_Port=='1900' or Object.Destination_Port == '1900':  #SSDP
                    data+='{:<6} '.format(packet_type)
                elif Object.Source_Port in ['67','68'] or Object.Destination_Port in ['67','68']:    #dhcp
                    if Object.options.find('Message_type:Discover')!=-1:
                        msgtype = 'Discover'
                    elif Object.options.find('Message_type:Offer')!=-1:
                        msgtype = 'Offer'
                    elif Object.options.find('Message_type:Request')!=-1:
                        msgtype = 'Request'
                    elif Object.options.find('Message_type:Decline')!=-1:
                        msgtype = 'Decline'
                    elif Object.options.find('Message_type:Pack')!=-1:
                        msgtype = 'Pack'
                    elif Object.options.find('Message_type:Pnak')!=-1:
                        msgtype = 'Pnak'
                    elif Object.options.find('Message_type:Release')!=-1:
                        msgtype = 'Release'
                    elif Object.options.find('Message_type:Inform')!=-1:
                        msgtype = 'Inform'
                    else:
                        msgtype = 'Not known'

                    data+='{:<6} {} -Transaction ID:{}'.format(packet_type,msgtype,Object.trans_id.split(':')[1])
                elif Object.Source_Port in ['546','547'] or Object.Destination_Port in ['546','547']:   #dhcpv6
                    data+='{:<6} '.format('DHCPV6')
                elif Object.Source_Port == '53' or Object.Destination_Port == '53':     #dns
                    data+='{:<6} {} {} {} {}'.format(packet_type,Object.Response.split(':')[1],Object.Transaction_ID,Object.queries.split(':')[3].split('[')[1],Object.queries.split(':')[2].split(' ')[0])
                else:
                    data+=red_color+"data to this udp port haven't been implemented yet!"+end_color
	    else:
		data_3 =data_2
		print format_multi_line("\t\t",data_3)
	elif eth_proto == 1544:  #ARP
            data+='{:<17} ==> {:<17} '.format(Object.senderMACAddr,Object.targetMACAddr)
            if Object.opcode == 'REQUEST(1)':
                data+='{:<6} Who has {}? Tell {} '.format('ARP',Object.targetIPAddr,Object.senderIPAddr)
            elif Object.opcode == 'REPLY(2)':
                data+='{:<6} {} is at {} '.format('ARP',Object.senderIPAddr,Object.senderMACAddr)
            #data+='ARP {} {} {} {} {} {} {} {}'.format(Object.hardwareType,Object.protocolType,Object.opcode,Object.senderMACAddr,"(",Object.senderIPAddr,")==>",Object.targetMACAddr,"(",Object.targetIPAddr,")")
        elif eth_proto == 56710:  #ipv6 
	    data+= red_color+"This is IPv6 packet..!You haven't Implemented yet!"+end_color
	else: 	#EEE 802.1Q (0x8100)
	    data+=red_color+"This is EEE 802.1Q packet...!You haven't Implemented yet!"+end_color
        print data
    else:
        print "Check the arguments passed to printPacket function"
