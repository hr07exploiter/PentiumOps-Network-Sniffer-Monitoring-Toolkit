from usefull import *



import socket,struct,textwrap



def dhcp(data_3,newObject):
    dhcp_message_type = {'1':'Boot_Request(1)','2':'Boot_Reply(2)'}
    dhcp_hardware_type = {'1':'Ethernet(1)'}
    msg_type,hrdwr_type,hrdwr_addr_len,hops,trans_id,sec_elapsed,flags,c_ip_addr,your_ip_addr,next_serv_ip_addr,relay_ip_addr,c_mac_addr,c_hrdwr_addr_padd,serv_host_name,boot_file_name,magic_1,magic_2,magic_3,magic_4 = struct.unpack("!B B B B L H H 4s 4s 4s 4s 6s 10s 64s 128s s s s s ",data_3[0:240])
    msg_type = "Msg_type:{}{}{}".format(pink_color,dhcp_message_type["%d"%msg_type],end_color)
    hrdwr_type = "Hardware_type:{}".format(dhcp_hardware_type["%d"%hrdwr_type])
    hrdwr_addr_len = "Hardware_addr_len:{}".format(hrdwr_addr_len)
    hops = "Hops:{}".format(hops)
    trans_id = "Transaction_ID:0x%x"%trans_id
    sec_elapsed ="Seconds_elapsed:{}".format(sec_elapsed)
    if (flags&(2**15))>>15:
        broadcast_flag = "Broadcast_flag:{}Broadcast(1){}".format(yellow_color,end_color)
    else:
        broadcast_flag = "Broadcast_flag:{}Unicast(0){}".format(yellow_color,end_color)
    flags = broadcast_flag+"Reserved_flag:0x%x"%flags
    c_ip_addr = "Client_IP_addr:{}".format(ipv4(c_ip_addr))
    your_ip_addr = "your(client)_IP_addr:{}".format(ipv4(your_ip_addr))
    next_serv_ip_addr = "Next_server_IP_addr:{}".format(ipv4(next_serv_ip_addr))
    relay_ip_addr = "Relay_agent_IP_addr:{}".format(ipv4(relay_ip_addr))
    c_mac_addr = "Client_mac_addr:{}".format(get_mac_addr(c_mac_addr))
    c_hrdwr_addr_padd = "Client_hardware_addr_padding:{}".format(c_hrdwr_addr_padd)
    serv_host_name = "Server_host_name:{}".format(get_file_name(serv_host_name))
    boot_file_name = "Boot_file_name:{}".format(get_file_name(boot_file_name))
    magic_cookie = "Magic_cookie:"+end_color+get_magic_cookie(magic_1,magic_2,magic_3,magic_4)
    options = get_options(data_3[240:])
    #print blue_color,"[*]BootStrap Protocol [DHCP]\t",end_color,msg_type,hrdwr_type,hrdwr_addr_len,hops,trans_id,sec_elapsed,flags,c_ip_addr,your_ip_addr,next_serv_ip_addr,relay_ip_addr,c_mac_addr,c_hrdwr_addr_padd,serv_host_name,boot_file_name,magic_cookie,options
    newObject.setDHCP(msg_type,hrdwr_type,hrdwr_addr_len,hops,trans_id,sec_elapsed,flags,c_ip_addr,your_ip_addr,next_serv_ip_addr,relay_ip_addr,c_mac_addr,c_hrdwr_addr_padd,serv_host_name,boot_file_name,magic_cookie,options)
    
def get_options(data_3):
    dhcp_opcode=  {'1':'Subnet_Mask(1)','2':'Time_offset(2)','3':'Router(3)','4':'Time_server(4)','5':'Name_server(5)','6':'Domain_name_server(6)','7':'Log_server(7)','8':'Cookie_server(8)','9':'LPR_server(9)','10':'Impress_server(10)','11':'Resource_Location_server(11)','12':'Host_name(12)','13':'Boot_file_size(13)','14':'Merit_dump_file(14)','15':'Domain_name(15)','16':'swap_server(16)','17':'Root_path(17)','18':'Extension_path','19':'IP_forwarding(19)','20':'Non-Local_source_routing(20)','21':'Policy_filter(21)','22':'Max_datagram_reassemblu_size(22)','23':'Default_IP_ttl(23)','24':'Path_MTU_aging_timeout(24)','25':'Path_MTU_plateau_table(25)','26':'Interface_MTU(26)','27':'All_subnets_are_local(27)','28':'Broadcast_address(28)','29':'Perform_Mask_Discovery(29)','30':'Mask_supplier_option(30)','31':'Perform_router_discovery(31)','32':'Router_socilitation_address(32)','33':'Static_route(33)','34':'Link_layer_parameters_per_interface','35':'ARP_cache_timeout(35)','36':'Ehternet_Encapsulation(36)','37':'TCP_parameters(37)','38':'TCP_keepalive_interval(38)','39':'TCP_keepalive_garbage(39)','40':'Application_and_service_domain(40)','41':'Network_info_servers(41)','42':'Network_time_protocol_servers(42)','43':'Vendor_specific_info(43)','44':'NetBIOS_over_TCP/IP_NS(44)','45':'NetBIOS_over_TCP/IP_Datagram_distribution_server(45)','46':'NetBIOS_over_TCP/IP_node_type(46)','47':'NetBIOS_over_TCP/IP_scope(47)','48':'X_window_sys_font_server(48)','49':'X_window_sys_Display_manager(49)','50':'Requested_IP_addr(50)','51':'IP_addr_lease_time(51)','52':'Option_overload(52)','53':'DHCP_message_type','54':'Server_Identifier(54)','55':'Parameter_request_list(55)','56':'Message(56)','57':'Max_DHCP_message_size(57)','58':'Renewal_time[T1]_value(58)','59':'Rebinding_time[T2]_value(59)','60':'Vendor_clalss_identifier(60)','61':'Client_identifier(61)','64':'Network_info_Service+Domain(64)','65':'Network_info_Service+servers(65)','66':'TFTP_server_name(66)','67':'Bootfile_name(67)','68':'Mobile_IP_HomeAgent(68)','69':'SMTP_server(69)','70':'POP3_server(70)','71':'NNTP_server(71)','72':'Default_WWW_server(72)','73':'Default_Finger_server(73)','74':'Default_IRC_server(74)','75':'StreetTalk_server(75)','76':'STDA_server(76)','119':'Domain_search(119)','121':'Classeless_static_route(121)','249':'Private/Classless_static_Route(mircosoft)(249)','252':'Private/Proxy autodiscovery(252)',}
    length = len(data_3)
    index = 0
    padding = "Padding:"
    options = yellow_color+"Options:-"+end_color
    while(index<length-1):
        code = struct.unpack("!B",data_3[index])[0]
        index+=1
        if code==0: #padding
            padding+='0'
        elif code==255:  #End
            options+="  End(255)"
        elif code==1:  #Subnet Mask
            index,option_len,subnet_mask = get_serv_addrs(data_3,index) 
            options+="  Subnet_mask:{}".format(subnet_mask)
        elif code==2:  #Time offset
            print "  Time_offset:{}".format(struct.unpack("!L",data[index+1:index+5]))
            index+=5
        elif code==3: #Router OPtion
            index,option_len,router_addrs = get_serv_addrs(data_3,index)
            options+="  Router:{}".format(router_addrs)
        elif code==5:   #Name Server Option
            index,option_len,NS_addrs = get_serv_addrs(data_3,index)
            options+="  Name_servers:{}".format(NS_addrs)
        elif code==6:   #Domain Name Server Option
            index,option_len,dns_addr = get_serv_addrs(data_3,index)
            options+="  DNS_servers:{}".format(dns_addr)
        elif code==7:   #Log Server Option
            index,option_len,Log_servs = get_serv_addrs(data_3,index)
            options+="  Log_servers:{}".format(Log_servs)
        elif code==8:  #Cookie Server Option
            index,option_len,cookie_servs = get_serv_addrs(data_3,index)
            options+="  Cookie_servers:{}".format(cookie_servs)
        elif code==9:   #LPR Server Option
            index,option_len,lpr_servs = get_serv_addrs(data_3,index)
            options+="  LPR_servers:{}".format(lpr_servs)
        elif code==10: #Impress Server Option
            index,option_len,impress_servs = get_serv_addrs(data_3,index)
            options+="  Impress_servers:{}".format(impress_servs)
        elif code==12:  #Host Name
            index,option_len,name = get_path_name(data_3,index)
            options+="  Host_name:{}".format(name)
        elif code==13: #Boot file size
            options+="  Boot_file_size:{}".format(struct.unpack("!H",data_3[index+1:index+3][0]))
            index+=3
        elif code==14: #Merit Dump File
            index,option_len,name = get_path_name(data_3,index)
            options+="  Merit_Dump_file:{}".format(name)
        elif code==15:  #Domain Name
            index,option_len,name = get_path_name(data_3,index)
            options+="  Domain_name:{}".format(name)           
        elif code==16:  #swap server
            index,option_len,server = get_serv_addrs(data_3,index)
            options+="  Swap_server:{}".format(server)
        elif code==17:  #Root Path
            index,option_len,path=get_path_name(data_3,index)
            options+="  Root_Disk_path:{}".format(path)
        elif code==18:   #Extensions Path
            index,option_len,path=get_path_name(data_3,index)
            options+="  Extensions_path:{}".format(path)
        elif code==19:  #IP Forwarding Enable/Disable Option
            result =  "Enabled" if struct.unpack("!B",data_3[index+1])[0] else "Disabled"
            index+=2
            options+="  IP_Forwarding:{}".format(result)
        elif code==20:  #Non-local source routing Enable/Disable
            result = "Enabled" if struct.unpack("!B",data_3[index+1])[0] else "Disabled"
            index+=2
            options+="  Non-Local_source_routing:{}".format(result)
        elif code==21:  #Policy_filter
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Policy_filter:{}".format(addr)
        elif code==22:  #Max_datagram_reassembly_size
            size = struct.unpack("!H",data_3[index+1:index+3])[0]
            index+=3
            options+="  Max_datagram_reassembly_size:{}".format(size)
        elif code==23:  #Default_IP_time to live
            ttl = struct.unpack("!B",data_3[index+1])
            index+=2
            options+="  Default_IP_TTL:{}".format(ttl)
        elif code==24:  #Path_MTU_aging_timeout
            timeout = struct.unpack("!L",data_3[index+1:index+5])[0]
            index+=5
            options+="  Path_MTU_aging_timeout:{}".format(timeout)
        elif code==25:  #Path_MTU_Plateau_table
            option_len = struct.unpack("!B",data_3[index])
            index+=1
            table = ""
            for i in range(index,index+option_len):
                table+="%d,"%(struct.unpack("!B",data_3[index])[0])
            options+=" Path_MTU_Plateau_table:{}".format(table)
        elif code==26:  #Interface_MTU
            mtu = struct.unpack("!H",data_3[index+1:index+3])[0]
            index+=3
            options+="  Interface_MTU:{}".format(mtu)
        elif code==27:  #All_subnets_are_local
            resutl = "all_subnets_share_same_MTU" if struct.unpack("!B",data_3[index+1])[0] else "all_subnets_don't_share_same_MTU"
            index+=2
            options+="  All_subnets_are_local:{}".format(result)
        elif code==28:  #Broadcast Address
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Broadcast_addr:{}".format(addr)
        elif code==29: #perform_Mask_Discovery  ie,1 indicates client can perform mask discovery using ICMP and 0 opposite
            value = struct.unpack("!B",data_3[index+1])[0]
            options+="  Perform_Mask_discovery:{}".format(value)
            index+=2
        elif code==30:  #Mask_Supplier 
            value = struct.unpack("!B",data_3[index+1])[0]
            options+="  Mask_supplier:{}".format(value)
            index+=2
        elif code==31:  #Perform router discovery 
            value = struct.unpack("!B",data_3[index+1])[0]
            options+="  Perform_router_discovery:{}".format(value)
            index+=2
        elif code==32:  #Router Solicitation Address
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Router_Solicitation_addr:{}".format(addr)
        elif code==33:  #Static Route
            index,option_len,addrs = get_serv_addrs(data_3,index)
            options+="  Static_Route:{}".format(addrs)
        elif code==34:  #Trailer_Encapsulation
            value = struct.unpack("!B",data_3[index+1])[0]
            options+="  Trailer_Encapsulation:{}".format(value)
        elif code==35:  #ARP Cache Timeout
            value = struct.unpack("!L",data_3[index+1:index+5])[0]
            index+=5
            options+="  ARP_Cache_Timeout:{}s".format(value)
        elif code==36:   #Ethernet_Encapsultion
            value = struct.unpack("!B",data_3[index+1])[0]
            index+=2
            options+="  Ethernet_Encapsulation:{}".format(value)
        elif code==37:  #TCP Default TTL
            value = struct.unpack("!B",data_3[index+1])[0]
            index+=2
            options+="  TCP_default_TTL:{}".format(value)
        elif code==38:  #TCP Keepalive Interval
            value = struct.unpack("!L",data_3[index+1:index+5])[0]
            index+=5
            options+="  TCP_Keepalive_Interval:{}".format(value)
        elif code==39:  #TCP Keepalive garbage
            value = struct.unpack("!B",data_3[index+1])[0]
            index+=2
            options+="  TCP_Keepalive_garbage:{}".format(value)
        elif code==40:  #Network Information Service domain
            index,option_len,name = get_path_name(data_3,index)
            options+="  Network_Info_Service_domain:{}".format(name)
        elif code==41:  #Network Information Servers
            index,option_len,addrs = get_serv_addrs(data_3,index)
            options+="  Network_info_servers:{}".format(addrs)
        elif code==42:  #Network Time Protocol servers
            index,option_len,addrs = get_serv_addrs(data_3,index)
            options+="  Network_Time_Protocol_servers:{}".format(addrs)
        elif code==43:  #Vendor Specific Information
            option_len = struct.unpack("!B",data_3[index])[0]
            index+=option_len+1
            options+= red_color+" Vendor_Specific_Info is not implemented Yet!"+end_color
        elif code==44:  #NetBIOS_over_TCP/IP_NS
            index,option_len,addrs = get_serv_addrs(data_3,index)
            options+="  NetBIOS_over_TCP/IP_NS:{}".format(addrs)
        elif code==45:  #NetBIOS ovet TCP/IP datagram distributionserver
            index,option_len,addrs = get_serv_addrs(data_3,index)
            options+="  NetBIOS_over_TCP/IP_Datagram_Distribution_server:{}".format(addrs)
        elif code==46:  #NetBIOS_over_TCP/IP_Node_type
            NetBIOS_nodetypes = {'1':'B-node(1)','2':'P-node(2)','4':'M-node(4)','8':'M-node(8)'}
            node_type = struct.unpack("!B",data_3[index+1])[0]
            index+=2
            options+="  NetBIOS_Node_type:{}".format(NetBIOS_nodetype["%d"%node_type])
        elif code==47:  #NetBIOS_over_TCP/IP_Socpe
            option_len = struct.unpack("!B",data_3[index])
            index+=options_len+1
            options+= red_color+"NetBIOS_over_TCP/IP_Scope is not Implemented Yet!"+end_color
        elif code==48:  #X window system font server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  X_window_system_font_server:{}".format(addr)
        elif code==49:  #X window system display manager
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  X_window_system_display_manager:{}".format(addr)
        elif code==50:  #Requested IP address
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Requested_IP_addr:{}".format(addr)
        elif code==51:  #IP Address Lease Time
            options+="  Lease_time:{}s".format(struct.unpack("!L",data_3[index+1:index+5])[0])
            index+=5
        elif code==53: #DHCP message type
            dhcp_msg_types = {'1':'Discover','2':'Offer','3':'Request','4':'Decline','5':'Pack','6':'Pnak','7':'Release','8':'Inform'}
            type = struct.unpack("!B",data_3[index+1])
            options+="  Message_type:{}".format(dhcp_msg_types["%d"%type])
            index+=2
        elif code==54: #Server Identifier
            options+="  Server_identifier_Addr:{}".format(ipv4(struct.unpack("!4s",data_3[index+1:index+5])[0]))
            index+=5
        elif code==55:  #Parameter_Request-list
            option_len = struct.unpack("!B",data_3[index])[0]
            index+=1
            parameter_list = ""
            for i in range(index,index+option_len):
                parameter_list+=","+dhcp_opcode["%s"%(struct.unpack("!B",data_3[i])[0])]
            index+=option_len
            options+="  Parameter_Request_list:{}".format(parameter_list)
        elif code==56:  #Message
            index,option_len,msg = get_path_name(data_3,index)
            options+="  Message:{}".format(msg)
        elif code==57:  #Max DHCP message size
            max_size = struct.unpack("!H",data_3[index+1:index+3])[0]
            index+=3
            options+="  Max_DHCP_message_size:{}".format(max_size)
        elif code==58:  #Renewal (T1) Time value
            ren_time = struct.unpack("!L",data_3[index+1:index+5])[0]
            index+=5
            options+="  Renewal_time:{}".format(ren_time)
        elif code==59:  #Rebinding (T2) time value
            rb_time = struct.unpack("!L",data_3[index+1:index+5])[0]
            index+=5
            options+="  Rebinding_time:{}".format(rb_time)
        elif code==60:  #Vendor Class Identifier
            index,option_len,vendor_str = get_path_name(data_3,index)
            options+="  Vendor_class_identifier:{}".format(vendor_str)
        elif code==61:  #Client identifier
            option_len = struct.unpack("!B",data_3[index])[0]
            index+=option_len+1
            options+=red_color+"Client Identifier[61] is not implemented yet!"+end_color
        
        elif code==64:  #Netowrk info service+domain
            index,option_len,name = get_path_name(data_3,index)
            options+="  Network_Info_Service+Domain:{}".format(name)
        elif code==65:  #Network info service+Servers
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Network_Info_Service+Servers:{}".fromat(addr)
        elif code==66:  #TFTP server name
            index,option_len,name = get_path_name(data_3,index)
            options+="  TFTP_server_name:{}".format(name)
        elif code==67:  #BootFile name
            index,option_len,name = get_path_name(data_3,index)
            options+="  BootFile_name:{}".format(name)
        elif code==68:  #Mobile IP Home Agent
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Mobile_IP_Home_Agent_addr:{}".format(addr)
        elif code==69:  #SMTP server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  SMTP_server:{}".format(addr)
        elif code==70:  #POP3 server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  POP3_server:{}".format(addr)
        elif code==71:  #NNTP server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  NNTP_server:{}".format(addr)
        elif code==72:  #Default_WWW_Server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Default_WWW_Server:{}".format(addr)
        elif code==73:  #Default_Finger_Server
            index,option_len,addr =get_serv_addrs(data_3,index)
            options+="  Default_Finger_Server:{}".format(addr)
        elif code==74:  #Default IRC server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Default_IRC_server:{}".format(addr)
        elif code==75:  #StreetTalk server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  Default_StreetTalk_server:{}".format(addr)
        elif code==76:  #streetTalk Directory Assistance (STDA) server
            index,option_len,addr = get_serv_addrs(data_3,index)
            options+="  STDA_server:{}".format(addr)
        
        else:
            options+="This option is not implemented yet!"
            break
    return options+padding

def get_magic_cookie(byte1,byte2,byte3,byte4):
    if byte1=='\x63' and byte2=='\x82' and byte3=='\x53' and byte4=='\x63':
        return 'DHCP'
    else:
        return red_color+"This magic_cookie type is Implemented yet!"+end_color

def get_serv_addrs(data_3,index):
    option_len = struct.unpack("!B",data_3[index])[0]
    index+=1
    serv_addr = ""
    temp_index=index
    for i in range(temp_index,temp_index+option_len,4):
        serv_addr+=",{}".format(ipv4(struct.unpack("! 4s",data_3[index:index+4])[0]))
    index+=option_len
    return index,option_len,serv_addr

def get_path_name(data_3,index):
     option_len = struct.unpack("!B",data_3[index])[0]
     name = get_file_name(data_3[index+1:index+option_len+1])
     index+=option_len+1
     return index,option_len,name


def get_file_name(data):
    name = ""
    for char in data:
        if char=='\x00':
            break
        name+=char
    if name=="":
        return "name not found"
    else:
        return name

def dhcpv6(data_6):
	print "dhcp version 6 is not implemented yet!"
	pass
