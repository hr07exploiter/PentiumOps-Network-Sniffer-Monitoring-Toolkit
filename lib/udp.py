from usefull import *
from dns import *
from dhcp import *


import struct

def udp_packet(other_data,newObject):      #unpack UDP Packet
	src_port,dest_port,length,checksum = struct.unpack("! H H H H",other_data[:8])
        #outfile.write(blue_color+"[*]User Datagram Protocol[UDP]:"+end_color)
	newObject.setUDP(str(src_port),str(dest_port),str(length),"0x%x"%checksum)
	return other_data[8:],src_port,dest_port,length

#Checking Inner Protocol of udp
def check_udp(data_3,src_port,dest_port,udp_size,newObject):
	if src_port==1900 or dest_port == 1900:
		ssdp(data_3,newObject)
	elif src_port in [67,68] or dest_port in [67,68]:
		dhcp(data_3,newObject)
	elif src_port in [546,547] or dest_port in [546,547]:
		#dhcpv6(data_3,newObject)
                pass
	elif src_port is 53 or dest_port is 53:
		dns(data_3,udp_size,newObject)
                pass
	else :
		#print red_color+"data to this udp port haven't been implemented yet!"+end_color
                pass


#Simple Service Discovery Protocol
def ssdp(data_3,newObject):
    #blue_color+"[*]Simple Service Discovery Protocol[SSDP]:"+end_color)
    data=""
    for line in data_3.split("\r\n"):
	data+="\t"+line
    newObject.setSSDP(data)
