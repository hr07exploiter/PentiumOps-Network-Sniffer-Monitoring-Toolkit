from usefull import *
import struct


#unpack TCP Segment
def tcp_segment(data_2,Object):
	src_port,dest_port,seq_no,ack_no,offset_reserved,flags,window,checksum,urg_ptr = struct.unpack("! H H L L B B H H H",data_2[:20])
        nounce = offset_reserved&1
        c_flag = (flags&(2**7))>>7
	e_flag = (flags&(2**6))>>6
	u_flag = (flags&(2**5))>>5
	a_flag = (flags&(2**4))>>4
	p_flag = (flags&(2**3))>>3
	r_flag = (flags&(2**2))>>2
	s_flag = (flags&(2**1))>>1
	f_flag = flags&(1)
	offset = offset_reserved>>4
        offset*=4
        #print "Setting tcp"
	#Object.setTCP(src_port,dest_port,seq_no,ack_no,offset,offset_reserved&(2**5-1),nounce,c_flag,e_flag,u_flag,a_flag,p_flag,r_flag,s_flag,f_flag,window,checksum,urg_ptr,options)
        index=20
        option_kind = {'0':'End_of_Option_List','1':'NOP','2':'MSS','3':'WndowScale','4':'SACK Permitted','5':'SACK','8':'TimeStamp'}
#        print "index=",index,"offset=",offset
        options=""
        #print "options"
        if index<offset:
    	    options+="\tOptions:-"
            while(index<offset):
                kind = struct.unpack('!B',data_2[index])[0]
                index+=1
                if kind==0: #End of Option List
                    options+="  kind:"+"%s"%option_kind["%d"%kind]
                elif kind == 1: #No Operation
                    options+="  Kind:"+"%s"%option_kind["%d"%kind]
                elif kind == 2: #Maximum Segment Size
                    length,MSS = struct.unpack("!B H",data_2[index:index+3])
                    options+="  Kind:"+"{}{}{}{}{}".format(option_kind["%d"%kind]," length:",length," Max_Seg_size:",MSS)
                    index+=3
                elif kind==3: #WindowScale
                    #length,shift_count = struct.unpack("!B B",data_2[index:index+2])
                    length,shift_count = struct.unpack("!B B",data_2[index:index+2])
                    options+="  Kind:"+"{}{}{}{}{}".format(option_kind["%d"%kind]," Length:",length," Shift_count:",shift_count)
                    index+=2
                elif kind==4:  #Selective Ack Permitted  
                    length = struct.unpack("!B",data_2[index])[0]
                    options+="  Kind:"+"{}{}{}".format(option_kind["%d"%kind]," Length:",length)
                    index+=1
                elif kind==5:
                    length,left_edge,right_edge = struct.unpack("!B L L",data_2[index:index+9])
                    options+="  Kind:"+"{}{}{}{}{}{}{}".format(option_kind["%d"%kind]," Length:",length," Left_edge:",left_edge," Right_edge:",right_edge)
                    index+=9
                elif kind==8:  #Time Stamp
                    length,TS_value,TS_echo = struct.unpack("!B L L",data_2[index:index+9])
                    options+="  Kind:"+"{}{}{}{}{}{}{}".format(option_kind["%d"%kind]," Length:",length," TimeStamp_value:",TS_value," TimeStamp_echo:",TS_echo)
                    index+=9
                else:
                    options+="(*)This option is not Implemented yet!"
                    break
        Object.setTCP(src_port,dest_port,seq_no,ack_no,offset,offset_reserved&(2**4-1)>>1,nounce,c_flag,e_flag,u_flag,a_flag,p_flag,r_flag,s_flag,f_flag,window,checksum,urg_ptr,options)
        
        #if offset+1>=len(data_2): return
        if dest_port == 80 or src_port== 80:  #http
            http_data(Object,data_2[offset:])
	
	

def http_data(Object,data_3):  #unpack http data
    if data_3 != "":
        Object.tcp_packet_type="HTTP"    
        Object.setHTTP(data_3)


