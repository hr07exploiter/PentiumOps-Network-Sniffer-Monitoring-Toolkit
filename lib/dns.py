from usefull import *
import struct

#DNS ---https://tools.ietf.org/html/rfc2929
def dns(data_3,udp_size,newObject):
	dns_rcodes= {'0':'No error(0)','1':'Format error(1)','2':'Server failure(2)','3':'Name Error(3)','4':'Not Implemented(4)','5':'Refused(5)'}
        dns_opcodes = {'0':'Standard query(0)','1':'Inverse query(1)','2':'server status request(2)'}
        dns_query_types = {'1':'host address [A][1)','2':'authoritative nameserver[NS][2)','3':'[mail_destination][3)','4':'[main_forwarder][4)','5':'cononical name for an alias[CNAME][5)','6':'Start of zone of authority[SOA][6)','7':'[mainbox_domain_name][7)','8':'[mail_group_member][8)','9':'[main_rename_domain_name][9)','10':'[null_RR][10)','12':'domain name pointer[PTR]{12)','15':'mail exchange[MX][15)','16':'text string[TXT][16)','24':'security signature[SIG][24)','28':'IPv6 Address[AAAA][28)','33':'[SRV][server selection)(33)'}
	dns_query_classes = {'1':'Internet[IN](1)','3':'Chaos[CH](3)','4':'Hesiod[HS](4)'}
	if show_dns !=0:
            id,flags_codes,query_c,answ_c,auth_c,addi_c= struct.unpack("!HHHHHH",data_3[:12])
	    opcode = (flags_codes>>11)&15
            #print blue_color+"[*]Domain Name System[DNS]:"+end_color#check
            Response,OpCode,Authoritative,Truncated,Recursion,AvailRecursion,Z,AnsAuth,NonAuth = "","","","","","","","",""
            if is_bit_set(flags_codes,1,16):
	       	Response = "Response:"+green_color+"Response(1)"+end_color
            else:
	      	Response = "Response:"+green_color+"Query(0)"+end_color
            OpCode = "OpCode:{}".format(dns_opcodes["%d"%opcode])
            if is_bit_set(flags_codes,1,16):
	        if is_bit_set(flags_codes,6,16):
		    Authoritative = "Authoritative:Non-authoritative_Server(1)"
        	else:
	            Authoritative = "Authoritative:Authoritative_Server(0)"
            if is_bit_set(flags_codes,7,16):
	        Truncated = "Truncated:Truncated(1)"
            else:
	        Truncated =  "Truncated:Non-Truncated(0)"
            if is_bit_set(flags_codes,8,16):
	        Recursion = "Recursion:query_recursively(1)"
            else:
	        Recursion = "Recursion:query_Non-recursively(0)"
            if is_bit_set(flags_codes,1,16):
	        if is_bit_set(flags_codes,9,16):
		    AvailRecursion =  "Recursion_avaliable:Recursive_queries_possible(1)"
        	else:
	            AvailRecursion = "Recursion_avaliable:Recursive_queries_not_possible(0)"
            if is_bit_set(flags_codes,10,16):
	        Z = "Z:not_reserved(1)"
            else:
	        Z = "Z:reserved(0)"
            if is_bit_set(flags_codes,1,16):
	        if is_bit_set(flags_codes,11,16):
		    AnsAuth = "Answer_authenticated:authenticated(1)"
        	else:
	            AnsAuth = "Answer_authenticated:Non-authenticated(0)"
            if is_bit_set(flags_codes,12,16):
	        NonAuth = "Non-authenticated_data:Acceptable(1)"
            else:
	        NonAuth = "Non-authenticated_data:Unacceptable(0)"
            rcode = (flags_codes)&15
            #print "\t"+Response+OpCode+Authoritative+Truncated+Recursion+AvailRecursion+Z+AnsAuth+NonAuth+" Transaction_ID:0x%x"%id+" Reply_code:"+str(dns_rcodes["%d"%rcode])+"Queries_count:"+str(query_c)+"Answers_count:"+str(answ_c)+"Authority_count:"+str(auth_c)+"Additional_info_count:"+str(addi_c)#check

            queries = ''
            answers = ''
            auth_answers = ''
            addi_answers = ''

	    qname,index = get_dns_name(data_3,12)
            qtype,qclass = struct.unpack("!HH",data_3[index:index+4])
            index+=4
	    queries+="\tQueries:"+yellow_color+"Name:"+qname+end_color+"    Type:"+dns_query_types["%d"%qtype]+"  Class:"+dns_query_classes["%d"%qclass]+'\n'
            
            if is_bit_set(flags_codes,1,16):
	        if answ_c != 0:
		    answers+="\tAnswers:-\n"
        	for i in range(answ_c):
		    #print struct.unpack("!s",data_3[index])#check
		    req = struct.unpack("!s",data_3[index+1])
        	    req_index = ord(req[0])
	            #print req_index,struct.unpack("!s",data_3[req_index])#check
		    index+=2
		    a_type,a_class,a_ttl,a_len = struct.unpack("!H H I H",data_3[index:index+10])
        	    index+=10
	            rdata = get_dns_data(data_3,index,a_type)
		    index+=a_len
		    a_name,new_index = get_dns_name(data_3,req_index)
                    answers+="\t(*)"+str(i+1)+":- Name:"+a_name+"Type:"+dns_query_types["%d"%a_type]+"Class:"+dns_query_classes["%d"%a_class]+"Time_to_live:%d"%a_ttl+"Data length:%d"%a_len+yellow_color+rdata+end_color+'\n'
		if auth_c != 0:
                    auth_answers+="\tAuthoritative:-\n"
                    #print 'auth'#check
                for i in range(auth_c):
                    #print i #check
                    tmp_ind =  struct.unpack("!s",data_3[index])[0] 
                    #print tmp_ind #check
                    req = struct.unpack("!s",data_3[index+1])
                    req_index = ord(req[0])
                    if(tmp_ind=='\x00'):
                        index+=1
                    else:
                        index+=2
                    a_type,a_class,a_ttl,a_len = struct.unpack("!H H I H",data_3[index:index+10])
                    index+=10
	            rdata =  get_dns_data(data_3,index,a_type)
                    index+=a_len
                    if tmp_ind!='\x00':
                        a_name,new_index = get_domain_name(data_3,req_index)
                    else:
                        a_name="<Root>"
                    auth_answers+="\t(*)"+str(i+1)+":- Name:"+a_name+"Type:"+dns_query_types["%d"%a_type]+"Class:"+dns_query_classes["%d"%a_class]+"Time_to_live:%d"%a_ttl+"Data_length:%d"%a_len+yellow_color+rdata+end_color+'\n'
        	if addi_c != 0:
                    addi_answers+="\tAdditional:-\n"
                    #print "additional" #check
                for i in range(addi_c):
                    
                    index+=2
                    a_type,a_class,a_ttl,a_len = struct.unpack("!H H I H",data_3[index:index+10])
                    index+=10
                    rdata =  get_dns_data(data_3,index,a_type)
                    index+=a_len
                    a_name,new_index = get_dns_name(data_3,req_index)
                    #print "qtype:",qtype#check
                    addi_answers+="\t(*)"+str(i+1)+":- Name:"+a_name+"Type:"+dns_query_types["%d"%a_type]+"Class:"+dns_query_classes["%d"%a_class]+"Time_to_live:%d"%a_ttl+"Data_length:%d"%a_len+yellow_color+rdata+end_color+'\n'
                
        newObject.setDNS(Response,OpCode,Authoritative,Truncated,Recursion,AvailRecursion,Z,AnsAuth,NonAuth," Transaction_ID:0x%x"%id," Reply_code:"+str(dns_rcodes["%d"%rcode]),"Queries_count:"+str(query_c),"Answers_count:"+str(answ_c),"Authority_count:"+str(auth_c),"Additional_info_count:"+str(addi_c),queries,answers,auth_answers,addi_answers)
	    
def get_dns_data(data_3,index,dns_type):
	if dns_type==1: #A
		addr = ipv4(struct.unpack("!4s",data_3[index:index+4])[0])
		rdata = "A address: %s"%addr
	elif dns_type==2: #NS
		name,new_index = get_domain_name(data_3,index)
		rdata = "Name Server: %s"%name
        elif dns_type==5: #CNAME
                name,new_index = get_domain_name(data_3,index)
                rdata = "CNAME: %s"%name
	elif dns_type==28: #AAAA
		addr = ipv6(struct.unpack("!16s",data_3[index:index+16])[0])
		rdata = "AAAA address: %s"%addr
	else:
		rdata = "rdata: Not implemented yet....!!!"
	return rdata


def get_domain_name(data_3,index):
	check,req = struct.unpack("!s",data_3[index]),struct.unpack("!s",data_3[index+1])
	a_name = ""
        prev_check = check
        check = ord(check[0])
        check = (check>>6)<<6
	#print check,req#check
        #print 'get_domain_name'#check
        isNullBit = 1
        try:
            if prev_check[0]!='\x00':
	        if check!=ord('\xc0'):
        	        a_name,index = get_dns_name(data_3,index)
		        check= struct.unpack("!s",data_3[index])
                        check = ord(check)
                        check = (check>>6)<<6
                        isNullBit = ord(struct.unpack("!s",data_3[index-1])[0])
                if check[0]==ord('\xc0')and isNullBit!=0:
                        index+=1 
                        req = struct.unpack("!H",data_3[index])
		        req_index = req[0]
                        req_index = (req_index<<2)>>2
		        #print index,'req = ',req #check
        	        req_name,new_index = get_domain_name(data_3,req_index)
	                a_name+=req_name
	                index+=2
            else:
                a_name='<Root>'
                index+=1
        except:
            pass
	return a_name,index

def get_dns_name(data_3,index):
        #print index,'get_dns_name'#check
        if index==0:
            return "",index+1;
	char = struct.unpack("!s",data_3[index])
	qname = ""
        new_char = ord(char[0])
        new_char = (new_char>>6)<<6
	while int(ord(char[0]))!=0 and new_char!=ord('\xc0'):
		for i in range(int(ord(char[0]))):
			index+=1
			char = struct.unpack("!s",data_3[index])
			qname+="%s"%char[0]
			#print index,qname#check
		index+=1
		char = struct.unpack("!s",data_3[index])
                new_char = ord(char[0])
                new_char = (new_char>>6)<<6
                #print "here: ",char
		qname+="."
        if new_char!=ord('\xc0'):
	    index+=1
	return qname,index
