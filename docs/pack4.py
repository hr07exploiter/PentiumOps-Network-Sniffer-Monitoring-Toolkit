#!/usr/bin/python

class HTTP():
    NumOfHTTPPackets = 0

    def setHTTP(self,data):
        self.http_data = data

        self.level4_packet_type="HTTP"
        HTTP.NumOfHTTPPackets+=1

class SSDP():
    NumOfSSDPPackets = 0

    def setSSDP(self,data):
        self.ssdpdata = data
        
        self.level4_packet_type="SSDP"
        SSDP.NumOfSSDPPackets+=1

class DHCP():
    NumOfDHCPPackets = 0

    def setDHCP(self,msg_type,hrdwr_type,hrdwr_addr_len,hops,trans_id,sec_elapsed,boot_flags,client_ip,your_ip,next_server_ip,relay_agent,client_mac,client_hrdwr_addr_pad,server_hostname,bootfile_name,magic_cookie,options,padding="0000000000000"):
        self.msg_type = msg_type
        self.hrdwr_type= hrdwr_type
        self.hrdwr_addr_len = hrdwr_addr_len
        self.hops = hops
        self.trans_id = trans_id
        self.sec_elapsed = sec_elapsed
        self.boot_flags = boot_flags
        self.client_ip = client_ip
        self.your_ip = your_ip
        self.next_server_ip = next_server_ip
        self.relay_agent = relay_agent
        self.client_mac = client_mac
        self.client_hrdwr_addr_pad = client_hrdwr_addr_pad
        self.server_hostname = server_hostname
        self.bootfile_name = bootfile_name
        self.magic_cookie = magic_cookie
        self.options = options
        self.padding = padding

        self.level4_packet_type="DHCP"
        #self.json['msg_type'],self.json['hrdwr_type'],self.json['hrdwr_addr_len'],self.json['hops'],self.json['trans_id'],self.json['sec_elapsed'],self.json['boot_flags'],self.json['client_ip'],self.json['your_ip'],self.json['next_server_ip'],self.json['relay_agent'],self.json['client_mac'],self.json['client_hrdwr_addr_pad'],self.json['server_hostname'],self.json['bootfile_name'],self.json['magic{cookie'],self.json['options'],self.json['padding'] = msg_type,hrdwr_type,hrdwr_addr_len,hops,trans_id,sec_elapsed,boot_flags,client_ip,your_ip,next_server_ip,relay_agent,client_mac,client_hrdwr_addr_pad,server_hostname,bootfile_name,magic_cookie,options,padding
        DHCP.NumOfDHCPPackets+=1

class DNS():
    NumOfDNSPackets = 0

    def setDNS(self,Response,OpCode,Authoritative,Truncated,Recursion,AvailRecursion,Z,AnsAuth,NonAuth,Transaction_ID,Reply_code,Queries_count,Answers_count,Authority_count,Additional_info_count,queries,answers,auth_answers,addi_answers):
        self.Response = Response
        self.OpCode = OpCode
        self.Authoritative = Authoritative
        self.Truncated = Truncated
        self.Recursion = Recursion
        self.AvailRecursion = AvailRecursion
        self.Z = Z
        self.AnsAuth = AnsAuth
        self.NonAuth = NonAuth
        self.Transaction_ID = Transaction_ID
        self.Reply_code = Reply_code
        self.Queries_count = Queries_count
        self.Answers_count = Answers_count
        self.Authority_count =  Authority_count
        self.Additional_info_count = Additional_info_count
        self.queries = queries
        self.answers = answers
        self.auth_answers = auth_answers
        self.addi_answers = addi_answers

        self.level4_packet_type="DNS"
        #self.json['Response'],self.json['OpCode'],self.json['Authoritative'],self.json['Truncated'],self.json['Recursion'],self.json['AvailRecursion'],self.json['Z'],self.json['AnsAuth'],self.json['NonAuth'],self.json['Transaction_ID'],self.json['Reply_code'],self.json['Queries_count'],self.json['Answers_count'],self.json['Authority_count'],self.json['Additional_info_count'],self.json['queries'],self.json['answers'],self.json['auth_answers'],self.json['addi_answers'] = Response,OpCode,Authoritative,Truncated,Recursion,AvailRecursion,Z,AnsAuth,NonAuth,Transaction_ID,Reply_code,Queries_count,Answers_count,Authority_count,Additional_info_count,queries,answers,auth_answers,addi_answers

        DNS.NumOfDNSPackets+=1
        
