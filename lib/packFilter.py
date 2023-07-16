from usefull import *

import time,sys


printText = 0

ipv4filter = "[*]Internet Protocol Version 4[IPv4]"
icmpfilter = "[*]Internet Control Message Protocol[ICMP]:"
igmpfilter = "[*]Internet Group Management Protocol[IGMP]:"
tcpfilter = "[*]Transmission Control Protocol[TCP]:"
arpfilter = "[*]Address Resolution Protocol["
dnsfilter = "[*]Domain Name System[DNS]:"
dhcpfilter = "[*]BootStrap Protocol [DHCP]"
allfilter = "tomcruze"*100
filterText = " "
def printFilter(sI,eI,lines):
    for index in range(sI,eI):
        print lines[index]

def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            #time.sleep(0.001)
            continue
        yield line
def dynamictext(thefile):
    lines = follow(thefile)
        
    packetLines = []
    for line in lines:
        if line.find("----------------")!=-1:
            packetLines.append("-"*100)
            filterdata(packetLines)
            packetLines = []
        packetLines.append(line.strip("\n"))
            
    
def filterdata(lines):
    if len(lines) == 0:
        return
#    print lines
    global printText
    startIndex = 0
    endIndex = 0
    curIndex = 0
    length = len(lines)
    while True:
        if curIndex >= length:
            break
        if lines[curIndex].find("------------------") != -1:
            startIndex=endIndex
            endIndex = curIndex
            if printText == 1:
                printFilter(startIndex,endIndex,lines)
                printText = 0
       # print lines[curIndex].find(filterText)
        if lines[curIndex].find(filterText) != -1 or lines[curIndex].find(allfilter)==0:
            printText = 1
        curIndex+=1
    


def packFilter(packets,doPrint):
    
    #print len(packets)
    for i in range(len(packets)):
        printPacket(packets[i],'2')
        

#    print green_color
#    print "\n\t1.IPv4\n\t2.ICMP\n\t3.IGMP\n\t4.TCP\n\t5.ARP\n\t6.DNS\n\t7.DHCP\n\t8.ALL"
#    print end_color
#    canContinue = 0
#    while canContinue==0:
#        if canContinue == 1:
#            break
#        filterNum = raw_input(blue_color+"what Packets do you want to filter:"+end_color)
#        canContinue = 1
#        if filterNum ==  '1':
#            filterText = ipv4filter
#        elif filterNum == '2':
#            filterText = icmpfilter
#        elif filterNum == '3':
#            filterText = igmpfilter
#        elif filterNum == '4':
#            filterText = tcpfilter
#        elif filterNum == '5':
#            filterText = arpfilter
#        elif filterNum == '6':
#            filterText = dnsfilter
#        elif filterNum == '7':
#            filterText = dhcpfilter
#        elif filterNum == '8':
#            filterText = ""
#        else :
#            print "Please enter a valid Number...!"
#            canContinue = 0
#        filterdata(lines)
#        dynamictext(outfd)
#
