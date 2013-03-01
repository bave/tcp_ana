# -*- coding: utf-8 -*-
#!/usr/bin/env python

import sys
import dpkt
import socket
from pylab import *
from datetime import *

FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10

FIN_ACK = 0x11
SYN_ACK = 0x12
RST_ACK = 0x14

S_SRT = "request"
S_EST = "connecting"
S_END = "release"

class FlowEntry:

    def __init__(self, key_ip):
        self.flow_list = {}
        self.key_ip = key_ip
        return
    #end_def


    def __del__(self):
        del self.flow_list
        del self.key_ip
        return
    #end_def

    def set_flow(self, ip1, port1, ip2, port2, flags, ts):

        if ip1 == self.key_ip:
            return self.__set_flow(ip1, port1, ip2, port2, flags, ts)
        elif ip2 == self.key_ip:
            return self.__set_flow(ip2, port2, ip1, port1, flags, ts)
        else:
            return False
        #end_def

        return True
    #end_def


    def __set_flow(self, src_ip, src_port, dst_ip, dst_port, flags, ts):

        date = datetime.fromtimestamp(int(ts))
        unixtime_sec  = int(str(ts).split(".")[0])
        unixtime_msec = int(str(ts).split(".")[1])
        flow = "TCP "+src_ip+":"+str(src_port)+" "+dst_ip+":"+str(dst_port)

        if self.flow_list.has_key(flow):
            if flags == SYN:
                if self.flow_list[flow]["session"] == S_END:
                    self.flow_list[flow]["session"] = S_SRT
                    self.flow_list[flow]["s_time"]  = unixtime_sec
                    self.flow_list[flow]["e_time"]  = None
                    self.flow_list[flow]["span"]    = 0
                    self.flow_list[flow]["count"]   = self.flow_list[flow]["count"] + 1
                    #print "SYN"
                    return True
                #end_if
            elif flags == SYN_ACK:
                if self.flow_list[flow]["session"] == S_SRT:
                    self.flow_list[flow]["session"] = S_EST
                    self.flow_list[flow]["e_time"]  = unixtime_sec
                    self.flow_list[flow]["span"]    = self.flow_list[flow]["e_time"] - self.flow_list[flow]["s_time"]
                    #print "EST"
                    return True
                else:
                    return False
                #end_if
            elif flags == FIN or flags == RST or flags == FIN_ACK or flags == RST_ACK:
                if self.flow_list[flow]["session"] == S_EST:
                    self.flow_list[flow]["session"] = S_END
                    self.flow_list[flow]["e_time"] = unixtime_sec 
                    self.flow_list[flow]["span"]    = self.flow_list[flow]["e_time"] - self.flow_list[flow]["s_time"]
                    #print "END"
                    return True
                else:
                    return False
                #end_if
            else:
                self.flow_list[flow]["e_time"] = unixtime_sec
                self.flow_list[flow]["span"]    = self.flow_list[flow]["e_time"] - self.flow_list[flow]["s_time"]
                return True
            #end_if
        else:
            if flags == SYN:
                self.flow_list[flow] = {}
                self.flow_list[flow]["session"] = S_SRT
                self.flow_list[flow]["s_time"]  = unixtime_sec
                self.flow_list[flow]["e_time"]  = None
                self.flow_list[flow]["span"]    = 0
                self.flow_list[flow]["count"]   = 0
                #print "SYN"
                return True
            else:
                return False
            #end_if
        #end_if
    #end_def

    def get_flow_list(self):
        return self.flow_list
    #end_def

    def print_flow_list(self):
        for i in self.flow_list:
            print i, self.flow_list[i]
        return self.flow_list
    #end_def

#end_class


def plotting(list, filename):
    rcParams['figure.facecolor'] = 'w'
    rcParams['legend.numpoints'] = 1
    rcParams['font.size'] = 12

    bar(range(len(list)), list)

    v = [0, len(list), 0, max(list)] # x_min x_max y_min y_max
    axis(v)
    title(filename, fontsize=14, fontname='serif')
    xlabel("[keep time]")
    ylabel("[Number of conection(release)]")
    #savefig(filename+".eps")
    show()
    return
#end_def

def usage():
    print u"python %s [key_ip_address] [pcap_file]" % sys.argv[0]
    print u"	key_ip_address      : 切り出すソースIPアドレス(IPv4)"
    print u"	pcap_file           : そのまま"
    return
#end_def


def main():

    if (len(sys.argv) != 3):
        usage()
        return 1
    #end_if

    key_ip = sys.argv[1]
    if key_ip == None:
        return -1
    filename = sys.argv[2]
    if filename == None:
        return -1
    outputfile = filename

    #filename = u'./test4.pcap'
    #key_ip = u'150.65.206.242'

    f_entry = FlowEntry(key_ip)
    pcr = dpkt.pcap.Reader(open(filename,'rb'))

    packet_count = 0

    for (ts, buf) in pcr:

        packet_count += 1

        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            print 'Fail parse:', packet_count, ': skipping'
            continue
        #end_try

        if type(eth.data) == dpkt.ip.IP:
            packet = eth.data
            src_ip = socket.inet_ntoa(packet.src)
            dst_ip = socket.inet_ntoa(packet.dst)
            segment = packet.data
            if type(packet.data) == dpkt.udp.UDP:
                src_port = segment.sport
                dst_port = segment.dport
                continue
            elif type(packet.data) == dpkt.tcp.TCP:
                src_port = segment.sport
                dst_port = segment.dport
                flags = segment.flags
                f_entry.set_flow(src_ip, src_port, dst_ip, dst_port, flags, ts)
            #end_if
        #end_if

    #end_for

    #f_entry.print_flow_list()

    flow_list = f_entry.get_flow_list()

    list_span = []
    for i in flow_list:
        if flow_list[i]["session"] == S_END:
            list_span.append(int(flow_list[i]["span"]))
    #end_for

    list_max = max(list_span)
    list_min = min(list_span)

    hist = []

    for i in xrange(list_max+1):
        hist.append(0)
    #end_for

    for i in list_span:
        hist[i] = hist[i] + 1
    #end_for

    print hist
    plotting(hist, outputfile)


#end_def

if __name__ == '__main__':
    main()
