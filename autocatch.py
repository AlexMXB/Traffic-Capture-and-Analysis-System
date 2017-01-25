#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import sniff,PcapWriter
import datetime
import time

def write(file_name, packets):
    """Write the captured packets to a new pcap file"""
    writer = PcapWriter(file_name, append = True)
    for p in packets:
        writer.write(p)
    writer.flush()
    writer.close()

def CatchandSave(k):
    """Conduct periodical traffic capture and store process """
    for i in range(100):
        print '开始捕获第%d个流量数据包'%i
        packets = sniff(filter="tcp",prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.payload%"), timeout=k)
        # pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"),count=5)
        # if time.strftime('%Y-%m-%d %X',time.localtime())=='2016-05-23 11:05:00':
        # packets = sniff(filter="tcp", prn=lambda x: x.show(),count=2000)
        # packets = sniff(filter="tcp", prn=lambda x: x.show(),timeout=k)
        filename = "%s.pcap" % str(datetime.datetime.now())
        write(filename, packets)
        print '完成第%d个数据流量包保存'%i
        time.sleep(30)
        i = i+1
        print '准备第%d个数据流量包捕获'%i

"""函数调用测试"""
if __name__ == '__main__':
    print "hello"
    CatchandSave(60)




