# !/usr/bin/python
# -*- coding: utf-8 -*-
import dpkt
import datetime
import socket
import csv

def mac_addr(address):
    """Convert a MAC address to a readable/printable string
        Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
        Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)

def ip_to_str(address):
    """Print out an IP address given a string
    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntoa(address)

def print_packets(pcap):
    """Print out information about each packet in a pcap
    Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        # Print out the timestamp in UTC
        print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... )
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue
        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        # Print out the info
        # Return the info
        print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)


def test():
    """Open up a test pcap file and print out the packets"""
    with open('testsource/taobao300s.pcap', 'rb') as f:
        print 'ok'
        pcap = dpkt.pcap.Reader(f)
        Store_packets_info(pcap)

def Store_packets_info(pcap):
    """Store information about each packet in a pcap
           Args:
               pcap: dpkt pcap reader object (dpkt.pcap.Reader)
        """
    # For each packet in the pcap process the contents
    # Collect data and process , store respectively
    with open("featureList/feature.csv", 'w') as csv_file:
        writer = csv.writer(csv_file, dialect='excel')
        writer.writerow(['URI', 'Method', 'User-agent', 'Body'])
        for timestamp, buf in pcap:
            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)
            # Make sure the Ethernet data contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
                continue
            # Now grab the data within the Ethernet frame (the IP packet)
            ip = eth.data
            # Check for TCP in the transport layer
            if isinstance(ip.data, dpkt.tcp.TCP):
                # Set the TCP data
                tcp = ip.data
                # Now see if we can parse the contents as a HTTP request
                try:
                    request = dpkt.http.Request(tcp.data)
                    if tcp.dport == 80 and len(tcp.data) > 0:
                        http = dpkt.http.Request(tcp.data)
                        new =[]
                        new.append(http.uri)
                        new.append(http.method)
                        try:
                            if http.headers['user-agent'] is not None:
                                new.append(http.headers['user-agent'])
                            else:
                                new.append("None")
                        except:
                            continue
                        new.append(http.body)
                        print new
                        writer.writerow(new)

                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue
                # Print out the info
                print 'HTTP request: %s\n' % repr(request).decode(encoding='utf-8')
        csv_file.close()


def print_http_request(pcap):
    """Print out information about each packet in a pcap
           Args:
               pcap: dpkt pcap reader object (dpkt.pcap.Reader)
        """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue
        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data
        # Check for TCP in the transport layer
        if isinstance(ip.data, dpkt.tcp.TCP):
            # Set the TCP data
            tcp = ip.data
            # Now see if we can parse the contents as a HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
                if tcp.dport == 80 and len(tcp.data) > 0:
                    http = dpkt.http.Request(tcp.data)
                    print http.uri
                    print http.method
                    print http.headers
                    print http.body
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            # Print out the info
            print 'HTTP request: %s\n' % repr(request).decode(encoding='utf-8')

if __name__ == "__main__":
    test()