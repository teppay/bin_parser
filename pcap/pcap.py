#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io

from ctypes import *
from argparse import ArgumentParser

class PcapHeader(LittleEndianStructure):
    __hdr_len__ = 24
    _fields_ = (
        ('magic_num', c_uint32), # magic number
        ('major_ver', c_uint16), # major version
        ('minor_ver', c_uint16), # minor version
        ('timezone_offset', c_int32), 
        ('timestamp_accuracy', c_uint32), 
        ('snap_len', c_uint32), # snapshot_length : max size of each packet capture data
        ('link_type', c_uint32) # link-layer header type
    )

class PacketHeader(LittleEndianStructure):
    __hdr_len__ = 16
    _fields_ = (
                ('timestamp_sec', c_uint32),
                ('timestamp_usec', c_uint32),
                ('cap_len', c_uint32),
                ('pkt_len', c_uint32),
               )
    
    def __len__(self):
        return self.__hdr_len__


def show_pcap_header(pcap_header):
    print(f'magic number : {hex(pcap_header.magic_num)}')
    print(f'major version : {pcap_header.major_ver}')
    print(f'minor version : {pcap_header.minor_ver}')
    print(f'timezone offset : {pcap_header.timezone_offset}')
    print(f'timestamp_accuracy : {pcap_header.timestamp_accuracy}')
    print(f'snapshot length : {pcap_header.snap_len}')
    print(f'link-layer header type : {pcap_header.link_type}')

def show_packet_header(packet_header):
    print(f'timestamp_sec : {packet_header.timestamp_sec}')
    print(f'timestamp_usec : {packet_header.timestamp_usec}')
    print(f'capture length : {packet_header.cap_len}')
    print(f'packet length : {packet_header.pkt_len}')

def debug():
    import string

    file_name = 'kbd.pcap'
    # file_name = 'test.pcap'

    # buffer = io.BytesIO(string.ascii_lowercase.encode('utf-8')[:24])
    buffer = open(file_name, 'rb')
    ph = PcapHeader()
    pkth = PacketHeader()
    buffer.readinto(ph)
    show_pcap_header(ph)
    for _ in range(10):
        buffer.readinto(pkth)
        print('----------------------------')
        print('----------------------------')
        show_packet_header(pkth)
        print('----------------------------')
        print(buffer.read(24))

if __name__ == '__main__':
    # Check debug flag
    parser = ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    
    is_debug = args.debug

    if is_debug:
        debug()