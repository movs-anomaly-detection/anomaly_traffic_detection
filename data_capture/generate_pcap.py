# import json
import pyshark
import sys
import url_walker

try:
    domain_list_filename = sys.argv[1]
    ring_file_name = sys.argv[2]
    assert ring_file_name.endswith('.pcap') or ring_file_name.endswith('.pcapng'), 'Extension have to be equal ".pcap" either ".pcapng"'
    sslkeylog_filename = None
    if len(sys.argv) == 4:
        sslkeylog_filename = sys.argv[3]
    else: raise
except:
    print('Required arguments')
    print('1) text file with urls like "https://bitly.com" separatly on each line')
    print('2) filename-template to save pcap-files to')
    print('3) filename of ssl keys to write to (optional parameter)')
    exit()

urls = list()
with open(domain_list_filename, 'r') as file:
    urls = [line.rstrip() for line in file]

with pyshark.LiveRingCapture(interface='any', bpf_filter='tcp port 443', num_ring_files=100, ring_file_size=200_000, ring_file_name=ring_file_name) as network_capture:
    with url_walker.UrlWalker(urls, sslkeylog_filename) as walker:
        for packet in network_capture.sniff_continuously():
            if walker.ready(): break

exit()