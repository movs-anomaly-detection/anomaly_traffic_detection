import sys, os, re, json, glob
import pyshark
import yadisk, io
from threading import Lock
from multiprocessing import Pool

def prepare_for_output(pre_json_object):
    if type(pre_json_object) == str:
        if re.fullmatch(r'([0-9a-f][0-9a-f]:)*[0-9a-f][0-9a-f]', pre_json_object) != None:
            pre_json_object = re.sub(r'([0-9a-f][0-9a-f]):', r'\1', pre_json_object)
    if type(pre_json_object) == list:
        return [prepare_for_output(value) for value in pre_json_object]
    if type(pre_json_object) != dict:
        if type(pre_json_object) != float:
            try:
                if pre_json_object.startswith('0x'):
                    pre_json_object = int(pre_json_object, base=16)
                else:
                    pre_json_object = int(pre_json_object)
            except:
                pass
        return pre_json_object
    
    new_dict = dict()
    for key, value in pre_json_object.items():
        if type(value) != float:
            try:
                if value.startswith('0x'):
                    value = int(value, base=16)
                else:
                    value = int(value)
            except:
                pass
        
        if type(value) == dict:
            value = prepare_for_output(value)
        elif type(value) == list:
            value = [prepare_for_output(it) for it in value]
        elif type(value) == str:
            if re.fullmatch(r'([0-9a-f][0-9a-f]:)*[0-9a-f][0-9a-f]', value) != None:
                value = re.sub(r'([0-9a-f][0-9a-f]):', r'\1', value)
                
        key = key.split('.')[-1]
        if not key.endswith('_tree'):
            new_dict[key] = value
        
    return new_dict

def get_dict(s):
    match_list = re.fullmatch(r'addr=([\d.]+):?(\d*) proto=(\w+)', s)
    if len(match_list.regs) == 4:
        return { 'addr':match_list[1], 'port':match_list[2], 'proto':match_list[3] }
    return { 'addr':match_list[1], 'proto':match_list[2] }

def remove_prefix(obj):
    new_list = [get_dict(s) for s in obj[1]]
    return (obj[0], new_list)

def create_dict(item):
    dict_item = get_dict(item[0])
    dict_item |= prepare_for_output(item[1][0])
    dict_item['packets'] = item[1][1]
    return dict_item

try:
    needed_proto = sys.argv[1]
    pcap_file_mask = sys.argv[2]
    
    save_to = sys.argv[3]
    ya_disk = False
    if save_to.startswith('@yadisk/'):
        save_to = save_to.removeprefix('@yadisk/')
        ya_disk = True
        
    key, tls_session = None, None
    if len(sys.argv) == 5:
        if sys.argv[4].endswith(".key"):
            key_file = sys.argv[4]
            prefs = {
                'ssl.desegment_ssl_records': 'TRUE',
                'ssl.desegment_ssl_application_data': 'TRUE',
                'tcp.desegment_tcp_streams': 'TRUE',
                'ssl.keys_list': key_file 
            }
        elif sys.argv[4].endswith(".log"):
            nss_file = sys.argv[4]
            prefs = {
                'ssl.desegment_ssl_records': 'TRUE',
                'ssl.desegment_ssl_application_data': 'TRUE',
                'tcp.desegment_tcp_streams': 'TRUE',
                'tls.keylog_file': nss_file 
            }
        else: raise
    else:
        prefs = {
            'ssl.desegment_ssl_records': 'TRUE',
            'ssl.desegment_ssl_application_data': 'TRUE',
            'tcp.desegment_tcp_streams': 'TRUE'
        }
except:
    print("Required arguments")
    print("1) needed proto")
    print("2) pcap file mask")
    print("3) folder to save json-files to")
    print("4) key or log file (optional parameter)")
    exit()

if ya_disk:
    ya_dsk_tkn = os.environ['YANDEX_DISK_TOKEN']
    cloud = yadisk.YaDisk(token=ya_dsk_tkn)

needed_dir = pcap_file_mask.removesuffix(pcap_file_mask.split('/')[-1])
pcap_file_mask = pcap_file_mask.removeprefix(needed_dir)

write_lock = Lock()

def write(sessions_info, nodes_info, pcap_file):
    i = 0
    ip_key = ''
    for joined_addr_and_proto in sessions_info.keys():
        ip = re.findall(r'\d+(?:\.\d+){3}', joined_addr_and_proto)[0]
        if ip == ip_key:
            i += 1
        else:
            i -= 1
            if i < 0:
                ip_key = ip
                i = 0

    list_of_keys = nodes_info.pop(ip_key)
    for key in list_of_keys:
        if key in sessions_info: sessions_info.pop(key)
        
    nodes_info = dict(map(remove_prefix, nodes_info.items()))
    sessions_info = [create_dict(item) for item in sessions_info.items()]
    
    if ya_disk:
        tmp = json.dumps(nodes_info, sort_keys=True, indent=2)
        with io.StringIO(tmp) as f:
            cloud.upload(f, f'{save_to}/nodes_of_{pcap_file}.json', overwrite=True)
        tmp = json.dumps(sessions_info, sort_keys=True, indent=2)
        with io.StringIO(tmp) as f:
            cloud.upload(f, f'{save_to}/sessions_of_{pcap_file}.json', overwrite=True)
    else:
        with open(f'{save_to}/nodes_of_{pcap_file}.json', 'w') as f:
            json.dump(nodes_info, f, sort_keys=True, indent=2)
        with open(f'{save_to}/sessions_of_{pcap_file}.json', 'w') as f:
            json.dump(sessions_info, f, sort_keys=True, indent=2)

def get_sessions(pcap_file : str):
    nodes_info, sessions_info = dict(), dict()
    
    captured = pyshark.FileCapture(
        needed_dir + pcap_file, display_filter='ip',
        override_prefs=prefs, use_json=True
    )
    
    print(f"Begin handling of {pcap_file}\n", end='')

    for packet in captured:
        ip_addr = packet['ip'].src
        nodes_info[ip_addr] = nodes_info.get(ip_addr, set())
        
        tr_layers = [('udp', True), ('tcp', True), ('arp', False), ('icmp', False), ('dns', False), ('netbios', False)]
        forward = False
        pack_info = dict()
        
        for name, upper in tr_layers:
            if name in packet:
                pack_info = { 'timestamp':float(packet.sniff_timestamp) }
                if upper:
                    pack = packet[name]
                    sess_key = f'addr={ip_addr}:{pack.srcport} proto={name}'
                else:
                    sess_key = f'addr={ip_addr} proto={name}'
                forward = upper
                break
        
        sessions_info[sess_key] = sessions_info.get(sess_key, (dict(), list()))
        
        nodes_info[ip_addr].add(sess_key)
        
        if not forward:
            continue
        
        sess_layers = ['quic', 'tls']
        
        for name in sess_layers:
            if name in packet:
                packs = packet.get_multiple_layers(name)
                pack_info[name] = list()
                for pack in packs:
                    if hasattr(pack, 'record'):
                        records = pack.record if type(pack.record) == list else [pack.record]
                        for rec in records:
                            if hasattr(rec, 'handshake'):
                                session_info = sessions_info[sess_key][0].get('handshake', list())
                                session_info.append(rec._all_fields['tls.handshake'])
                                sessions_info[sess_key][0]['handshake'] = session_info
                            else:
                                pack_info[name].append(rec._all_fields)
        
        if needed_proto in packet:
            packs = packet.get_multiple_layers(needed_proto)
            pack_info[needed_proto] = list()
            for pack in packs:
                pack = packet[needed_proto]
                pack_info[needed_proto].append(pack._all_fields)
            if 'DATA' in packet:
                pack_info['data'] = packet['DATA']._all_fields
        
        sessions_info[sess_key][1].append(prepare_for_output(pack_info))
    
    print(f"End handling of {pcap_file}\n", end='')
    
    captured.close()
    
    with write_lock:
        write(sessions_info, nodes_info, pcap_file)
    
files_range = glob.glob(pcap_file_mask, root_dir=needed_dir)

with Pool(4) as p:
    results = p.map(get_sessions, files_range)