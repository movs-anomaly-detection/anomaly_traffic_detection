import yadisk, io
import sys, os, json, glob
from multiprocessing.pool import ThreadPool
from multiprocessing import Lock
import parsers
from collections import Counter
from dotenv import load_dotenv

try:
    pcap_file_mask = sys.argv[1]
    
    save_to = sys.argv[2]
    ya_disk = False
    if save_to.startswith('@yadisk/'):
        save_to = ('app:' + save_to.removeprefix('@yadisk')).removesuffix('/')
        ya_disk = True
    elif not os.path.exists(save_to):
        os.mkdir(save_to)
    
    prefs = {
        'ssl.desegment_ssl_records': 'TRUE',
        'ssl.desegment_ssl_application_data': 'TRUE',
        'tcp.desegment_tcp_streams': 'TRUE' 
    }
    if len(sys.argv) == 4:
        if sys.argv[3].endswith(".key"):
            key_file = sys.argv[3]
            prefs['ssl.keys_list'] = key_file
        elif sys.argv[3].endswith(".log"):
            nss_file = sys.argv[3]
            prefs['tls.keylog_file'] = nss_file
        else: raise
except:
    print('Required arguments')
    print('1) pcap file mask')
    print('2) folder to save json-files to')
    print('3) key or log file (optional parameter)')
    exit()

if ya_disk:
    load_dotenv()
    ya_dsk_tkn = os.environ['YANDEX_DISK_TOKEN']
    cloud = yadisk.YaDisk(token=ya_dsk_tkn)
    assert cloud.check_token(), 'Yandex token is incorrect'
    if not cloud.exists(save_to):
        cloud.mkdir(save_to)

needed_dir = pcap_file_mask.removesuffix(pcap_file_mask.split('/')[-1])
pcap_file_mask = pcap_file_mask.removeprefix(needed_dir)

write_lock = Lock()

def write(sessions_info, nodes_info, pcap_file):
    # самый популярный ip-адрес - это тот с которого записывали
    ip_key = Counter(map(lambda sess: sess['addr'], sessions_info)).most_common(1)[0][0]
    
    nodes_info = list(filter(lambda node: ip_key != node['addr'], nodes_info))
    sessions_info = list(filter(lambda sess: ip_key != sess['addr'], sessions_info))
    
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

files_range = glob.glob(pcap_file_mask, root_dir=needed_dir)

def get_sessions(pcap_file: str):
    print(f'Begin handling of {pcap_file}\n', end='')
    
    parser = parsers.PCAPParser(needed_dir + pcap_file, prefs)
    sessions_info, nodes_info = parser.stop()
    with write_lock:
        write(sessions_info, nodes_info, pcap_file)
    
    print(f'End handling of {pcap_file}\n', end='')

with ThreadPool(min(4, len(files_range))) as p:
    results = p.map(get_sessions, files_range)