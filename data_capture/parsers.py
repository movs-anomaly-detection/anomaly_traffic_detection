from collections import Counter
import re
import pyshark
# import maxminddb
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from math import log2
from multiprocessing.pool import ThreadPool
from threading import Lock


class EntropyComputer:
    '''
    Класс для рассчёта энтропий
    '''
    
    def __init__(self):
        self.__counts = dict()
        self.__data_len = 0
    
    def new_data(self, data: bytes):
        for key, value in Counter(data).items():
            self.__counts[key] = self.__counts.get(key, 0) + value
        self.__data_len += len(data)
    
    def entropy(self):
        counts = self.__counts.values()
        
        xlogx = lambda p: p * log2(p)
        shannon_entropy = -sum(xlogx(pv / self.__data_len) for pv in counts)
        
        estimated = self.__data_len / 256
        chi2_entropy = 1
        if estimated != 0:
            chi2_entropy = sum(pow(pv - estimated, 2) / estimated for pv in counts) + (256 - len(counts)) * estimated
        
        return shannon_entropy, chi2_entropy


class SessionAllotter:
    '''
    Класс для парсинга пакетов и хранения информации по сессиям
    '''
    
    def __init__(self):
        self.__nodes_info, self.__sessions_info = dict(), dict()
    
    @staticmethod
    def __get_dict_(s):
        match_list = re.fullmatch(r'addr=([\d.]+):?(\d*) proto=(\w+)', s)
        if len(match_list.regs) == 4:
            return { 'addr':match_list[1], 'port':match_list[2], 'proto':match_list[3] }
        return { 'addr':match_list[1], 'proto':match_list[2] }
    
    @property
    def nodes_info(self):
        return self.__nodes_info

    @nodes_info.getter
    def nodes_info(self):
        def remove_prefix(obj):
            ret = { ('addr',obj[0]) }
            new_list = [dict(set(SessionAllotter.__get_dict_(s).items()) - ret) for s in obj[1]]
            return dict(ret) | { 'sessions':new_list }
        return list(map(remove_prefix, self.__nodes_info.items()))

    @property
    def sessions_info(self):
        return self.__sessions_info
    
    @sessions_info.getter
    def sessions_info(self):
        def create_dict(item):
            dict_item = SessionAllotter.__get_dict_(item[0])
            dict_item |= item[1][0]
            dict_item['shannon_entropy'], dict_item['chi2_entropy'] = item[1][2].entropy()
            dict_item['packets'] = item[1][1]
            return dict_item
        return list(map(create_dict, self.__sessions_info.items()))
    
    @classmethod
    def get_fields(cls, pre_json_object) -> dict:
        if pre_json_object is None or pre_json_object == 'None':
            return None
        if issubclass(type(pre_json_object), str):
            if re.fullmatch(r'([0-9a-f][0-9a-f]:)+[0-9a-f][0-9a-f]', pre_json_object) is not None:
                pre_json_object = pre_json_object.replace(':', '')
            if re.fullmatch(r'0x[0-9a-f]+', pre_json_object) is not None:
                pre_json_object = int(pre_json_object, base=16)
            elif re.fullmatch(r'\d+', pre_json_object) is not None:
                pre_json_object = int(pre_json_object)
            return pre_json_object
        if type(pre_json_object) is list:
            return [cls.get_fields(value) for value in pre_json_object]
        if type(pre_json_object) is bytes:
            return pre_json_object.hex()
        if type(pre_json_object) is int:
            return pre_json_object
        
        if hasattr(pre_json_object, 'field_names'):
            new_dict = dict()
            for key in pre_json_object.field_names:
                value = cls.get_fields(pre_json_object.get_field(key))
                
                if not key.endswith('_tree'):
                    key = key.split('.')[-1]
                    if key == 'certificate' and type(value) is list:
                        def get_cert_info(raw_cert: str):
                            if len(raw_cert) % 2 != 0:
                                return {}
                            cert = x509.load_der_x509_certificate(bytes.fromhex(raw_cert))
                            
                            if cert.issuer == cert.subject:
                                is_selfissued = True
                                try:
                                    # код взят из туториала (не помню какого)
                                    issuer_public_key = cert.public_key()
                                    issuer_public_key.verify(
                                        cert.signature,
                                        cert.tbs_certificate_bytes,
                                        # Depends on the algorithm used to create the certificate
                                        padding.PKCS1v15(),
                                        cert.signature_hash_algorithm,
                                    )
                                    is_selfsigned = True
                                except:
                                    is_selfsigned = False
                            else:
                                is_selfissued = False
                                is_selfsigned = False
                                
                            return {
                                'serial_number':cert.serial_number,
                                'is_selfissued':is_selfissued,
                                'is_selfsigned':is_selfsigned,
                                'fingerprint':cert.fingerprint(hashes.SHA256()).hex()
                            }
                        value = [get_cert_info(raw_cert) for raw_cert in value]
                    new_dict[key] = value
                    
            return new_dict
        
        return None
    
    def __call__(self, packet):
        ip_addr = packet['ip'].src
        self.__nodes_info[ip_addr] = self.__nodes_info.get(ip_addr, set())
        
        tr_layers = ['udp', 'tcp'] #, ('arp', False), ('icmp', False), ('dns', False), ('netbios', False)
        # forward = False
        pack_info = dict()
        
        sess_key = None
        for name in tr_layers:
            if name in packet:
                pack_info = { 'timestamp':float(packet.sniff_timestamp) }
                pack = packet[name]
                sess_key = f'addr={ip_addr}:{pack.srcport} proto={name}'
                break
        
        if sess_key is None: return
        
        self.__sessions_info[sess_key] = self.__sessions_info.get(sess_key, (dict(), list(), EntropyComputer()))
        
        self.__nodes_info[ip_addr].add(sess_key)
        
        sess_layers = ['tls']
        
        for name in sess_layers:
            if name in packet:
                packs = packet.get_multiple_layers(name)
                pack_info[name] = list()
                for pack in packs:
                    if hasattr(pack, 'record'):
                        records = pack.record if type(pack.record) is list else [pack.record]
                        for rec in records:
                            if hasattr(rec, 'handshake'):
                                session_info = self.__sessions_info[sess_key][0].get('handshake', list())
                                handshake_msg = self.get_fields(rec.get_field('handshake'))
                                
                                def hs_fields_parse(hmsg):
                                    if hmsg is not None:
                                        hmsg['timestamp'] = pack_info['timestamp']
                                        return hmsg
                                
                                if type(handshake_msg) is list:
                                    session_info.extend(filter(lambda x: x is not None, map(hs_fields_parse, handshake_msg)))
                                elif handshake_msg is not None:
                                    session_info.append(hs_fields_parse(handshake_msg))
                                
                                self.__sessions_info[sess_key][0]['handshake'] = session_info
                            else:
                                tls_pack = self.get_fields(rec)
                                def tls_packet(msg):
                                    if 'app_data' in msg:
                                        self.__sessions_info[sess_key][2].new_data(bytes.fromhex(msg['app_data']))
                                    else:
                                        pack_info[name].append(msg)
                                if type(tls_pack) is list:
                                    for p in tls_pack: tls_packet(p)
                                else:
                                    tls_packet(tls_pack)
        
        self.__sessions_info[sess_key][1].append(pack_info)


class PCAPParser:
    '''
    Класс для парсинга .pcap-файла
    '''
    
    def __init__(self, pcap_filename: str, preferences: dict = {}):
        self.__parser = SessionAllotter()
        self.__captured = pyshark.FileCapture(
            pcap_filename, display_filter='ip',
            override_prefs=preferences, use_json=True
        )
        self.__captured.apply_on_packets(self.parser)
    
    def stop(self):
        # try:
        #     (parser, self.captured)
        # except:
        #     print('Something went wrong...')
        return self.__parser.sessions_info, self.parser.nodes_info
    
    def __del__(self):
        self.__captured.close()


class LiveParser:
    '''
    Класс для парсинга интернет-трафика с сетевой карты
    '''
    
    __lock = Lock()
    __run = False
    __pool = ThreadPool(processes=1)
    
    def __handle_(self, interface: str, preferences: dict):
        parser = SessionAllotter()
        with pyshark.LiveCapture(
            interface, bpf_filter='ip',
            override_prefs=preferences, use_json=True
        ) as live_capture:
            for packet in live_capture.sniff_continuously():
                parser(packet)
                with self.__lock:
                    if not self.__run: break
        return parser.sessions_info, parser.nodes_info
    
    def __init__(self, interface: str, preferences: dict = {}):
        self.__run = True
        self.__result = self.__pool.apply_async(func=lambda: self.__handle_(interface, preferences))
    
    def stop(self):
        with self.__lock:
            self.__run = False
        return self.__result.get()
    
    def __del__(self):
        self.__pool.close()