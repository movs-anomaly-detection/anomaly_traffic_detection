import os, socket
from selenium import webdriver
from multiprocessing.pool import ThreadPool
from selenium.webdriver.firefox.options import Options

class UrlWalker:
    '''
    Класс для прохождения по url-ссылкам и выдаче для каждой ссылки её ip-адреса в виде frozenset.
    Создаёт специальный поток в котором происходит логика прохода по списку ссылок.
    '''
    
    __pool = ThreadPool(processes=1)
    
    @staticmethod
    def __webdriver_cycle_(urls: list[str], import_ssl_keys_to: str):
        if import_ssl_keys_to is not None:
            os.environ["SSLKEYLOGFILE"] = import_ssl_keys_to

        options = Options()
        options.add_argument("-headless")

        ips = list()

        with webdriver.Chrome(options) as driver:
            driver.set_page_load_timeout(2.5)
            driver.set_script_timeout(0.5)
            
            for url in urls:
                try: ips.append(socket.gethostbyname(url.split('://')[-1]))
                except: continue
                try: driver.get(url)
                except: pass
        
        return frozenset(ips)
    
    def __init__(self, urls: list[str], import_ssl_keys_to: str = None):
        self.__result = self.__pool.apply_async(UrlWalker.__webdriver_cycle_, args=[urls, import_ssl_keys_to])
    
    def get(self):
        return self.__result.get()
    
    def ready(self):
        return self.__result.ready()
    
    def __del__(self):
        self.__pool.close()