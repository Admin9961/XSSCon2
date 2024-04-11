import requests
from lib.helper.Log import *
from lib.helper.helper import *
from lib.core import *
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from multiprocessing import Process

class crawler:

    visited = []

    @classmethod
    def getLinks(cls, base, proxy, headers, cookie):
        lst = []
        conn = session(proxy, headers, cookie)
        text = conn.get(base).text
        isi = BeautifulSoup(text, "html.parser")

        for obj in isi.find_all("a", href=True):
            url = obj["href"]
            
            if url.startswith(("http://", "https://", "mailto:", "javascript:", "tel:")):
                continue

            full_url = urljoin(base, url)
            if full_url not in cls.visited:
                lst.append(full_url)
                cls.visited.append(full_url)

        return lst

    @classmethod
    def crawl(cls, base, depth, proxy, headers, level, method, cookie):

        urls = cls.getLinks(base, proxy, headers, cookie)
        
        for url in urls:
            
            p = Process(target=core.main, args=(url, proxy, headers, level, cookie, method))
            p.start()
            p.join()
            if depth != 0:
                cls.crawl(url, depth-1, base, proxy, level, method, cookie)
                
            else:
                break
