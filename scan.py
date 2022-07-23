import requests
import re 
import json
import threading
import os
def request(flow):
    request = flow.request 
    url=request.url
    mutex = threading.Lock()
    for i in range(2):
        t = threading.Thread(target=scan, args=(url, mutex))
        t.start()


def scan(url,t):
    t.acquire()
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
    }
    pathDir = os.listdir('../plug/vul/')
    for allDir in pathDir:
        p = os.path.join('../plug/vul/' + allDir)
        try:
            with open(p, 'rt', encoding='utf-8') as f:
                json_data = json.load(f)
                u=re.sub("(?<==)([^&]*)",json_data['payload'],url)
                response = requests.get(u, headers=header)
                i = re.search(json_data['res'], response.text)
                if i:
                    print('[+] 存在漏洞：' + json_data['name'])
                    print(u)
                    with open('../result/report.txt','at') as f:
                        f.writelines(u+'\n')
        except Exception as e:
            pass
