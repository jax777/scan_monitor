# coding:utf-8
import requests
from config import HEADERS

plugin_info = {
    "name": "http_put",
    "info": "http_put方法开启",
    "level": "高危",
    "type": "服务器配置错误",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    tempheasers = HEADERS

    if domain:
        tempheasers['Host'] = domain
    url = webinfo['scheme'] + ip + ':' + port
    try:
        r = requests.options(url, timeout=timeout, headers=tempheasers, verify=False)
        if 'public' in r.headers and 'PUT' in r.headers['public']:
            requests.put(url + "/goodtest.txt", data='test', timeout=timeout, headers=tempheasers, verify=False)
            testreq = requests.get(url + "/goodtest.txt", timeout=timeout, headers=tempheasers, verify=False)
            if testreq.status_code == 200:
                plugin_info['vulinfo'] = 'http put'
                return 1
    except:
        pass

    return 0