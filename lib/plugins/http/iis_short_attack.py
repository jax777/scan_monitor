# coding:utf-8
import requests
from config import HEADERS

plugin_info = {
    "name": "iss_short",
    "info": "iss短文件名",
    "level": "低位",
    "type": "组件版本过低",
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
        r1 = requests.get(url + '/*~1****/a.aspx', timeout=timeout, headers=tempheasers, verify=False)
        r2 = requests.get(url + '/woshihaoren*~1****/a.aspx', timeout=timeout, headers=tempheasers, verify=False)
        if r1.status_code == 404 and r2.status_code == 400:
            plugin_info['vulinfo'] = 'iss short'
            return 1
    except:
        pass
    return 0