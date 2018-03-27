# coding:utf-8

import requests
import re

plugin_info = {
    "name": "http proxy",
    "info": "http proxy 可入内网",
    "level": "高危",
    "type": "未授权",
    "url": "",
    "vulinfo": "",
}
headers =  {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0'}
def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    url = "http://ip.chinaz.com/getip.aspx"
    proxy = "http://" + ip + ":" + str(port)
    proxies = {'http': proxy}
    try:
        response = requests.get(url, timeout=timeout, headers=headers, proxies=proxies, verify=False)
        response.close()
        p_ip = re.search(r'''ip:'\d+\.\d+\.\d+\.\d+''',response.text).group()
        plugin_info['vulinfo'] = 'http proxy ： ' + p_ip
        return 1.
    except:
        return 0
