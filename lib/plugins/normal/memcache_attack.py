# coding:utf-8
import re
import socket

plugin_info = {
    "name": "memchche未授权",
    "info": "导致敏感信息泄露。",
    "level": "高危",
    "type": "未授权",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info



def check(ip, portinfo, timeout):
    socket.setdefaulttimeout(timeout)
    if  portinfo['port']==11211 or 'memchche' in portinfo['type']:
        payload = '\x73\x74\x61\x74\x73\x0a'  # command:stats
        s = socket.socket()
        try:
            s.connect((ip, portinfo['port']))
            s.send(payload)
            recvdata = s.recv(2048)  # response larger than 1024
            s.close()
            if recvdata and 'STAT version' in recvdata:
                plugin_info['vulinfo'] = 'memcache version:' + ''.join(re.findall(r'version\s(.*?)\s', recvdata))
                plugin_info['vulinfo'] += ' | total_items:' + ''.join(re.findall(r'total_items\s(\d+)\s', recvdata))
                return 1
        except:
            pass
        return 2
    return 0