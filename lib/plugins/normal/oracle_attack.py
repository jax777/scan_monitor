# coding:utf-8
import re
import hashlib
import struct
import binascii
import socket


plugin_info = {
    "name": "oracle弱口令",
    "info": "导致敏感信息泄露，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info




def check(ip, portinfo, timeout):
    return 0
    if portinfo['port']==1521 or  'oracle' in portinfo['type']:
        for _ in open("dict/oracle.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                if result == "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00":
                    plugin_info['vulinfo'] = 'mysql ' + dic[0] + '  :  ' + dic[1]
                    return 1
            except Exception, e:
                pass
        return 2
    return 0