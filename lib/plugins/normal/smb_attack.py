#coding:utf-8
from smb.SMBConnection import SMBConnection
import socket

plugin_info = {
    "name": "smb弱口令",
    "info": "直接导致机器被直接入侵控制。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info

def ip2hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        pass
    try:
        query_data = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41" + \
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" + \
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        dport = 137
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.sendto(query_data, (ip, dport))
        x = _s.recvfrom(1024)
        tmp = x[0][57:]
        hostname = tmp.split("\x00", 2)[0].strip()
        hostname = hostname.split()[0]
        return hostname
    except:
        pass

def check(ip, portinfo,timeout):
    socket.setdefaulttimeout(timeout)
    if portinfo['port']==445 or 'smb' in portinfo['type']:
        hostname = ip2hostname(ip)
        if not hostname: return 0
        for _ in open("dict/smb.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                conn = SMBConnection(dic[0], dic[1], 'sacnmonitor', hostname)
                if conn.connect(ip) == True:
                    plugin_info['vulinfo'] = 'smb ' + dic[0] + '  :  ' + dic[1]
                    return 1
            except:
                pass
        return 2
    return 0