# coding:utf-8
import ldap
import socket

plugin_info = {
    "name": "ldap弱口令",
    "info": "导致敏感信息泄露，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info



def check(ip, portinfo, timeout):
    socket.setdefaulttimeout(timeout)
    if portinfo['port']==389 or 'ldap' in portinfo['type']:
        for _ in open("dict/ldap.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                ldappath = 'ldap://' + ip + ':' + portinfo['port'] + '/'
                l = ldap.initialize(ldappath)
                re = l.simple_bind(dic[0], dic[1])
                if re == 1:
                    plugin_info['vulinfo'] = 'ldap ' + dic[0] + '  :  ' + dic[1]
                    return 1
            except:
                pass
        return 2
    return 0