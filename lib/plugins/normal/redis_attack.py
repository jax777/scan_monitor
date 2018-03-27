# coding:utf-8
import socket
import traceback

plugin_info = {
    "name": "Redis弱口令",
    "info": "导致数据库敏感信息泄露，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "http://www.freebuf.com/vuls/85021.html",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(ip, portinfo,timeout):
    if portinfo['port']==6379 or 'redis' in portinfo['type']:
        try:
            socket.setdefaulttimeout(timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, portinfo['port']))
            s.send("INFO\r\n")
            result = s.recv(1024)
            if "redis_version" in result:
                plugin_info['vulinfo'] = 'redis unauthed '
                return 1
            elif "Authentication" in result:
                for password in open("dict/redis_pass.dic", "r"):
                    _password = password.strip()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip, portinfo['port']))
                    s.send("AUTH %s\r\n" % (_password))
                    result = s.recv(1024)
                    if '+OK' in result:
                        plugin_info['vulinfo'] = 'redis pass : '+ _password
                        return 1
        except Exception, e:
            traceback.print_exc()
            return 2
    return 0