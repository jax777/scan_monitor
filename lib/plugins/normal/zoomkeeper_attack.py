# coding:utf-8
import socket


plugin_info = {
    "name": "Zookeeper未授权访问",
    "info": "Zookeeper Unauthorized access",
    "level": "中危",
    "type": "未授权访问",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info



def check(ip, portinfo, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, portinfo['port']))
        flag = "envi"
        # envi
        # dump
        # reqs
        # ruok
        # stat
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'Environment' in data:
            plugin_info['vulinfo'] = 'zoomkeeper unauthed '
            return 1
    except:
        pass
    return 0