# coding:utf-8
import paramiko
import traceback

plugin_info = {
    "name": "ssh弱口令",
    "info": "严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(ip, portinfo,timeout):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if portinfo['port']==22 or 'ssh' in portinfo['type']:
        for _ in open("dict/ssh.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                ssh.connect(ip, portinfo['port'], dic[0], dic[1], timeout=timeout)
                ssh.close()
                plugin_info['vulinfo'] = 'ssh ' + dic[0] + '  :  ' + dic[1]
                return 1
            except:
                pass
        return 2
    return 0