# coding:utf-8
import telnetlib


plugin_info = {
    "name": "telnet弱口令",
    "info": "严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info



def check(ip, portinfo, timeout):
    if portinfo['port']==23 or 'telnet' in portinfo['type']:
        for _ in open("dict/telnet.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                tn = telnetlib.Telnet(ip, portinfo['port'], timeout=timeout)
                tn.set_debuglevel(3)
                # 输入登录用户名
                tn.read_until("login: ")
                tn.write(dic[0] + '\n')
                # 输入登录密码
                tn.read_until("Password: ")
                tn.write(dic[1] + '\n')
                if tn.read_until(dic[0] + "@"):
                    plugin_info['vulinfo'] = 'telnet ' + dic[0] + '  :  ' + dic[1]
                    return 1
            except:
                pass
        return 2
    return 0