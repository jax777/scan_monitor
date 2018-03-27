# coding:utf-8
import ftplib


plugin_info = {
    "name": "FTP弱口令",
    "info": "导致敏感信息泄露，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info



def check(ip, portinfo, timeout):
    if portinfo['port']==21 or 'ftp' in portinfo['type']:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, portinfo['port'], timeout)
            ftp.login()
            x = ftp.nlst()
            ftp.quit()
            plugin_info['vulinfo'] = 'ftp unauthed' + str(x)
            return 1
        except ftplib.all_errors:
            pass

        for _ in open("dict/ftp.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, portinfo['port'], timeout)
                ftp.login(dic[0],dic[1])
                x = ftp.nlst()
                ftp.quit()
                plugin_info['vulinfo'] = 'ftp '+ dic[0] + '  :  ' + dic[1] + '   ' + str(x)
                return 1
            except ftplib.all_errors:
                pass
        return 2
    return 0