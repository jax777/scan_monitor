# coding:utf-8
import pymongo
import traceback

plugin_info = {
    "name": "Mongo弱口令",
    "info": "导致数据库敏感信息泄露，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "http://www.freebuf.com/vuls/85021.html",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    if 'trying to access MongoDB over HTTP' in webinfo['content']:
        try:
            try:
                conn = pymongo.MongoClient(ip, port, socketTimeoutMS=timeout)
                plugin_info['vulinfo'] = 'mongo unauthed '+ conn.database_names()
                return 1
            except:
                pass
            for user_pass in open("dict/mongo.dic", "r"):
                tmp = user_pass.strip()
                _ = tmp.split()
                user = _[0]
                passwd = _[1]
                try:
                    conn = pymongo.MongoClient(ip, port, socketTimeoutMS=timeout)
                    conn.security_detect.authenticate(
                        user,
                        passwd,
                        source='admin'
                    )
                    plugin_info['vulinfo'] = 'mongo user: '+ user + ' pass:' + passwd +' dbs '+ conn.database_names()
                    return 1
                except:
                    return 2
        except:
            traceback.print_exc()
            return 2
    else:
        return 0