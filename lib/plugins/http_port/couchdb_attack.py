# coding:utf-8


plugin_info = {
    "name": "couchdb",
    "info": "couchdb，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "未授权",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    if 'couchdb' in webinfo['content']:
        plugin_info['vulinfo'] = 'couchdb'
        return 1.
    else:
        return 0