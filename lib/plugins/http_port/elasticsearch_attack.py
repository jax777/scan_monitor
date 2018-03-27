# coding:utf-8

plugin_info = {
    "name": "elasticsearch",
    "info": "elasticsearch泄漏，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "未授权",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info


def check(webinfo,ip,port,domain,timeout):
    if 'You Know, for Search' in webinfo['content']:
        plugin_info['vulinfo'] = 'elasticsearch '
        return 1.
    else:
        return 0