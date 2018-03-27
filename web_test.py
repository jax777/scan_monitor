#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone

"""
from lib.mongohelp import MongoHelper
import json
target = 'qq'
limit = 10
offset = 10
cron = MongoHelper(target)
_ ,total= cron.get_service(offset,limit)
rows = list(_)
result = {'total': total, 'rows': rows}
"""

import requests
import time

url = 'http://127.0.0.1:8888'
target = 'tt'
domain = 'jj.cn'
cookie = {'target':target}
def add_target_test():
    r = requests.get(url+'/add_target/'+target)
    print r.content
    if '1' in r.content:
        print 'good add_target_test'
    else:
        print  'bad add_target_test'

def add_domain_test():
    data = {'domain':domain}
    r = requests.post(url+'/add_domain',data=data,cookies=cookie)
    print r.content
    if '1' in r.content:
        print 'good add_domain_test'
    else:
        print 'bad add_domain_test'

def start_sub_domain_test():
    r = requests.get(url+'/start_sub_domain',cookies=cookie)
    print r.content
    if '1' in r.content:
        print 'good sub_domain_test'
    else:
        print 'bad sub_domain_test'

def listip_test():
    while 1:
        time.sleep(60)
        r = requests.get(url+'/listip',cookies=cookie)
        print r.content
        if '1' in r.content:
            print 'good listip_test'
            return
        else:
            #print 'bad listip_test'
            pass
    return

def portscan_test():
    r = requests.get(url + '/start_scan', cookies=cookie)
    print r.content
    if '1' in r.content:
        print 'good portscan_test'
    else:
        print 'bad portscan_test'

if __name__ == '__main__':
    add_target_test()
    add_domain_test()
    start_sub_domain_test()
    listip_test()
    time.sleep(60)
    portscan_test()
