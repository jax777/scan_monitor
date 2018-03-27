#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone

import hashlib
import os
from socket import inet_aton
from socket import inet_ntoa
from struct import unpack
from struct import pack
from lib.mongohelp import MongoHelper


def load_plugins():
    pass

def ip2long(ip_addr):
    return unpack("!L", inet_aton(ip_addr))[0]

def long2ip(ip_addr):
    return inet_ntoa(pack("!L", ip_addr))

def islocal(ip):
    ret = ip.split('.')
    if not len(ret) == 4:
       return 1
    if ret[0] == '10':
       return 1
    if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
       return 1
    if ret[0] == '192' and ret[1] == '168':
       return 1
    return 0



def lsip(target,width):
    ip_info = dict(
        _id = '',
        site = '',
        ip = '',
        portinfo = {},
        islocal = 0,
        status = 0
    )
    iplist = []
    cron = MongoHelper(target)
    for item in cron.wait_common('subip'):
        ip = item["ip"]
        if islocal(ip):
            pass
        else:
            iplist.append(ip)
    for ip in iplist:
        iptemp = ip2long(ip)
        for i in range(iptemp-width,iptemp+width):
            _ip = long2ip(i)
            try:
                ip_info = dict(
                    _id = hashlib.new('md5',_ip).hexdigest(),
                    domain = '',
                    ip = _ip,
                    portinfo = {},
                    status = 0,
                    isup = 0
                )
                cron.indert_common('iplist',ip_info)
            except:
                pass

    cron.upadte_common('subip')

def delay_subdomain_end(doamin):
    lock = doamin+'lock'
    while 1:
        os.system("cd subdomain/lock/ && ps -A| grep subdomain > %s" % lock)  # lock
        if not (os.path.getsize('subdomain/lock/'+lock)):
            os.system("cd subdomain/lock/ && rm -rf %s" % lock)
            return



def subdomain(target):
    cron = MongoHelper(target)
    for item in cron.wait_common('domain'):
        domain = item['domain']
        os.system('cd thirdparty/subDomainsBrute/ && python subDomainsBrute.py --full -o ../../subdomain/'+domain+' '+domain)
        delay_subdomain_end(domain)
        sub_file_to_db(target,domain)
        tc = MongoHelper(target)
        tc.upadte_subdomain('domain',domain)


def sub_file_to_db(target,domain):
    print 'sub_file_to_db'
    cron = MongoHelper(target)
    s_d = {}
    for sub in open("subdomain/"+domain, "r"):
        _sub = sub.split()
        for _ in _sub[1:]:
            ip = _.replace(',','')
            domain = _sub[0]
            if ip in s_d:
                s_d[ip] = s_d[ip] + '|' + domain
            else:
                s_d[ip] =  domain
            #cron.insert_subip(_sub[0],_.replace(',','')
    for i in s_d:
        if islocal(i):
            cron.insert_subip(s_d[i], i,1)
        else:
            cron.insert_subip(s_d[i], i)
            cron.insert_iplist(s_d[i], i)


def send_to_brute():
    pass


def wrong_log(wrong_info):
    with open('wrong.info', 'a') as f:
        f.write(wrong_info)
        f.write('\n--------------------------------------------------------------\n')


def info_log(info):
    with open('infolog.info', 'a') as f:
        f.write(info)
        f.write('\n--------------------------------------------------------------\n')

def passive_dns(domain):
    pass