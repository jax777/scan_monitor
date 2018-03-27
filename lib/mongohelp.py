#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone

from config import MONGODB_CONFIG
import pymongo
import hashlib


def Mongodb(db_info,dbname,tablename):
    db_info = db_info
    client = pymongo.MongoClient(db_info.get('host'), db_info.get('port'))
    client.security_detect.authenticate(
        db_info.get('username'),
        db_info.get('password'),
        source='admin'
    )
    db = client[dbname]
    return db[tablename]


class MongoHelper():

    def __init__(self,target=''):
        self.target = target

    def show_targets(self):
        self.cron = Mongodb(MONGODB_CONFIG, MONGODB_CONFIG.get('dbname'), MONGODB_CONFIG.get('tablename'))
        result = self.cron.find({}, {"_id": 0, "target": 1})
        return result

    def show_domains(self):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'domain')
        result = self.cron.find({}, {"_id": 0, "domain": 1})
        return result

    def add_target(self,target):
        self.cron = Mongodb(MONGODB_CONFIG, MONGODB_CONFIG.get('dbname'), MONGODB_CONFIG.get('tablename'))
        self.cron.insert({'target':target})

    def update_sub_ip(self, id, ip, domain):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'subip')
        # ip domain status
        self.cron.update({'_id': id}, {'$set': {'ip': ip, 'domain': domain}})

    def add_domain(self,domain):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'domain')
        _ = domain.split(',')
        #print _
        for i in _:
            # ip domain status
            print 'add domain %s in %s' % (i,self.target)
            self.cron.insert({'domain': i, 'status': 0})

    def get_iplist(self,offset=0,limit=0):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'iplist')
        if limit == 0:
            result = self.cron.find({}, {"_id": 1, "domain": 1, "ip": 1})
            return result
        else:
            result = self.cron.find({}, {"_id": 1, "domain": 1, "ip": 1}).limit(limit).skip(offset)
            total = self.cron.find().count()
            return result, total

    def get_ip_port(self,status = 1,offset=0,limit=0):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'iplist')
        if limit == 0:
            result = self.cron.find({"status": status})
            return result
        else:
            result = self.cron.find({"status": status}, {'portinfo':0}).limit(limit).skip(offset)
            total = self.cron.find({"status": status}).count()
            return result,total

    def get_service(self,offset=0,limit=0):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'servicelist')
        if limit==0:
            result = self.cron.find()
            return result
        else:
            result = self.cron.find({}, {"_id": 0}).limit(limit).skip(offset)
            total = self.cron.find().count()
            return result,total


    def get_http_vul(self,offset=0,limit=0):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'httpinfo')
        if limit == 0:
            result = self.cron.find()
            return result
        else:
            result = self.cron.find({}, {"_id": 0}).limit(limit).skip(offset)
            total = self.cron.find().count()
            return result,total

    def get_port_vul(self,offset=0,limit=0):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'portvuls')
        result = self.cron.find({}, {"_id": 0}).limit(limit).skip(offset)
        total = self.cron.find().count()
        return result, total

    def get_tiny_scan(self,offset=0,limit=0):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'tinyscan')
        if limit == 0:
            result = self.cron.find()
            return result
        else:
            result = self.cron.find({}, {"_id": 0,'src':0}).limit(limit).skip(offset)
            total = self.cron.find().count()
            return result,total

    def show_progress(self,status = 1):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'iplist')
        total = self.cron.find().count()
        done = self.cron.find({"status": status}).count()
        rate = str(round(done*100.0/total,2))
        result = [rate,'width: '+rate+'%;',rate+'%'+'|%d/%d'%(done,total)]
        return result

#--------------------------------------------------------------------------------------------------#


    def wait_common(self,tablename):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, tablename)
        result = self.cron.find({"status": 0})
        return result

    def upadte_subdomain(self, tablename,subdomain):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, tablename)
        self.cron.update({'domain': subdomain}, {'$set': {'status': 1}})
        return 0

    def upadte_common(self,tablename):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, tablename)
        self.cron.update_many({'status': 0}, {'$set': {'status': 1}} )
        return 0

    def indert_common(self, tablename,info):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, tablename)
        self.cron.insert(info)
        return 0

    def insert_subip(self,domain,ip,islocal = 0):        # doamain a.qq.com|b.qq.com
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'subip')
        sub = {}
        sub['domain'] = domain
        sub['islocal'] = islocal
        sub['ip'] = ip
        sub['_id'] = hashlib.new('md5',ip).hexdigest()
        sub['status'] = 0
        try:
            self.cron.insert(sub)
        except pymongo.errors.DuplicateKeyError,e:
            _ = self.cron.find_one_and_delete({'_id':sub['_id']})
            sub['status'] = _['status']
            sub['domain'] += '|' + _['domain']
            self.cron.insert(sub)
        return 0

    def insert_iplist(self, domain, ip):  # doamain a.qq.com|b.qq.com
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'iplist')
        sub = {}
        sub['domain'] = domain    # doamain a.qq.com|b.qq.com
        sub['ip'] = ip
        sub['_id'] = hashlib.new('md5', ip).hexdigest()
        sub['status'] = 0
        try:
            self.cron.insert(sub)
        except pymongo.errors.DuplicateKeyError,e:
            _ = self.cron.find_one_and_delete({'_id':sub['_id']})
            if _['status']:
                sub['domain'] += '|sep|' + _['domain']
            else:
                sub['domain'] += '|' + _['domain']
            self.cron.insert(sub)
        return 0

    def insert_service(self,service):
        name = 'servicelist'
        self.cron = Mongodb(MONGODB_CONFIG, self.target, name)
        self.cron.insert_many(service)
        return 0

    def insert_port_vuls(self, portvuls):
        name = 'portvuls'
        self.cron = Mongodb(MONGODB_CONFIG, self.target,name)
        self.cron.insert_many(portvuls)
        return 0

    def insert_http_info(self, httpinfo):
        name = 'httpinfo'
        self.cron = Mongodb(MONGODB_CONFIG, self.target, name)
        self.cron.insert_many(httpinfo)
        return 0

    def insert_wait_scan(self,wait_scan):
        name = 'waitscan'
        self.cron = Mongodb(MONGODB_CONFIG, self.target, name)
        self.cron.insert_many(wait_scan)
        return 0

    def insert_tiny_scan(self,tiny_scan):
        name = 'tinyscan'
        self.cron = Mongodb(MONGODB_CONFIG, self.target, name)
        self.cron.insert_many(tiny_scan)
        return 0


    def update_ip_list_status(self,_id):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'iplist')
        self.cron.update_many({'_id': _id}, {'$set': {"status": 1}})
        return

    def update_ip_list(self,_id,portinfo):
        self.cron = Mongodb(MONGODB_CONFIG, self.target, 'iplist')
        ports = ''
        for i in portinfo:
            ports += str(i['port']) + '|'
        self.cron.update({'_id': _id}, {'$set': { "portinfo": portinfo,'ports':ports, "isup": 1}})
        return 0


