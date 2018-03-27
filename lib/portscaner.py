#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone


import imp
import os
import nmap
import time
import threading
import requests
import time
import chardet
import traceback
from bs4 import BeautifulSoup


from webscaner.BBScan import batch_scan

from gevent.pool import Pool
from gevent import monkey

from lib.common_spider import Spider

from lib.plugins.heartbleed_attack import heratbleed_attack

from lib.mongohelp import MongoHelper

from lib.core import wrong_log
from lib.core import info_log

from config import SCAN_THREADS
from config import GLOBAL_NMAP_ARGUMENTS
from config import HEADERS
from config import TIMEOUT
monkey.patch_all()


def get_title(text):
    try:
        soup = BeautifulSoup(text, "html.parser")
        if soup.title:
            return soup.title.string
        else:
            return text[:20]
    except Exception,e:
        wrong_log(traceback.format_exc())


class PortScaner():
    def __init__(self, target='',new = True):
        self.target = target
        self.normal_plugins = []
        self.http_port_plugins = []

        self.load_normal_plugins()
        self.load_http_port_plugins()
        #self.load_http_plugins()

        self.new = new
        #self.service = []
        #self.port_vuls = []   #  id ip_domain port  type version
        #self.http_info = [] # id ip  url  title src tinyscan - ｛ url_domain title src isvul ｝
        #self.wait_scan = []
        self.stop = True


    def save_to_db(self,service,port_vuls,http_info,wait_scan,tiny_scan):
        print 'save_to_db runing',self.target
        try:
            if len(service)>0:
                print 'store service'
                cron = MongoHelper(self.target)
                cron.insert_service(service)
            if len(port_vuls) > 0:
                print 'store port_vuls'
                cron = MongoHelper(self.target)
                cron.insert_port_vuls(port_vuls)
            if len(http_info) > 0:
                print 'store http_info'
                cron = MongoHelper(self.target)
                cron.insert_http_info(http_info)
            if len(tiny_scan) > 0:
                print 'store tiny_scan'
                cron = MongoHelper(self.target)
                cron.insert_tiny_scan(tiny_scan)
            if len(wait_scan) > 0:
                print 'store wait_scan'
                cron = MongoHelper(self.target)
                cron.insert_wait_scan(wait_scan)
        except Exception,e:
            wrong_log(traceback.format_exc())


    def load_normal_plugins(self):
        p_name = os.listdir('lib/plugins/normal')
        detect_names = {}

        for name in p_name:
            main_name = name.split('.')[0] # file name
            if main_name in detect_names:
                detect_names[main_name] = 1
            else:
                detect_names[main_name] = 0
        for i in detect_names:
            fp, pathname, description = imp.find_module(i, ['lib/plugins/normal'])
            m = imp.load_module(i, fp, pathname, description)
            self.normal_plugins.append(m)


    def load_http_port_plugins(self):
        p_name = os.listdir('lib/plugins/http_port')
        detect_names = {}

        for name in p_name:
            main_name = name.split('.')[0]  # file name
            if main_name in detect_names:
                detect_names[main_name] = 1
            else:
                detect_names[main_name] = 0
        for i in detect_names:
            fp, pathname, description = imp.find_module(i, ['lib/plugins/http_port'])
            m = imp.load_module(i, fp, pathname, description)
            self.http_port_plugins.append(m)








    def get_web_info(self,ip,port,domain):
        webinfo = {
            'httpcode':200,
            'scheme':'http://',
            'content':'',
            'title':'',

        } # null means not a http server port
        headers = HEADERS
        if domain:
            headers['Host'] = domain

        url = ip +':'+str(port)
        #info_log(url)
        try:
            r = requests.get('http://'+url, timeout=4, headers=headers)
            r.close()
            webinfo['httpcode'] = r.status_code
            if r.status_code == 400:
                r = requests.get('https://'+url, timeout=4, headers=headers, verify=False)
                r.close()
                webinfo['httpcode'] = r.status_code
                webinfo['scheme'] = 'https://'
            else:
                webinfo['scheme'] = 'http://'
                webinfo['httpcode'] = r.status_code
            if r.content:
                enc = chardet.detect(r.content)
                webinfo['content'] = r.content.decode(enc['encoding'], 'ignore').encode('utf-8')
                webinfo['title'] = get_title(webinfo['content'])
            else:
                pass
        except Exception,e:
            # something wrong------------------------------------------------
            #wrong_log('get_web_info  '+ url)
            #wrong_log(traceback.format_exc())
            return False

        return webinfo



    def get_port_info_nmap(self,ip):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments=GLOBAL_NMAP_ARGUMENTS)
            result=[]
            """
           >>> nm['127.0.0.1']['tcp']
    {8888: {'product': '', 'state': 'open', 'version': '', 'name': 'sun-answerbook', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 27017: {'product': '', 'state': 'open', 'version': '', 'name': 'unknown', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 22: {'product': '', 'state': 'open', 'version': '', 'name': 'ssh', 'conf': '10', 'extrainfo': 'protocol 2.0', 'reason': 'syn-ack', 'cpe': ''}, 50000: {'product': '', 'state': 'open', 'version': '', 'name': 'ibm-db2', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}}

           """
            try:
                for v, k in nm[ip].get('tcp').items():
                    _ = {}
                    #print k
                    try:
                        _['port'] = v
                        _['name'] = k['name']
                        _['version'] = k['version']
                        _['type'] = k['product'].lower()
                        result.append(_)
                    except Exception,e:
                        wrong_log('get_port_info_nmap  ' + str(v))
                        #wrong_log(str(traceback.format_exc()))
            except Exception, e:
                pass
                #print nm
                #wrong_log(traceback.format_exc())
            return result
        except:
            time.sleep(1800)
            return 0

    def get_port_info_zmap(self):
        pass

    def get_port_info_masscan(self):
        pass

    def ip_filter(self):
        pass



    def send_to_http_port_plugins(self,webinfo,ip,port,domain,port_vuls):
        # something wrong------------------------------------------------#
        for _ in self.http_port_plugins:
            #info_log(str(_))
            flag = _.check(webinfo,ip,port,domain,TIMEOUT )
            if flag:
                if flag == 1:
                    # save something into db
                    vul = {}
                    vul['ip'] = ip
                    vul['ip_domain'] = ip + '|' + domain
                    #vul['domain'] = domain
                    vul['port'] = port
                    vul['vulinfo'] = _.get_plugin_info()['vulinfo']
                    port_vuls.append(vul)
                    #info_log(str(vul))
                    return 0
                else:
                    # flag 2
                    return 0
        # normal http server   send to tiny_http_scan
        return 1

    def send_to_normal_plugins(self,ip,portinfo,domain,port_vuls):
        # something wrong------------------------------------------------#
        for _ in self.normal_plugins:
            #info_log(str(_))
            flag = _.check( ip, portinfo,TIMEOUT)
            if flag:
                if flag==1:
                    # save something into db
                    vul = {}
                    vul['ip'] = ip
                    vul['ip_domain'] = ip+'|'+ domain
                    #vul['domain'] = domain
                    vul['port'] = portinfo['port']
                    vul['vulinfo'] = _.get_plugin_info()['vulinfo']
                    port_vuls.append(vul)
                    #info_log(str(vul))
                    return
                else:
                    #flag 2
                    return


    def http_tiny_scan(self,webinfo,ip,port,domain,http_info,wait_scan,tiny_scan):
        # start  here
        url = webinfo['scheme'] + ip + ':' + str(port)
        #info_log('http_tiny_scan '+ url)
        tmp_tiny_scan = batch_scan(url,domain)
        tiny_scan += tmp_tiny_scan
        vul = {}
        vul['httpcode'] = webinfo['httpcode']
        vul['domain_url'] = domain + '|'+url
        vul['title'] = webinfo['title']
        vul['content'] = webinfo['content']
        vul['tiny_scan'] = len(tmp_tiny_scan)
        spider = Spider(ip,url,domain,webinfo['scheme'])
        req_wait_sacn = spider.run()
        wait_scan += req_wait_sacn
        #info_log(str(req_wait_sacn))
        http_info.append(vul)



    def scan(self,ipinfo):
        try:
            service = []
            port_vuls = []  # id ip_domain port  type version
            http_info = []  # id ip  url  title src tinyscan - ｛ url_domain title src isvul ｝
            wait_scan = []
            tiny_scan = []
            _id = ipinfo['_id']
            ip = ipinfo['ip']
            print 'scan', ip
            if '|sep|' in ipinfo['domain']:
                domains = ipinfo['domain'].split('|sep|')[0].split('|')
            else:
                domains = ipinfo['domain'].split('|')
            cron = MongoHelper(self.target)
            cron.update_ip_list_status(_id)
            if self.new:
                portinfos = self.get_port_info_nmap(ip)
            else:
                portinfos = ipinfo['portinfo']

            if portinfos == 0:
                print 'nmap error'
                return 0
            cron = MongoHelper(self.target)
            cron.update_ip_list(_id,portinfos)
            # portinfo [{port,type,version},]
            for portinfo in portinfos:
                for domain in domains:
                    webinfo = self.get_web_info(ip,portinfo['port'],domain)
                    if webinfo:
                        #http
                        ip_domain = ip+'-'+domain
                        service.append({'ip_domain':ip_domain,'port':portinfo['port'],'type':portinfo['type'],'version':portinfo['version']})      #  id ip_domain port  type version
                        # service Redundancy
                        #info_log('append service' + ip_domain)
                        if 'https' in webinfo['scheme']:
                            ssl_info = heratbleed_attack(ip,portinfo['port'])
                            if ssl_info:
                                port_vuls.append(ssl_info)
                            self.http_tiny_scan(webinfo, ip, portinfo['port'], domain,http_info,wait_scan,tiny_scan)
                        else:
                            if self.send_to_http_port_plugins(webinfo,ip,portinfo['port'],domain,port_vuls):
                                self.http_tiny_scan(webinfo,ip,portinfo['port'],domain,http_info,wait_scan,tiny_scan)

                        self.send_to_normal_plugins(ip, portinfo, domain, port_vuls)
                            # something wrong strtus2 weblojic
                    else:
                        #normal
                        service.append({'ip_domain': ip, 'port': portinfo['port'], 'type': portinfo['type'],'version': portinfo['version']})
                        self.send_to_normal_plugins(ip,portinfo,domain,port_vuls)
                        #info_log('append service'+ip)
                        break
            self.save_to_db(service,port_vuls,http_info,wait_scan,tiny_scan)
        except Exception,e:
            wrong_log(traceback.format_exc())

    def run(self):
        cron = MongoHelper(self.target)
        _=cron.get_ip_port(0)
        self.iplist = list(_)
        #gevent
        scan_pool = Pool(SCAN_THREADS)
        print 'scan'
        scan_pool.map(self.scan, self.iplist)
        self.stop = False


