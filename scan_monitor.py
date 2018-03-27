#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone

import traceback
import os
import json

from multiprocessing import Process

import tornado.ioloop
import tornado.web
#from bson.json_util import dumps
#import bson
from tornado.escape import json_decode

from lib.portscaner import PortScaner
from lib.mongohelp import MongoHelper
from lib.core import subdomain
from lib.core import lsip
from lib.core import wrong_log

from config import WIDTH

import sys
reload(sys)
sys.setdefaultencoding('utf-8')


scan_process = []

class show_targets(tornado.web.RequestHandler):
    def get(self):
        try:
            cron = MongoHelper()
            result = cron.show_targets()
            _ = []
            for i in result:
                _.append(i['target'])
            self.write(json.dumps(_))
        except:
            self.write("0")

class show_domains(tornado.web.RequestHandler):
    def get(self):
        target = self.get_cookie("target")
        try:
            cron = MongoHelper(target)
            result = cron.show_domains()
            _ = []
            for i in result:
                _.append(i['domain'])
            self.write(json.dumps(_))
        except:
            self.write("0")


class add_target(tornado.web.RequestHandler):
    def get(self):
        target = self.get_argument('target')
        try:
            cron = MongoHelper()
            cron.add_target(target)
            self.set_cookie("target", target)
            self.write("1")
        except:
            self.write("0")

class set_target(tornado.web.RequestHandler):
    def get(self):
        target = self.get_cookie('target')
        self.set_cookie("target", target)
        self.write("1")

class update_ip_domain(tornado.web.RequestHandler):
    def post(self):
        data = json_decode.loads(self.request.body)
        target= self.get_cookie("target")
        try:
            cron = MongoHelper(target)
            cron.add_target(data['_id'],data['ip'],data['domain'])
            self.write("1")
        except:
            self.write("0")
            traceback.print_exc()

class add_domain(tornado.web.RequestHandler):
    def get(self):
        domain = self.get_argument('domain')       #qq.com,tencent.com
        target= self.get_cookie("target")
        try:
            cron = MongoHelper(target)
            cron.add_domain(domain)
            self.write("1")
        except:
            self.write("0")
            traceback.print_exc()


class get_iplist(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        offset = int(self.get_argument('offset'))
        limit = int(self.get_argument('limit'))
        try:
            cron = MongoHelper(target)
            _ ,total= cron.get_iplist(offset,limit)
            rows = list(_)
            result = {'total':total,'rows':rows}
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()

class get_ip_port(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        offset = int(self.get_argument('offset'))
        limit = int(self.get_argument('limit'))
        try:
            cron = MongoHelper(target)
            _ ,total = cron.get_ip_port(1,offset,limit)
            rows = list(_)
            result = {'total': total, 'rows': rows}
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()

class get_service(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        offset = int(self.get_argument('offset'))
        limit = int(self.get_argument('limit'))
        try:
            cron = MongoHelper(target)
            _,total = cron.get_service(offset,limit)
            rows = list(_)
            result = {'total': total, 'rows': rows}
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()

class get_http_vul(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        offset = int(self.get_argument('offset'))
        limit = int(self.get_argument('limit'))
        try:
            cron = MongoHelper(target)
            _, total = cron.get_http_vul(offset,limit)
            rows = list(_)
            result = {'total': total, 'rows': rows}
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()

class get_port_vul(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        offset = int(self.get_argument('offset'))
        limit = int(self.get_argument('limit'))
        try:
            cron = MongoHelper(target)
            _, total = cron.get_port_vul(offset,limit)
            rows = list(_)
            result = {'total': total, 'rows': rows}
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()



class get_tiny_scan(tornado.web.RequestHandler):
    def get(self):
        target = self.get_cookie("target")
        offset = int(self.get_argument('offset'))
        limit = int(self.get_argument('limit'))
        try:
            cron = MongoHelper(target)
            _, total = cron.get_tiny_scan(offset, limit)
            rows = list(_)
            result = {'total': total, 'rows': rows}
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()


class show_progress(tornado.web.RequestHandler):
    def get(self):
        target = self.get_cookie("target")
        try:
            cron = MongoHelper(target)
            result = cron.show_progress()
            self.write(json.dumps(result))
        except:
            self.write("0")
            traceback.print_exc()





class listip(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        cron = MongoHelper(target)
        if (not cron.wait_common('domain').count()):
            p = Process(target=lsip, args=(target,WIDTH,))
            p.start()
            self.write("1")
        else:
            self.write("0")
            pass

class start_sub_domain(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        p = Process(target=subdomain, args=(target,))
        p.start()
        self.write("1")

#----------------------------------------------------#
def startscan_fun(target):
    p = PortScaner(target)
    p.run()


class start_scan(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        print 'start scan ' , target
        p = Process(target=startscan_fun, args=(target,))
        p.start()
        self.write("1")

#----------------------------------------------------#
def autoscan_func(target):
    subdomain(target)
    lsip(target,WIDTH)
    p = PortScaner(target)
    p.run()

class autoscan(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        p = Process(target=autoscan_func, args=(target,))
        p.start()
        scan_process.append(p)
        self.write("1")
# ----------------------------------------------------#

#----------------------------------------------------#
def scan_again_func(target):
    p = PortScaner(target,False)
    p.run()

class scan_again(tornado.web.RequestHandler):
    def get(self):
        target= self.get_cookie("target")
        p = Process(target=scan_again_func, args=(target,))
        p.start()
        scan_process.append(p)
        self.write("1")
# ----------------------------------------------------#

"""
class send_to_brute(tornado.web.RequestHandler):
    def post(self):
        data = json_decode.loads(self.request.body)
        #{"ip":"xx","port":"808","type":"mongo"}
        target = self.get_cookie("target")
        command = 'hydra -L users.txt -P password.txt -t 1 -s %s -vV -e ns   %s %s' %(data['ip'],data['ip'],'type')
        pass
"""

class index(tornado.web.RequestHandler):
    def get(self):
        self.render('index.html')
def make_app():
    settings = {
        "static_path": os.path.join(os.path.dirname(__file__), "static"),
    }
    return tornado.web.Application([
        (r"/show_targets", show_targets),
        (r"/add_target", add_target),
        (r"/set_target", set_target),
        (r"/update_ip_domain", update_ip_domain),
        (r"/add_domain", add_domain),
        (r"/show_domains", show_domains),
        (r"/get_iplist", get_iplist),
        (r"/get_ip_port", get_ip_port),
        (r"/get_service", get_service),
        (r"/get_http_vul", get_http_vul),
        (r"/get_tiny_scan", get_tiny_scan),
        (r"/get_port_vul", get_port_vul),
        (r"/show_progress", show_progress),

#?order=asc&offset=0&limit=10
        (r"/start_sub_domain", start_sub_domain),
        (r"/listip", listip),
        (r"/start_scan", start_scan),

        (r"/autoscan", autoscan),

        (r"/scan_again", scan_again),
        #(r"/send_to_brute", send_to_brute),
        #js css html
        (r"/index", index),
    ], **settings)



if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()