#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone

import requests
import Queue
import urlparse
import re
import traceback
import chardet

from lib.requests_browser import Requests_browser

from  lib.core import info_log
from  lib.core import wrong_log

from lxml import etree



def get_current_path(url):
    i = -1
    while url[i] != '/':
        i = i -1
    return url[:i+1]

def get_current_host(url):
    _ = url.split('/')
    return _[0]+ '//' + _[2]

def get_scheme(url):
    _ = url.split('/')
    return _[0]+ '//'



class Spider():
    # request store format  [1 (get)/0 (post),url,data]
    def __init__(self,ip,url,domain,scheme,depth=2):
        self.ip = ip
        #self.target = target       # detect crawl
        self.url = url
        self.domain = domain
        self.depth = depth      # crawl  depth limit   2
        self.req_scan = []    #  [1 (get)/0 (post),url,data]
        self.reqque = Queue.Queue()   # [req,depth]
        self.reqque.put([[1,url,''],1])

        self.blacklist = ['tomcat',
                     'nginx',
                     'index of',
                     'directory',
                     'iis',
                     'jenkins',
                     'tengine',
                     'lnmp',
                     'xampp',
                     'oneinstack',
                     'phpstudy',
                     'server test page',
                     'microsoft',
                     'phpmyadmin',
                     ]

        self.detecion = []



        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                      '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1'}

        if domain:
            self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                      '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1',
                        'Host': domain}
        #self.requests_browser = Requests_browser(self.headers)

        # PHANTOMJS
    def set_headers(self,url):
        domain =  url.split('/')[2].split(':')[0]
        if self.ip == domain:
            return self.headers
        else:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                     '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1',
                       'Host': domain}
            return headers


    def get_html(self,req):
        # [1 (get)/0 (post),url,data]
        try:
            if req[0]:
                r = requests.get(req[1], headers=self.set_headers(req[1]), verify=False)
                #r = self.requests_browser.get(req[1])
                enc = chardet.detect(r.content)
                content = r.content.decode(enc['encoding'], 'ignore').encode('utf-8')
                return content
            else:
                r = requests.post(req[1], headers=self.set_headers(req[1]),data = req[2],verify=False)
                enc = chardet.detect(r.content)
                content = r.content.decode(enc['encoding'], 'ignore').encode('utf-8')
                return content
        except Exception,e:
            #wrong_log(traceback.format_exc())
            #wrong_log(str(req))
            return 'wrong status'


    def black_detect(self,title):
        # detcet by title
        title = title.lower()

        for i in self.blacklist:
            if i in title:
                return True   # stop
        return False    # continue scan


    def detect(self,req):
        url = str(req[1])
        #domain = url.split('/')[2]
        # http://140.207.69.83:80/thread-45758770-10-1.html 待解决
        #http:fm.qq.com/category/39110_38942
        #http://www.iqiyi.com/w_19ruj41o0l.html


        try:
            if url:
                _ = urlparse.urlparse(url)
                if req[0]:
                    # get 伪静态
                    if _[4]:
                        pass
                    elif '_' in url or '-' in url:
                        pass
                    else:
                        return 0


            #if self.ip in domain or  self.target in domain:     # detect  domain area
                some_control_word = ['method','m','action','act','cmd','commmand','ac',]
                url = re.sub(r'[\w_-]{28,}', '', url)
                url = re.sub(r'[\w_-]{16}', '', url)
                url = re.sub(r'[\d]{10,13}', '', url)
                _ = urlparse.urlparse(url)
                params = urlparse.parse_qs(_[4])
                path = re.sub(r'\d+', '', _[2])
                path_tmp = path.split('/')
                path_new = ''
                for i in path_tmp:
                    count = i.count('_') + i.count('-')
                    if count:
                        path_new = path_new + '/' + str(count)
                    else:
                        path_new =  path_new + '/' + i
                tmp = _[0] + _[1] + path_new
                for i in some_control_word:
                    if i in params:
                        try:
                            tmp += params[i][0]
                        except:
                            pass
                            #wrong_log(params[i][0])
                if tmp in self.detecion:
                    return 0
                else:
                    self.detecion.append(tmp)
                    self.req_scan.append(req)
                    return 1
        except Exception, e:
            wrong_log(traceback.format_exc()+url)




    def get_links_forms(self,html,url):
        reqs = []
        if isinstance(html, str):
            try:
                etreeHtml = etree.HTML(html)
                title = etreeHtml.xpath('//title/text()')
                if title:
                    if self.black_detect(title[0]):
                        return []
                links = etreeHtml.xpath('//a[@href]/@href')
                # get forms
                for i in links:
                    if i:
                        if 'javascript' in i or 'mailto' in i:
                            pass
                        else:
                            if '//' not in i:
                                if i[0] == '/':
                                    i = get_current_host(url) + i
                                else:
                                    i = get_current_path(url) + i
                            elif i[:2] == '//':
                                i = get_scheme(url) + i

                            if self.detect(['GET',i,'']):
                                #info_log(i)
                                reqs.append(['GET',i,''])
                forms = etreeHtml.xpath('//form')
                for i in forms:
                    try:
                        action = str(i.xpath('@action')[0])
                        if 'javascript' in i or 'mailto' in action:
                            continue
                        else:
                            if '//' not in action:
                                if action[0] == '/':
                                    action = get_current_host(url) + action
                                else:
                                    action = get_current_path(url) + action
                            elif i[:2] == '//':
                                action = get_scheme(url) + action

                            if self.detect(['post', i, '']):
                                # info_log(i)
                                reqs.append(['post', i, ''])
                        inputs = i.xpath('//input')
                        data = ''
                        for t in inputs:
                            name = ''
                            value = ''
                            try:
                                name = t.xpath('@name')[0]
                                value = t.xpath('@value')[0]
                            except:
                                pass

                                #wrong_log(str(t.xpath('@name')))
                                #wrong_log(str(t.xpath('@value')))

                            data = data + name + '=' + value + '&'
                        if self.detect(['post',action,data[:-1]]):
                            reqs.append(['post',action,data[:-1]])       # data[:-1] delet the last &
                    except Exception, e:
                        wrong_log(url+traceback.format_exc())

            except Exception, e:
                wrong_log(traceback.format_exc())
        else:
            pass
        return reqs



    def run(self):
        while self.reqque.qsize()>0:
            try:
                _ = self.reqque.get()
                html = self.get_html(_[0])
                reqs = self.get_links_forms(html,_[0][1])
                if _[1] < self.depth:
                    new_dep = _[1] + 1
                    for i in reqs:
                        self.reqque.put([i,new_dep])
            except Exception,e:
                wrong_log(traceback.format_exc())
        tmp_req = []
        for i in self.req_scan:
            tmp_req.append({'method':i[0],'url':i[1],'data':i[2],'status':0,'source':self.url})
        return tmp_req



