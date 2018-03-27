#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A tiny Batch weB vulnerability Scanner
# my[at]lijiejie.com    http://www.lijiejie.com


import urlparse
import httplib
import logging
import re
import threading
import Queue
from bs4 import BeautifulSoup
import time
import glob
import os
import socket
import urllib2
import urllib
import traceback


from webscaner.lib.common import get_time, parse_url, decode_response_text

def error_log(wrong_info):
    with open('error.log', 'a') as f:
        f.write(wrong_info)
        f.write('\n--------------------------------------------------------------\n')

class InfoDisScanner():
    def __init__(self, timeout=600,domain=''):
        self.START_TIME = time.time()
        self.TIME_OUT = timeout
        self.domain = domain
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                      '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1',
                        'Range': 'bytes=0-10240',
                        'Connection': 'Close'}
        if domain:
            self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                          '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1',
                            'Range': 'bytes=0-10240',
                            'Connection': 'Close',
                            'Host': domain}

        self.LINKS_LIMIT = 100      # max number of Folders to scan

        self.full_scan = True
        self._init_rules()

        self.url_queue = Queue.Queue()     # all urls to scan
        self.urls_processed = []           # urls already in queue
        self.urls_enqueued = []

        self.lock = threading.Lock()
        socket.setdefaulttimeout(20)


    def init_reset(self):
        self.START_TIME = time.time()
        self.url_queue.queue.clear()
        self.urls_processed = []           # urls already in queue
        self.urls_enqueued = []
        self.results = {}
        self.file = None


    def init_from_url(self, url):
        self.init_reset()
        self.url = url
        if not url.find('://') > 0: self.url = 'http://' + url
        self.schema, self.host, self.path = parse_url(url)
        self.init_final()




    def init_final(self):
        self.max_depth = self._cal_depth(self.path)[1] + 3     # max depth to scan
        if True:
            self._404_status = 404
            self.has_404 = True
        else:
            self.check_404()           # check existence of HTTP 404
            if self._404_status == -1:
                return
        if not self.has_404:
            #print '[%s] [Warning] %s has no HTTP 404.' % (get_time(), self.host)
            pass
        _path, _depth = self._cal_depth(self.path)
        self._enqueue('/')
        self._enqueue(_path)
        if True:
            self.crawl_index(_path)




    def _cal_depth(self, url):
        # calculate depth of a given URL, return tuple (url, depth)
        if url.find('#') >= 0: url = url[:url.find('#')]    # cut off fragment
        if url.find('?') >= 0: url = url[:url.find('?')]    # cut off query string
        if url.startswith('//'):
            return '', 10000    # //www.baidu.com/index.php, ignored
        if not urlparse.urlparse(url, 'http').scheme.startswith('http'):
            return '', 10000    # no HTTP protocol, ignored

        if url.startswith('http'):
            _ = urlparse.urlparse(url, 'http')
            if _.netloc == self.host:    # same hostname
                url = _.path
            else:
                return '', 10000         # not same hostname, ignored
        while url.find('//') >= 0:
            url = url.replace('//', '/')

        if not url:
            return '/', 1         # http://www.example.com

        if url[0] != '/': url = '/' + url
        url = url[: url.rfind('/')+1]
        depth = url.count('/')
        return url, depth


    def _init_rules(self):
        self.text_to_find = []
        self.regex_to_find = []
        self.text_to_exclude = []
        self.regex_to_exclude = []
        self.rules_dict = []

        p_tag = re.compile('{tag="([^"]+)"}')
        p_status = re.compile('{status=(\d{3})}')
        p_content_type = re.compile('{type="([^"]+)"}')
        p_content_type_no = re.compile('{type_no="([^"]+)"}')

        for rule_file in glob.glob('webscaner/rules/*.txt'):
            infile = open(rule_file, 'r')
            for url in infile.xreadlines():
                url = url.strip()
                if url.startswith('/'):
                    _ = p_tag.search(url); tag = _.group(1).replace("{quote}", '"') if _ else ''
                    _ = p_status.search(url); status = int(_.group(1)) if _ else 0
                    _ = p_content_type.search(url); content_type = _.group(1) if _ else ''
                    _ = p_content_type_no.search(url); content_type_no = _.group(1) if _ else ''
                    url = urllib.unquote(url.split()[0])
                    rule = (url, tag, status, content_type, content_type_no)
                    if not rule in self.rules_dict:
                        self.rules_dict.append(rule)
            infile.close()

        _re = re.compile('{text="(.*)"}')
        _re2 = re.compile('{regex_text="(.*)"}')

        _file_path = 'webscaner/rules/white.list'
        if not os.path.exists(_file_path):
            return
        for line in open(_file_path):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _m = _re.search(line)
            if _m:
                self.text_to_find.append( _m.group(1).decode('utf-8', 'ignore') )
            else:
                _m = _re2.search(line)
                if _m:
                    self.regex_to_find.append( re.compile(_m.group(1).decode('utf-8','ignore')) )

        _file_path = 'webscaner/rules/black.list'
        if not os.path.exists(_file_path):
            return
        for line in open(_file_path):
            line = line.strip()
            if not line or line.startswith('#'): continue
            _m = _re.search(line)
            if _m:
                self.text_to_exclude.append( _m.group(1).decode('utf-8', 'ignore') )
            else:
                _m = _re2.search(line)
                if _m:
                    self.regex_to_exclude.append( re.compile(_m.group(1).decode('utf-8', 'ignore')) )


    def _http_request(self, url, timeout=10):
        try:
            if not url: url = '/'
            conn_fuc = httplib.HTTPSConnection if self.schema == 'https' else httplib.HTTPConnection
            conn = conn_fuc(self.host, timeout=timeout)

            conn.request(method='GET', url=url,headers=self.headers)
            resp = conn.getresponse()
            resp_headers = dict(resp.getheaders())
            status = resp.status
            if resp_headers.get('content-type', '').find('text') >= 0 or \
                            resp_headers.get('content-type', '').find('html') >= 0 or \
                            int(resp_headers.get('content-length', '0')) <= 307200:    # 1024 * 300
                html_doc = decode_response_text(resp.read())
            else:
                html_doc = ''
            conn.close()
            return status, resp_headers, html_doc
        except Exception, e:
            return -1, {}, ''
        finally:
            conn.close()


    def get_status(self, url):
        return self._http_request(url)[0]



    def check_404(self):
        try:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                default_port = 443 if self.schema.lower() == 'https' else 80
                host, port = self.host.split(':') if self.host.find(':') > 0 else (self.host, default_port)
                if s.connect_ex((host, int(port))) == 0:
                    s.close()
                    self._404_status, headers, html_doc = \
                        self._http_request('/bbscan_wants__your_response.php')
                else:
                    self._404_status, headers, html_doc = -1, {}, ''
            except:
                self._404_status, headers, html_doc = -1, {}, ''
            finally:
                s.close()

            if self._404_status == -1:
                #print '[%s] [ERROR] Fail to connect to %s' % (get_time(), self.host)
                pass
            self.has_404 = (self._404_status == 404)
            if not self.has_404:
                self.len_404_doc = len(html_doc)
            return self.has_404
        except Exception, e:
            error_log("[Check_404] Exception %s" % e)


    def _enqueue(self, url):
        url = str(url)
        _url = re.sub('\d+', '{num}', url)
        if _url in self.urls_processed:
            return False
        elif len(self.urls_processed) >= self.LINKS_LIMIT:
            return False
        else:
            self.urls_processed.append(_url)

        for _ in self.rules_dict:
            try:
                full_url = url.rstrip('/') + _[0]
            except:
                continue
            full_url = full_url.decode('utf-8', 'ignore')
            if full_url in self.urls_enqueued:
                continue
            url_description = {'prefix': url.rstrip('/'), 'full_url': full_url}
            item = (url_description, _[1], _[2], _[3], _[4])
            self.url_queue.put(item)
            self.urls_enqueued.append(full_url)

        if self.full_scan and url.count('/') > 3:
            self._enqueue('/'.join(url.split('/')[:-2]) + '/')

        return True


    def crawl_index(self, path):
        try:
            status, headers, html_doc = self._http_request(path)
            if status != 200:
                try:
                    html_doc = decode_response_text(urllib2.urlopen(self.url).read())
                except Exception,e :
                    pass
            soup = BeautifulSoup(html_doc, "html.parser")
            links = soup.find_all('a')
            for l in links:
                url = l.get('href', '').strip()
                url, depth = self._cal_depth(url)
                if depth <= self.max_depth:
                    self._enqueue(url)
        except Exception, e:
            error_log('[crawl_index Exception] %s' % e)
            #traceback.print_exc()


    def load_all_urls_from_file(self):
        try:
            with open(self.file) as inFile:
                lines = inFile.readlines()
            for line in lines:
                _ = line.split()
                if len(_) == 3 and (_[2].find('^^^200') > 0 or _[2].find('^^^403') > 0):
                    url = urlparse.unquote(_[1])
                    url, depth = self._cal_depth(url)
                    if len(url) >= 70: continue
                    #print url
                    self._enqueue(url)
        except Exception, e:
            error_log('[load_all_urls_from_file Exception] %s' % e)



    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) > 0:
                return True
        for _regex in self.regex_to_find:
            if _regex.search(html_doc) > 0:
                return  True
        return False


    def exclude_text(self, html_doc):
        for _text in self.text_to_exclude:
            if html_doc.find(_text) > 0:
                return False
        for _regex in self.regex_to_exclude:
            if _regex.search(html_doc) > 0:
                return False
        return True


    def get_title(sefl, html_doc):
        try:
            soup = BeautifulSoup(html_doc,'lxml')
            return soup.title.string.encode('utf-8').strip()
        except:
            return html_doc[:20]

    def _scan_worker(self):
        while self.url_queue.qsize() > 0:
            if time.time() - self.START_TIME > self.TIME_OUT:
                #print '[%s] [ERROR] Timed out task: %s' % (get_time(), self.host)
                return
            try:
                item = self.url_queue.get(timeout=0.1)
            except:
                return
            try:
                url_description, tag, code, content_type, content_type_no = item
                url = url_description['full_url']
                #print type(url),url, type(self.host),self.host
                url = url.replace(u'{sub}', self.host.split('.')[0])
                prefix = url_description['prefix']
                if url.find('{hostname_or_folder}') >= 0:
                    _url = url[: url.find('{hostname_or_folder}')]
                    if _url.count('/') == 1:
                        url = url.replace('{hostname_or_folder}', self.host)
                    elif _url.count('/') > 1:
                        url = url.replace('{hostname_or_folder}', _url.split('/')[-2])
                url = url.replace('{hostname}', self.host)
                if url.find('{parent}') > 0:
                    if url.count('/') >= 2:
                        ret = url.split('/')
                        ret[-2] = ret[-1].replace('{parent}', ret[-2])
                        url =  '/' + '/'.join(ret[:-1])
                    else:
                        continue
            except Exception, e:
                #error_log('[_scan_worker Exception 1] %s' % e)
                error_log(url)
                error_log(traceback.format_exc())
                #traceback.print_exc()
                continue
            if not item or not url:
                break

            #print '[%s]' % url.strip()
            try:
                status, headers, html_doc = self._http_request(url)

                if headers.get('content-type', '').find('image/') >= 0:    # exclude image type
                    continue

                if html_doc.strip() == '' or len(html_doc) < 10:    # data too short
                    continue

                if not self.exclude_text(html_doc):    # exclude text found
                    continue

                valid_item = False
                if status == 200 and  self.find_text(html_doc):
                    valid_item = True
                else:
                    if status in [400, 404, 503, 502, 301, 302]:
                        continue
                    if  headers.get('content-type', '').find('application/json') >= 0 and \
                            not url.endswith('.json'):    # no json
                        continue

                    if tag:
                        if html_doc.find(tag) >= 0:
                            valid_item = True
                        else:
                            continue    # tag mismatch

                    if content_type and headers.get('content-type', '').find(content_type) < 0 or \
                        content_type_no and headers.get('content-type', '').find(content_type_no) >=0:
                        continue    # type mismatch

                    if self.has_404 or status!=self._404_status:
                        if code and status != code and status != 206:    # code mismatch
                            continue
                        elif code!= 403 and status == 403:
                            continue
                        else:
                            valid_item = True

                    if (not self.has_404) and status in (200, 206) and item[0]['full_url'] != '/' and (not tag):
                        _len = len(html_doc)
                        _min = min(_len, self.len_404_doc)
                        if _min == 0:
                            _min = 10
                        if abs(_len - self.len_404_doc) / _min  > 0.3:
                            valid_item = True

                    if status == 206:
                        if headers.get('content-type', '').find('text') < 0 and headers.get('content-type', '').find('html') < 0:
                            valid_item = True
                        else:
                            continue

                if valid_item:
                    self.lock.acquire()
                    # print '[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url)
                    if not prefix in self.results:
                        self.results[prefix]= []
                    _ = {'status': status, 'url': '%s://%s%s' % (self.schema, self.host, url),'domain':self.domain,'title':self.get_title(html_doc),'src':html_doc}
                    if _ not in self.results[prefix]:
                        self.results[prefix].append(_)
                    self.lock.release()

                if len(self.results) >= 15:
                    #print 'More than 15 vulnerabilities found for [%s], seems to be false positives, exit.' % prefix
                    return
            except Exception, e:
                error_log('[InfoDisScanner._scan_worker][2][%s] Exception %s' % (url, e))
                #traceback.print_exc()


    def scan(self, threads=10):
        try:
            if self._404_status == -1:
                return self.host, {}
            threads_list = []
            for i in range(threads):
                t = threading.Thread(target=self._scan_worker)
                threads_list.append(t)
                t.start()
            for t in threads_list:
                t.join()
            for key in self.results.keys():
                if len(self.results[key]) > 15:    # more than 20 URLs found under folder: false positives
                    del self.results[key]
            return self.host, self.results
        except Exception, e:
            #traceback.print_exc()
            error_log('[InfoDisScanner.scan exception] %s' % e)



def batch_scan(url,domain='', threads_num=5, timeout=5):
    s = InfoDisScanner(timeout * 60, domain=domain)
    # lock.acquire()

    #print '[%s] Scan %s' % (get_time(), url )
    # lock.release()
    s.init_from_url(url)
    host, results = s.scan(threads=threads_num)
    q_results = []
    if results:
        for key in results.keys():
            q_results += results[key]
    return q_results
#_ = {'status': status, 'url': '%s://%s%s' % (self.schema, self.host, url),'domain':self.domain,'title':self.get_title(html_doc),'src':html_doc}