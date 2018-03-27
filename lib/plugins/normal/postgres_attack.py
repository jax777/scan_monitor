# coding:utf-8
import hashlib
import socket


plugin_info = {
    "name": "PostgresSQL弱口令",
    "info": "导致敏感信息泄露，严重可导致服务器被入侵。",
    "level": "高危",
    "type": "弱口令",
    "url": "",
    "vulinfo": "",
}

def get_plugin_info():
    return plugin_info

def make_response(username, password, salt):
    pu = hashlib.md5(password + username).hexdigest()
    buf = hashlib.md5(pu + salt).hexdigest()
    return 'md5' + buf


def auth(host, port, username, password, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        packet_length = len(username) + 7 + len(
            "\x03user  database postgres application_name psql client_encoding UTF8  ")
        p = "%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c" % (
        0, 0, 0, packet_length, 0, 0, 0, 0, username, 0, 0, 0, 0, 0, 0, 0, 0)
        sock.send(p)
        packet = sock.recv(1024)
        if packet[0] == 'R':
            authentication_type = str([packet[8]])
            c = int(authentication_type[4:6], 16)
            if c == 5: salt = packet[9:]
        else:
            return 3
        lmd5 = make_response(username, password, salt)
        packet_length1 = len(lmd5) + 5 + len('p')
        pp = 'p%c%c%c%c%s%c' % (0, 0, 0, packet_length1 - 1, lmd5, 0)
        sock.send(pp)
        packet1 = sock.recv(1024)
        if packet1[0] == "R":
            return True
    except Exception, e:
        if "Errno 10061" in str(e) or "timed out" in str(e): return 3




def check(ip, portinfo, timeout):
    if portinfo['port']==5432 or  'postgre' in portinfo['type']:
        for _ in open("dict/postgre.dic"):
            tmp = _.strip()
            dic = tmp.split()
            try:
                result = auth(ip, portinfo['port'], dic[0], dic[1], timeout)
                if result == True:
                    plugin_info['vulinfo'] = 'PostgresSQL ' + dic[0] + '  :  ' + dic[1]
                    return 1
            except:
                pass
        return 2
    return 0