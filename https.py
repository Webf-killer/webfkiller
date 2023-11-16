#멀티스레딩 HTTPS 프록시 서버 (설명추가)

import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser

def with_color(c, s):
#콘솔 출력에 색상 추가
    return "\x1b[%dm%s\x1b[0m" % (c, s)

def join_with_script_dir(path):
#현재 스크립트의 위치를 기반으로 파일 경로 합치는 함수
    return os.path.join(os.path.dirname(os.path.abspath(file)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
#ThreadingHTTPServer클래스를 이용해 프록시 서버를 실행 - 1
    address_family = socket.AF_INET6
    daemon_threads = True


def handle_error(self, request, client_address):
#오류 처리 함수
#소켓 또는 SSL 관련 오류 무시, 그외의 오류 기본 핸들러로 전달
    # surpress socket/ssl related errors
    cls, e = sys.exc_info()[:2]
    if cls is socket.error or cls is ssl.SSLError:
        pass
    else:
        return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
#HTTP요청이 들어오면 do_GET, do_POST 등의 메서드로 HTTP 요청을 처리
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

def __init__(self, *args, **kwargs):
    self.tls = threading.local()
    self.tls.conns = {}

    BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

def log_error(self, format, *args):
    # surpress "Request timed out: timeout('timed out',)"
    if isinstance(args[0], socket.timeout):
        return

    self.log_message(format, *args)

def do_CONNECT(self):
# CONNECT 연결 처리- HTTPS 통신 처리
#SSL 연결을 생성하려고 할 때 호출되는 메서드
#CA 인증서와 개인 키가 존재하면, 연결을 가로채고 (intercept)
#클라이언트에게 가짜 인증서를 제공
#그렇지 않으면, 단순히 연결을 중계(relay)
    if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
        self.connect_intercept()
    else:
        self.connect_relay()


def connect_intercept(self):
#SSL 연결을 가로채는 메서드
#동적으로 인증서를 생성
#클라이언트 연결을 SSL로 감싸기
    hostname = self.path.split(':')[0]
    certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

    with self.lock:
        if not os.path.isfile(certpath):
            epoch = "%d" % (time.time() * 1000)
            p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
            p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
            p2.communicate()

    self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
    self.end_headers()

    self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
    self.rfile = self.connection.makefile("rb", self.rbufsize)
    self.wfile = self.connection.makefile("wb", self.wbufsize)

    conntype = self.headers.get('Proxy-Connection', '')
    if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
        self.close_connection = 0
    else:
        self.close_connection = 1

def connect_relay(self):
#SSL 연결을 중계하는 메서드
#클라이언트와 대상 서버 간의 연결
    address = self.path.split(':', 1)
    address[1] = int(address[1]) or 443
    try:
        s = socket.create_connection(address, timeout=self.timeout)
    except Exception as e:
        self.send_error(502)
        return
    self.send_response(200, 'Connection Established')
    self.end_headers()

    conns = [self.connection, s]
    self.close_connection = 0
    while not self.close_connection:
        rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
        if xlist or not rlist:
            break
        for r in rlist:
            other = conns[1] if r is conns[0] else conns[0]
            data = r.recv(8192)
            if not data:
                self.close_connection = 1
                break
            other.sendall(data)

def do_GET(self):
#HTTP GET 요청을 처리하는 메서드
#요청 경로에 CA 인증서를 보내주고 그외의 경우 요청처리 후 응답 봔환
#요청 분석
#(필요한 경우 request_handler 메서드: 요청 본문을 수정후 요청을 원래의 대상 서버로 전달)
#->응답을 받은 후, (또! 필요한 경우 response_handler 메서드: 응답 본문을 수정)
#(응답을 클라이언트로 전달)
    if self.path == 'http://proxy2.test/':
        self.send_cacert()
        return

    req = self
    content_length = int(req.headers.get('Content-Length', 0))
    req_body = self.rfile.read(content_length) if content_length else None

    if req.path[0] == '/':
        if isinstance(self.connection, ssl.SSLSocket):
            req.path = "https://%s%s" % (req.headers['Host'], req.path)
        else:
            req.path = "http://%s%s" % (req.headers['Host'], req.path)

    req_body_modified = self.request_handler(req, req_body)
    if req_body_modified is False:
        self.send_error(403)
        return
    elif req_body_modified is not None:
        req_body = req_body_modified
        req.headers['Content-length'] = str(len(req_body))

    u = urlparse.urlsplit(req.path)
    scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
    assert scheme in ('http', 'https')
    if netloc:
        req.headers['Host'] = netloc
    setattr(req, 'headers', self.filter_headers(req.headers))
#filter_headers 메서드: 헤더 필터링

    try:
        origin = (scheme, netloc)
        if not origin in self.tls.conns:
            if scheme == 'https':
                self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
            else:
                self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
        conn = self.tls.conns[origin]
        conn.request(self.command, path, req_body, dict(req.headers))
        res = conn.getresponse()

        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        setattr(res, 'headers', res.msg)
        setattr(res, 'response_version', version_table[res.version])

        # support streaming
        if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
            self.response_handler(req, req_body, res, '')
            setattr(res, 'headers', self.filter_headers(res.headers))
            self.relay_streaming(res)
            with self.lock:
                self.save_handler(req, req_body, res, '')
            return

        res_body = res.read()
    except Exception as e:
        if origin in self.tls.conns:
            del self.tls.conns[origin]
        self.send_error(502)
        return

    content_encoding = res.headers.get('Content-Encoding', 'identity')
    res_body_plain = self.decode_content_body(res_body, content_encoding)

    res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
    if res_body_modified is False:
        self.send_error(403)
        return
    elif res_body_modified is not None:
        res_body_plain = res_body_modified
        res_body = self.encode_content_body(res_body_plain, content_encoding)
        res.headers['Content-Length'] = str(len(res_body))

    setattr(res, 'headers', self.filter_headers(res.headers))

    self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
    for line in res.headers.headers:
        self.wfile.write(line)
    self.end_headers()
    self.wfile.write(res_body)
    self.wfile.flush()

    with self.lock:
        self.save_handler(req, req_body, res, res_body_plain)

def relay_streaming(self, res):
#스트리밍 응답을 클라이언트로 중계하는 메서드
    self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
    for line in res.headers.headers:
        self.wfile.write(line)
    self.end_headers()
    try:
        while True:
            chunk = res.read(8192)
            if not chunk:
                break
            self.wfile.write(chunk)
        self.wfile.flush()
    except socket.error:
        # connection closed by client
        pass

do_HEAD = do_GET
do_POST = do_GET
do_PUT = do_GET
do_DELETE = do_GET
do_OPTIONS = do_GET

def filter_headers(self, headers):
#요청 또는 응답 헤더를 필터링하는 메서드
#헤더 중 hop-by-hop 헤더와 지원되지 않는 인코딩을 제거
    # http://tools.ietf.org/html/rfc2616#section-13.5.1
    hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
    for k in hop_by_hop:
        del headers[k]

    # accept only supported encodings
    if 'Accept-Encoding' in headers:
        ae = headers['Accept-Encoding']
        filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
        headers['Accept-Encoding'] = ', '.join(filtered_encodings)

    return headers

def encode_content_body(self, text, encoding):
#HTTP 본문 인코딩
    if encoding == 'identity':
        data = text
    elif encoding in ('gzip', 'x-gzip'):
        io = StringIO()
        with gzip.GzipFile(fileobj=io, mode='wb') as f:
            f.write(text)
        data = io.getvalue()
    elif encoding == 'deflate':
        data = zlib.compress(text)
    else:
        raise Exception("Unknown Content-Encoding: %s" % encoding)
    return data

def decode_content_body(self, data, encoding):
#HTTP 본문을 디코딩
    if encoding == 'identity':
        text = data
    elif encoding in ('gzip', 'x-gzip'):
        io = StringIO(data)
        with gzip.GzipFile(fileobj=io) as f:
            text = f.read()
    elif encoding == 'deflate':
        try:
            text = zlib.decompress(data)
        except zlib.error:
            text = zlib.decompress(data, -zlib.MAX_WBITS)
    else:
        raise Exception("Unknown Content-Encoding: %s" % encoding)
    return text

def send_cacert(self):
#클라이언트에게 CA 인증서를 전송하는 메서드
    with open(self.cacert, 'rb') as f:
        data = f.read()

    self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
    self.send_header('Content-Type', 'application/x-x509-ca-cert')
    self.send_header('Content-Length', len(data))
    self.send_header('Connection', 'close')
    self.end_headers()
    self.wfile.write(data)

def print_info(self, req, req_body, res, res_body):
#요청과 응답 정보를 콘솔에 출력하는 메서드
    def parse_qsl(s):
        return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
    if u.query:
        query_text = parse_qsl(u.query)
        print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

    cookie = req.headers.get('Cookie', '')
    if cookie:
        cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
        print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

    auth = req.headers.get('Authorization', '')
    if auth.lower().startswith('basic'):
        token = auth.split()[1].decode('base64')
        print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

    if req_body is not None:
        req_body_text = None
        content_type = req.headers.get('Content-Type', '')

        if content_type.startswith('application/x-www-form-urlencoded'):
            req_body_text = parse_qsl(req_body)
        elif content_type.startswith('application/json'):
            try:
                json_obj = json.loads(req_body)
                json_str = json.dumps(json_obj, indent=2)
                if json_str.count('\n') < 50:
                    req_body_text = json_str
                else:
                    lines = json_str.splitlines()
                    req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
            except ValueError:
                req_body_text = req_body
        elif len(req_body) < 1024:
            req_body_text = req_body

        if req_body_text:
            print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

    print with_color(36, res_header_text)

    cookies = res.headers.getheaders('Set-Cookie')
    if cookies:
        cookies = '\n'.join(cookies)
        print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

    if res_body is not None:
        res_body_text = None
        content_type = res.headers.get('Content-Type', '')

        if content_type.startswith('application/json'):
            try:
                json_obj = json.loads(res_body)
                json_str = json.dumps(json_obj, indent=2)
                if json_str.count('\n') < 50:
                    res_body_text = json_str
                else:
                    lines = json_str.splitlines()
                    res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
            except ValueError:
                res_body_text = res_body
        elif content_type.startswith('text/html'):
            m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
            if m:
                h = HTMLParser()
                print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
        elif content_type.startswith('text/') and len(res_body) < 1024:
            res_body_text = res_body

        if res_body_text:
            print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

def request_handler(self, req, req_body):
#요청 처리 메서드
    pass

def response_handler(self, req, req_body, res, res_body):
#응답 처리 메서드
    pass

def save_handler(self, req, req_body, res, res_body):
#요청과 응답을 저장하는 메서드 -> print_info를 호출-> 정보 출력
    self.print_info(req, req_body, res, res_body)
def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
#프록시 서버 실행하는 함수
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('::1', port)

HandlerClass.protocol_version = protocol
httpd = ServerClass(server_address, HandlerClass)

sa = httpd.socket.getsockname()

print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."

httpd.serve_forever()
if name == 'main':
    test()