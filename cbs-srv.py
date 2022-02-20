#!/usr/bin/env python3

import select
import socket
from OpenSSL import SSL
from urllib.parse import urlparse, unquote

import re
from os import path, environ
import subprocess
import mimetypes

import logging
import yaml

logging.basicConfig(level=logging.INFO)
mimetypes.add_type('text/gemini', '.gmi')
mimetypes.add_type('text/gemini', '.gemini')

# ------------------------------------------------------------------------------


class CBSNotFound(Exception): pass
class CBSTraversal(Exception): pass
class CBSExtraPath(Exception): pass


def recv_req(conn: SSL.Connection, timeout=.1):
    data = b''
    while True:
        ready = select.select([conn], [], [], timeout)
        if ready[0]:
            data += conn.recv(4096)
            if b'\r\n' in data:
                lines = data.splitlines()
                if len(lines) > 1:
                    logging.warning('Discarding data after URL line of request: {}'.format(data))
                try:
                    req = lines[0].decode('ascii')
                except Exception:
                    logging.error('URL is not ascii: {}'.format(data))
                    return None
                return req
        else:
            logging.error('Timeout while waiting for URL')
            return None


def translate_path(url_path: str, base_path: str, check_existence=True, allow_extra=True):
    # Build path one element at a time until we find a file
    trans_path = base_path
    path_len = 0
    for part in url_path.split('/'):
        path_len += len(part) + 1
        # RFC 3986 says path components may have parameters, so look for any
        # reserved delimiter characters and discard everything after one.
        # Although the Gemini spec says not all of the components of generic URI
        # syntax are supported, and disallowing path parameters seems in the
        # spirit of the protocol, path parameters are not specifically mentioned
        # so I try to do what feels safest and expect that they may show up.
        part = unquote(re.split('[!$&\'()*+,;=]', part)[0])
        trans_path = path.join(trans_path, part)
        if check_existence and path.isfile(trans_path):
            break
    else:
        if check_existence:
            if path.isdir(trans_path):
                trans_path = path.join(trans_path, 'index.gmi')
                if not path.isfile(trans_path):
                    raise CBSNotFound(trans_path)
            else:
                raise CBSNotFound(trans_path)

    # Make sure the path didn't escape the base path.
    trans_path = path.realpath(trans_path)
    if path.commonpath([base_path, trans_path]) != base_path:
        raise CBSTraversal(trans_path)

    # Grab all the leftovers verbatim for CGI scripts.
    extra_path = url_path[max(path_len-1, 0):]
    if extra_path and not allow_extra:
        raise CBSExtraPath(extra_path)

    return trans_path, extra_path


# ------------------------------------------------------------------------------


def serve_req(conn: SSL.Connection, addr, url: str, conf: dict):
    # Attempt to parse the url and do basic validation
    logging.info('Serving URL "{}"'.format(url))
    try:
        url_parsed = urlparse(url)
    except ValueError:
        logging.error('Could not parse URL: "{}"'.format(url))
        return serve_badreq(conn, "Could not parse URL")
    if url_parsed.scheme != 'gemini':
        logging.error('Bad scheme: "{}"'.format(url_parsed.scheme))
        return serve_badreq(conn, "Non-gemini scheme")
    if url_parsed.netloc == '':
        logging.error('Netloc unspecified: "{}"'.format(url))
        return serve_badreq(conn, "Netloc unspecified")

    # Parse the path information into a system path
    try:
        req_path, extra_path = translate_path(url_parsed.path, conf['servedir'])
    except CBSNotFound:
        logging.error('URL not found: "{}"'.format(url))
        return serve_notfound(conn)
    except CBSTraversal:
        logging.error('URL contains bad traversal: "{}"'.format(url))
        return serve_badreq(conn, "Naughty directory traversal")

    # If the path is in the cgi directory then do some special CGI stuff.
    if conf['cgidir'] is not None and path.commonpath([conf['cgidir'], req_path]) == conf['cgidir']:
        return serve_cgi(conn, addr, req_path, extra_path, url_parsed, conf)

    # If the request is for a static file, there should be no extra path info
    if extra_path:
        logging.warning('Extra path info after file: "{}"'.format(url_parsed.path))
        return serve_notfound(conn)

    # Otherwise, serve up a static file
    return serve_file(conn, req_path)


def serve_badreq(conn: SSL.Connection, msg=''):
    conn.send('59 {}\r\n'.format(msg).encode('utf-8'))


def serve_notfound(conn: SSL.Connection):
    conn.send('51 Page not found\r\n'.encode('utf-8'))


def serve_cgierror(conn: SSL.Connection, msg=''):
    conn.send('42 {}\r\n'.format(msg).encode('utf-8'))


def serve_cgi(conn: SSL.Connection, addr, req_path, extra_path, url, conf: dict):
    cert = conn.get_peer_certificate()

    try:
        extra_trans, _ = translate_path(extra_path, conf['servedir'], check_existence=False, allow_extra=False)
    except CBSTraversal:
        logging.error('Extra path contains bad traversal: "{}"'.format(extra_path))
        return serve_badreq(conn, "Naughty directory traversal")

    env = environ.copy()

    # RFC 3875
    env['AUTH_TYPE'] = 'CERTIFICATE' if cert is not None else ''
    env['CONTENT_LENGTH'] = ''     # Requests don't contain content, leave blank
    env['CONTENT_TYPE'] = ''       # Requests don't contain content, leave blank
    env['GATEWAY_INTERFACE'] = 'CGI/1.1'
    env['PATH_INFO'] = unquote(extra_path)  # RFC 3875 specifies no URL encoding
    env['PATH_TRANSLATED'] = extra_trans
    env['QUERY_STRING'] = url.query
    env['REMOTE_ADDR'] = str(addr)
    env['REMOTE_HOST'] = ''        # TODO: pull domain name from cert?
    env['REMOTE_IDENT'] = ''       # There is no ident info in gemini, leave blank
    env['REMOTE_USER'] = ''        # TODO: populate with TLS session ID?  Maybe name from cert?
    env['REQUEST_METHOD'] = 'GET'  # This is the closest reasonable value
    env['SCRIPT_NAME'] = req_path
    env['SERVER_NAME'] = url.hostname
    env['SERVER_PORT'] = str(conf['port'])
    env['SERVER_PROTOCOL'] = 'GEMINI/0.16.1'
    env['SERVER_SOFTWARE'] = 'CORNED_BEEF_SANDWICH/0.0.0'

    env['TLS_CIPHER'] = conn.get_cipher_name()
    env['TLS_VERSION'] = conn.get_cipher_version()
    env['TLS_CLIENT_HASH'] = 'SHA256:'+''  # SHA-256 hash of raw cert bytes
    env['TLS_CLIENT_ISSUER'] = ''
    env['TLS_CLIENT_ISSUER_DN'] = ''
    env['TLS_CLIENT_SUBJECT'] = ''
    env['TLS_CLIENT_SUBJECT_DN'] = ''
    env['TLS_CLIENT_PUBKEY'] = ''
    env['TLS_CLIENT_SERIAL_NUMBER'] = ''

    env['GEMINI_URL'] = ''

    try:
        proc = subprocess.run(req_path, env=env, timeout=10, capture_output=True, check=True)
    except subprocess.TimeoutExpired:
        logging.error('CGI script timeout: "{}"'.format(req_path))
        return serve_cgierror(conn, "CGI script timeout")
    except subprocess.CalledProcessError as x:
        logging.error('CGI script returned error: "{}" -> {}'.format(req_path, x.returncode))
        return serve_cgierror(conn, "CGI script returned error")
    except PermissionError:
        logging.error('CGI script permission error: "{}"'.format(req_path))
        return serve_cgierror(conn, "CGI not executable")

    conn.send(proc.stdout)


def serve_file(conn: SSL.Connection, filedir):
    mime_type, encoding = mimetypes.guess_type(filedir)
    with open(filedir, 'rb') as f:
        conn.send('20 {}\r\n'.format(mime_type or 'application/octet-stream').encode('utf-8'))
        conn.send(f.read())


# ------------------------------------------------------------------------------


def accept_client_cert(conn, cert, err_num, err_depth, ret_code):
    return True


def main():
    # Load the config, set reasonable defaults, and preprocess some directories.
    conf = yaml.safe_load(open('./cbs.conf'))
    if 'addr' not in conf: conf['addr'] = '0.0.0.0'
    if 'port' not in conf: conf['port'] = 1965
    conf['servedir'] = path.abspath(conf['servedir'])
    if 'cgidir' in conf:
        conf['cgidir'] = path.join(conf['servedir'], conf['cgidir'])
    else:
        conf['cgidir'] = None

    # Set up the TLS server that blindly accepts all client certs.
    ctxt = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctxt.set_verify(SSL.VERIFY_PEER, accept_client_cert)
    ctxt.use_certificate_file(conf['cert'])
    ctxt.use_privatekey_file(conf['pkey'])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((conf['addr'], conf['port']))
        sock.listen()
        ssock = SSL.Connection(ctxt, sock)
        ssock.set_accept_state()
        while True:
            conn, addr = ssock.accept()
            conn.do_handshake()
            logging.info('Connection from {}'.format(addr))
            req = recv_req(conn)
            if req is not None:
                serve_req(conn, addr, req, conf)
            else:
                serve_badreq(conn, "Received invalid request")
            conn.shutdown()
            conn.sock_shutdown(socket.SHUT_RDWR)


if __name__ == '__main__':
    main()
