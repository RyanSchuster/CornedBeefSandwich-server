#!/usr/bin/env python3

import select
import socket
from OpenSSL import SSL
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
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
# Helpers


def accept_client_cert(conn, cert, err_num, err_depth, ret_code):
    return True


class CBSException(Exception):
    def __init__(self, code, meta, logdata=None):
        self.code = code
        self.meta = meta
        self.logdata = logdata


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
                except UnicodeDecodeError:
                    raise CBSException(59, 'Non-ascii URL', data)
                return req
        else:
            raise CBSException(59, 'Timeout while waiting for URL')


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
                    raise CBSException(51, 'URL not found', trans_path)
            else:
                raise CBSException(51, 'URL not found', trans_path)

    # Make sure the path didn't escape the base path.
    trans_path = path.realpath(trans_path)
    if path.commonpath([base_path, trans_path]) != base_path:
        raise CBSException(59, 'Naughty directory traversal', trans_path)

    # Grab all the leftovers verbatim for CGI scripts.
    extra_path = url_path[max(path_len-1, 0):]
    if extra_path and not allow_extra:
        raise CBSException(59, 'Extra unexpected path information', extra_path)

    return trans_path, extra_path


# ------------------------------------------------------------------------------
# Serving


def serve_req(conn: SSL.Connection, addr, url: str, conf: dict):
    # Attempt to parse the url and do basic validation
    logging.info('Serving URL "{}"'.format(url))
    try:
        url_parsed = urlparse(url)
    except ValueError:
        raise CBSException(59, 'Could not parse URL', url)
    if url_parsed.scheme != 'gemini':
        raise CBSException(59, 'Non-gemini scheme', url_parsed.scheme)
    if url_parsed.netloc == '':
        raise CBSException(59, 'Netloc unspecified', url)

    # Parse the path information into a system path
    req_path, extra_path = translate_path(url_parsed.path, conf['servedir'])

    # If the path is in the cgi directory then do some special CGI stuff.
    if conf['cgidir'] is not None and path.commonpath([conf['cgidir'], req_path]) == conf['cgidir']:
        return serve_cgi(conn, addr, req_path, extra_path, url_parsed, conf)

    # If the request is for a static file, there should be no extra path info
    if extra_path:
        raise CBSException(51, 'URL not found', 'extra path info: {}'.format(url_parsed.path))

    # Otherwise, serve up a static file
    return serve_file(conn, req_path)


def serve_cgi(conn: SSL.Connection, addr, req_path, extra_path, url, conf: dict):
    cert = conn.get_peer_certificate()
    extra_trans, _ = translate_path(extra_path, conf['servedir'], check_existence=False, allow_extra=False)

    # TODO: properly escape characters in DNs, see RFC 2253
    issuer_dn = b','.join([n+b'='+v for n, v in cert.get_issuer().get_components()]).decode('utf-8')
    subject_dn = b','.join([n+b'='+v for n, v in cert.get_subject().get_components()]).decode('utf-8')
    pubkey = cert.get_pubkey().to_cryptography_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
    # TODO: validate cert valid dates
    # TODO: does the handshake still check the CertificateVerify message if the set_verify callback returns true?

    # RFC 3875
    env = environ.copy()
    env['AUTH_TYPE'] = 'CERTIFICATE' if cert is not None else ''
    env['CONTENT_LENGTH'] = ''  # Requests don't contain content, leave blank
    env['CONTENT_TYPE'] = ''  # Requests don't contain content, leave blank
    env['GATEWAY_INTERFACE'] = 'CGI/1.1'
    env['PATH_INFO'] = unquote(extra_path)  # RFC 3875 specifies no URL encoding or parameters
    env['PATH_TRANSLATED'] = extra_trans
    env['QUERY_STRING'] = url.query
    env['REMOTE_ADDR'] = addr[0]
    env['REMOTE_HOST'] = ''  # TODO: pull domain name from cert?
    env['REMOTE_IDENT'] = ''  # There is no ident info in gemini, leave blank
    env['REMOTE_USER'] = ''  # TODO: populate with TLS session ID?  Maybe name from cert?
    env['REQUEST_METHOD'] = 'GET'  # This is the closest reasonable value
    env['SCRIPT_NAME'] = req_path
    env['SERVER_NAME'] = url.hostname
    env['SERVER_PORT'] = str(conf['port'])
    env['SERVER_PROTOCOL'] = 'GEMINI/0.16.1'
    env['SERVER_SOFTWARE'] = 'CORNED_BEEF_SANDWICH/0.0.0'

    env['TLS_CIPHER'] = conn.get_cipher_name()
    env['TLS_VERSION'] = conn.get_cipher_version()
    env['TLS_CLIENT_HASH'] = cert.digest('sha256')  # TODO: compare format to other servers
    env['TLS_CLIENT_ISSUER'] = issuer_dn
    env['TLS_CLIENT_ISSUER_DN'] = issuer_dn
    env['TLS_CLIENT_ISSUER_CN'] = cert.get_issuer().CN
    env['TLS_CLIENT_SUBJECT'] = subject_dn
    env['TLS_CLIENT_SUBJECT_DN'] = subject_dn
    env['TLS_CLIENT_SUBJECT_CN'] = cert.get_subject().CN
    env['TLS_CLIENT_PUBKEY'] = pubkey  # TODO: does this or something similar already exist in other servers?
    env['TLS_CLIENT_SERIAL_NUMBER'] = str(cert.get_serial_number())  # TODO: compare format to other servers

    env['GEMINI_URL'] = ''

    try:
        proc = subprocess.run(req_path, env=env, timeout=10, capture_output=True, check=True)
    except subprocess.TimeoutExpired:
        raise CBSException(42, 'CGI script timeout', req_path)
    except subprocess.CalledProcessError as x:
        raise CBSException(42, 'CGI script error', '{} -> {}'.format(req_path, x.returncode))
    except PermissionError:
        raise CBSException(42, 'CGI not executable', req_path)
    conn.send(proc.stdout)


def serve_file(conn: SSL.Connection, filedir):
    mime_type, encoding = mimetypes.guess_type(filedir)
    try:
        f = open(filedir, 'rb')
        content = f.read()
        f.close()
    except Exception as x:
        raise CBSException(40, 'Server error accessing content', x)
    conn.send('20 {}\r\n'.format(mime_type or 'application/octet-stream').encode('utf-8'))
    conn.send(content)


# ------------------------------------------------------------------------------
# Top level


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
            try:
                req = recv_req(conn)
                serve_req(conn, addr, req, conf)
            except CBSException as x:
                logging.error('{} {} {}'.format(x.code, x.meta, x.logdata))
                conn.send('{} {}\r\n'.format(x.code, x.meta).encode('utf-8'))
            except Exception as x:
                logging.error('Exception: {}'.format(x))
                conn.send('40 Server error\r\n')
            conn.shutdown()
            conn.sock_shutdown(socket.SHUT_RDWR)


if __name__ == '__main__':
    main()
