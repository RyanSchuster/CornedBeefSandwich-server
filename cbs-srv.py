#!/usr/bin/env python3

import select
import socket
from OpenSSL import SSL
from urllib.parse import urlparse

from os import path, PathLike, environ
import subprocess
import mimetypes

import logging
import argparse

logging.basicConfig(level=logging.INFO)
mimetypes.add_type('text/gemini', '.gmi')
mimetypes.add_type('text/gemini', '.gemini')

# ------------------------------------------------------------------------------


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


def serve_req(conn: SSL.Connection, addr, url: str, servedir: PathLike, cgidir: PathLike):
    url = urlparse(url)
    servedir = path.abspath(servedir)
    cgidir = path.join(servedir, cgidir)
    reqdir = path.abspath(path.join(servedir, '.'+url.path))
    if path.commonpath([servedir, reqdir]) != servedir:
        return serve_notfound(conn)
    if path.isdir(reqdir):
        reqdir = path.join(reqdir, 'index.gmi')
    if not path.isfile(reqdir):
        return serve_notfound(conn)
    if path.commonpath([cgidir, reqdir]) == cgidir:
        return serve_cgi(conn, addr, reqdir, url)
    return serve_file(conn, reqdir)


def serve_notfound(conn: SSL.Connection):
    conn.send(b'51 Page not found\r\n')


def serve_cgi(conn: SSL.Connection, addr, scriptdir: PathLike, url):
    cert = conn.get_peer_certificate()
    env = environ.copy()

    # RFC 3875
    env['AUTH_TYPE'] = 'CERTIFICATE' if cert is not None else ''
    env['CONTENT_LENGTH'] = ''
    env['CONTENT_TYPE'] = ''
    env['GATEWAY_INTERFACE'] = 'CGI/1.1'
    env['PATH_INFO'] = ''          # TODO: maybe later
    env['PATH_TRANSLATED'] = ''    # TODO: maybe later
    env['QUERY_STRING'] = url.query
    env['REMOTE_ADDR'] = addr
    env['REMOTE_HOST'] = ''        # TODO: pull domain name from cert?
    env['REMOTE_IDENT'] = ''       # There is no ident info in gemini, leave blank
    env['REMOTE_USER'] = ''        # TODO: populate with TLS session ID?  Maybe name from cert?
    env['REQUEST_METHOD'] = 'GET'  # This is the closest reasonable value, I worry about that idempotency tho
    env['SCRIPT_NAME'] = str(scriptdir)
    env['SERVER_NAME'] = url.hostname
    env['SERVER_PORT'] = '1965'    # FIXME: pull this from options just in case it's overridden
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

    print(cert.get_issuer())
    print(cert.get_subject())
    print(cert.get_pubkey())

    # subprocess.Popen(scriptdir, env=env).wait(timeout=10)
    if conn.get_peer_certificate() is None:
        conn.send(b'60\r\n')
    else:
        conn.send(b'20 text/gemini\r\n')
        conn.send(b'# Your mother runs CGI scripts\r\n')


def serve_file(conn: SSL.Connection, filedir: PathLike):
    (mime_type, encoding) = mimetypes.guess_type(filedir)
    logging.info('mime_type:{}, encoding:{}'.format(mime_type, encoding))
    with open(filedir, 'rb') as f:
        conn.send('20 {}\r\n'.format(mime_type or 'application/octet-stream').encode('utf-8'))
        conn.send(f.read())


# ------------------------------------------------------------------------------


def accept_client_cert(conn, cert, err_num, err_depth, ret_code):
    return True


def main():
    parser = argparse.ArgumentParser('Corned Beef Sandwich Gemini Server')
    parser.add_argument('--addr', '-a', default='127.0.0.1', help='IP address to bind to (default:"127.0.0.1")')
    parser.add_argument('--port', '-p', type=int, default=1965, help='TCP port to listen on (default: 1965)')
    parser.add_argument('--servedir', '-s', default='./serve', help='Directory to serve (devault: "./serve")')
    parser.add_argument('--cgidir', '-g', default='cgi-bin', help='CGI script directory, relative to --servedir (default: "cgi-bin")')
    parser.add_argument('--certfile', '-c', default='./crypt/server.crt', help='Cert file')
    parser.add_argument('--keyfile', '-k', default='./crypt/server.key', help='Private key file')
    args = parser.parse_args()

    ctxt = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctxt.set_verify(SSL.VERIFY_PEER, accept_client_cert)
    ctxt.use_certificate_file(args.certfile, SSL.FILETYPE_PEM)
    ctxt.use_privatekey_file(args.keyfile, SSL.FILETYPE_PEM)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.addr, args.port))
        sock.listen()
        ssock = SSL.Connection(ctxt, sock)
        ssock.set_accept_state()
        while True:
            conn, addr = ssock.accept()
            conn.do_handshake()
            logging.info('Connection from {}'.format(addr))
            req = recv_req(conn)
            if req is not None:
                serve_req(conn, addr, req, args.servedir, args.cgidir)
            conn.shutdown()
            conn.sock_shutdown(socket.SHUT_RDWR)


if __name__ == '__main__':
    main()

