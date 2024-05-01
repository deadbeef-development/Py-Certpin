from typing import Callable, Tuple, ContextManager
import socket
import ssl
from logging import getLogger
from socketserver import BaseRequestHandler, ThreadingMixIn, TCPServer

from .util import bridge_sockets

logger = getLogger('certpin.proxy')

class Proxy:
    def __init__(self, certfile: str, keyfile: str, connect_upstream: Callable[[], ContextManager[socket.socket]]):
        self.certfile = certfile
        self.keyfile = keyfile
        self.connect_upstream = connect_upstream

class ProxyNotFound(Exception):
    pass

class ProxyHandler(BaseRequestHandler):
    def handle(self):
        self.server: ProxyServer
        
        with self.request.proxy.connect_upstream() as upstream_socket:
            bridge_sockets(self.request, upstream_socket)

class ProxyServer(ThreadingMixIn, TCPServer):
    def __init__(self, address: Tuple[str, int], get_proxy: Callable[[str], Proxy]):
        TCPServer.__init__(self, address, ProxyHandler, bind_and_activate=True)

        self.get_proxy = get_proxy
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.sni_callback = self.sni_callback

    def sni_callback(self, ssl_sock: ssl.SSLSocket, server_name: str, initial_context: ssl.SSLContext):
        proxy = ssl_sock.proxy = self.get_proxy(server_name)

        if proxy is None:
            raise ProxyNotFound(server_name)

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=proxy.certfile, keyfile=proxy.keyfile)
        
        ssl_sock.context = ssl_context

    def get_request(self):
        newsocket, fromaddr = super().get_request()
        ssl_socket = self.ssl_context.wrap_socket(newsocket, server_side=True)
        return ssl_socket, fromaddr

