from typing import Tuple
import socket, socketserver
import threading
import argparse
import ssl
import os
import json

from .util import load_certificate, bridge_sockets

def run_certpin_server(listen_addr: Tuple[str, int], ssl_target_addr: Tuple[str, int], target_server_name: str, pinned_cert_filepath: bytes = None, debug = False):
    listen_addr = tuple(listen_addr)
    ssl_target_addr = tuple(ssl_target_addr)

    def get_pinned_cert():
        if pinned_cert_filepath is not None:
            return load_certificate(pinned_cert_filepath)
    
    def verify_certificate(cert) -> bool:
        if debug:
            print(ssl.DER_cert_to_PEM_cert(cert))
        
        pinned_cert = get_pinned_cert()
        
        if pinned_cert is None:
            return True

        return cert == pinned_cert

    def print_info(*args):
        lhost, lport = listen_addr
        print(f"[{lhost}:{lport} -> {target_server_name}]", *args)

    class CertpinHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(ssl_target_addr) as upstream_sock:
                with context.wrap_socket(upstream_sock, server_hostname=target_server_name) as upstream_ssl_sock:
                    # Get the certificate
                    cert = upstream_ssl_sock.getpeercert(binary_form=True)

                    if verify_certificate(cert):
                        print_info("✔ Certificate valid - Bridging connection ✔")
                        bridge_sockets(self.request, upstream_ssl_sock)
                    else:
                        print_info("⚠ CERTIFICATE MISMATCH - CLOSING CONNECTION ⚠")
                        # Certificate mismatch, close the connection
                        upstream_ssl_sock.close()

    with socketserver.ThreadingTCPServer(listen_addr, CertpinHandler) as server:
        server.serve_forever()

def run_certpin_server_from_config(server_config: dict) -> threading.Thread:
    t = threading.Thread(None, run_certpin_server, kwargs=server_config)
    t.start()

    return t

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('config_filepath')

    args = parser.parse_args()
    config_filepath = args.config_filepath

    if os.path.isfile(config_filepath):
        with open(config_filepath, 'r') as fio:
            config = json.load(fio)
    else:
        print(f"Cannot open {config_filepath}")

    threads = list()
    
    for server_config in config['servers']:
        t = run_certpin_server_from_config(server_config)
        threads.append(t)
    
    for t in threads:
        t.join()
