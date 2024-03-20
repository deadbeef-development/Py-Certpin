from typing import Tuple
import socketserver
import threading
import argparse
import ssl
import os
import json
from contextlib import contextmanager

from .util import load_certificate, bridge_sockets, open_ssl_connection

@contextmanager
def run_certpin_server(listen_addr: Tuple[str, int], ssl_target_addr: Tuple[str, int], target_server_name: str, pinned_cert_filepath: str = None, debug = False):
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
            with open_ssl_connection(ssl_target_addr, target_server_name) as upstream_ssl_sock:
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
        yield server

def run_certpin_server_from_config(server_config: dict) -> threading.Thread:
    def target():
        with run_certpin_server(**server_config) as server:
            server.serve_forever()

    t = threading.Thread(None, target)
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
