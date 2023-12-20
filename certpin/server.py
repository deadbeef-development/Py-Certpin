import socket, socketserver
import threading
import argparse
import ssl
import os
import json

from typing import Tuple

def load_certificate(certfile_path):
    with open(certfile_path, 'rb') as certfile:
        return certfile.read()

def forward(source: socket.socket, destination: socket.socket):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    finally:
        source.close()
        destination.close()

def bridge_sockets(sock1, sock2):
        client_to_server_thread = threading.Thread(target=forward, args=(sock1, sock2))
        server_to_client_thread = threading.Thread(target=forward, args=(sock2, sock1))

        # Start the threads
        client_to_server_thread.start()
        server_to_client_thread.start()

        # Join
        client_to_server_thread.join()
        server_to_client_thread.join()

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

    class CertpinHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            context = ssl.create_default_context()

            with socket.create_connection(ssl_target_addr) as upstream_sock:
                with context.wrap_socket(upstream_sock, server_hostname=target_server_name) as upstream_ssl_sock:
                    # Get the certificate
                    cert = upstream_ssl_sock.getpeercert(binary_form=True)

                    if verify_certificate(cert):
                        print(f"[{target_server_name}] ✔ Certificate valid - Bridging connection ✔")
                        bridge_sockets(self.request, upstream_ssl_sock)
                    else:
                        print(f"[{target_server_name}] ⚠ CERTIFICATE MISMATCH - CLOSING CONNECTION ⚠")
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
