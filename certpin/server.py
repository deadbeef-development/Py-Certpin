import socket, socketserver
import threading
import argparse
import ssl

parser = argparse.ArgumentParser()

parser.add_argument('listen_host')
parser.add_argument('listen_port', type=int)
parser.add_argument('target_server')
parser.add_argument('target_server_port', type=int)
parser.add_argument('--pinned-cert')
parser.add_argument('--debug', default=False, action='store_true')

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

        # Optionally, you can join these threads if you need to wait for them to finish
        client_to_server_thread.join()
        server_to_client_thread.join()

if __name__ == "__main__":
    args = parser.parse_args()

    listen_addr = (args.listen_host, args.listen_port)
    target_addr = (args.target_server, args.target_server_port)
    target_hostname = args.target_server

    if args.pinned_cert is None:
        pinned_cert = None
    else:
        pinned_cert = load_certificate(args.pinned_cert)
    
    def verify_certificate(cert) -> bool:
        if args.debug:
            print(ssl.DER_cert_to_PEM_cert(cert))
        
        if pinned_cert is None:
            return True

        return cert == pinned_cert

    class CertpinHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            context = ssl.create_default_context()

            with socket.create_connection(target_addr) as upstream_sock:
                with context.wrap_socket(upstream_sock, server_hostname=target_hostname) as upstream_ssl_sock:
                    # Get the certificate
                    cert = upstream_ssl_sock.getpeercert(binary_form=True)

                    if verify_certificate(cert):
                        print("✔ Certificate valid - Bridging connection ✔")
                        bridge_sockets(self.request, upstream_ssl_sock)
                    else:
                        print("⚠ CERTIFICATE MISMATCH - CLOSING CONNECTION ⚠")
                        # Certificate mismatch, close the connection
                        upstream_ssl_sock.close()

    with socketserver.ThreadingTCPServer(listen_addr, CertpinHandler) as server:
        server.serve_forever()

