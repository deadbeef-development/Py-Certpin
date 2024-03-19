import socket
import threading
import errno

RECV_BUF_SIZE = 1_048_576

def load_certificate(certfile_path):
    with open(certfile_path, 'rb') as certfile:
        return certfile.read()

def forward(source: socket.socket, destination: socket.socket):
    try:
        while True:
            data = source.recv(RECV_BUF_SIZE)
            if not data:
                break
            destination.sendall(data)
    except OSError as e:
        # Check for Bad file descriptor error
        if e.errno == errno.EBADF:
            return
        else:
            raise 
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

