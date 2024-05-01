from argparse import ArgumentParser
import ssl

from .util import connect_ssl_insecure

parser = ArgumentParser()

parser.add_argument('server_address', help='host:port')
parser.add_argument('der_dest_file_path')

parser.add_argument('--server-name', default=None)

if __name__ == '__main__':
    args = parser.parse_args()

    host, port = args.server_address.split(':')

    ssl_server_addr = host, int(port)

    with connect_ssl_insecure(ssl_server_addr, args.server_name) as sock:
        with open(args.der_dest_file_path, 'wb') as fio:
            der = sock.getpeercert(binary_form=True)
            fio.write(ssl.DER_cert_to_PEM_cert(der))

