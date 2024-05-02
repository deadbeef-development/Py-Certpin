from typing import Tuple, Dict
import argparse
import os
import json
from contextlib import contextmanager
import logging

from .proxy import Proxy, ProxyServer
from .util import connect_ssl_insecure, load_pem_certfile_as_der

logger = logging.getLogger('certpin.server')

class CertMismatch(Exception):
    pass

def create_certpin_proxy(
        target_sni: str,
        target_certfile: str,
        target_address: Tuple[str, int],
        certfile: str, keyfile: str
) -> Proxy:
    @contextmanager
    def connect_upstream():
        with connect_ssl_insecure(target_address, target_sni) as upstream_ssl_sock:
            pinned_cert = load_pem_certfile_as_der(target_certfile)
            upstream_cert = upstream_ssl_sock.getpeercert(binary_form=True)

            if upstream_cert == pinned_cert:
                logger.info(f"✔ Accepted connection to {target_sni}")
                yield upstream_ssl_sock
            else:
                logger.error(f"⚠ Rejected connection to {target_sni}, certificate mismatch detected")
                raise CertMismatch(target_sni, target_address)
    
    return Proxy(
        certfile=certfile,
        keyfile=keyfile,
        connect_upstream=connect_upstream
    )

def load_proxies(proxy_config_dir: str) -> Dict[str, Proxy]:
    proxies = dict()

    for file_name in os.listdir(proxy_config_dir):
        file_path = os.path.join(proxy_config_dir, file_name)
        target_sni = file_name[:-5] # Ignore the .JSON

        try:
            with open(file_path, 'r') as fio:
                proxy_config = json.load(fio)
        except Exception as e:
            logger.error("Could not load proxy config", file_path, e)
            continue

        proxies[target_sni] = create_certpin_proxy(
            target_sni=target_sni,
            **proxy_config
        )

    return proxies

def parse_address(address_string: str) -> Tuple[str, int]:
    host, port = address_string.split(':')
    return (host, int(port))

parser = argparse.ArgumentParser()
parser.add_argument('bind_address', type=parse_address)
parser.add_argument('proxy_config_dir')

def __main__():
    logger.setLevel(logging.INFO)
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    logger.info("Starting Certpin Server")

    args = parser.parse_args()
    
    address = args.bind_address
    proxies = load_proxies(args.proxy_config_dir)

    logger.info(f"Proxies loaded: {len(proxies)}")

    with ProxyServer(address, proxies.get) as server:
        logger.info(f"Listening on {':'.join(map(str, address))}")
        server.serve_forever()

if __name__ == '__main__':
    __main__()

