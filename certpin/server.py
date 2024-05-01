from typing import Tuple, Dict
import argparse
import os
import json
from contextlib import contextmanager
from logging import getLogger

from .proxy import Proxy, ProxyServer
from .util import connect_ssl_insecure, load_pem_certfile_as_der

logger = getLogger('certpin.server')

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
                logger.info(f"[{target_sni}] ✔ Certificate valid - Bridging connection ✔")
                yield upstream_ssl_sock
            else:
                logger.error(f"[{target_sni}] ⚠ CERTIFICATE MISMATCH - CLOSING CONNECTION ⚠")
                raise CertMismatch(target_sni, target_address)
    
    return Proxy(
        certfile=certfile,
        keyfile=keyfile,
        connect_upstream=connect_upstream
    )

parser = argparse.ArgumentParser()
parser.add_argument('bind_address')
parser.add_argument('proxy_config_dir')

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
            *proxy_config
        )

    return proxies

def __main__():
    args = parser.parse_args()
    
    address = args.bind_address
    proxies = load_proxies(args.proxy_config_dir)

    with ProxyServer(address, proxies.get) as server:
        server.serve_forever()

if __name__ == '__main__':
    __main__()

