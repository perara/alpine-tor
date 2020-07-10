import random
import shutil
import subprocess
from concurrent.futures.thread import ThreadPoolExecutor

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

import sys
import time
from threading import Thread
from jinja2 import Template
import requests
import collections
import socket
import os
from OpenSSL import crypto, SSL
from stem.process import launch_tor
import pathlib
import logging


formatter = logging.Formatter('%(process)d - %(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)

root = logging.getLogger()
root.setLevel(logging.INFO)
if len(root.handlers) == 0:
    root.addHandler(ch)
_LOGGER = logging.getLogger("haproxy-tor")
_LOGGER.setLevel(logging.INFO)


current_dir = pathlib.Path(__file__).parent

if os.environ["HAPROXY_CONFIG_DIR"] == "":
    c_dir = pathlib.Path(__file__).parent

else:
    c_dir = os.environ["HAPROXY_CONFIG_DIR"]
    if not os.path.exists(c_dir):
        os.makedirs(c_dir, exist_ok=True)

os.makedirs(os.path.join(c_dir, "tor"), exist_ok=True)
os.makedirs(os.path.join(c_dir, "haproxy"), exist_ok=True)


def _read_file(path):
    try:
        with open(path, "r") as f:
            pid = f.read()
        return pid
    except FileNotFoundError:
        return ""


def netcat(host, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    s.sendall(content.encode())
    s.shutdown(socket.SHUT_WR)
    out = ''
    while True:
        data = s.recv(4096)
        if not data:
            break
        out += repr(data)
    s.close()
    return out


def threaded(a):
    def wrapped(self):
        if not hasattr(self, "__joinables__"):
            setattr(self, "__joinables__", [])
        t = Thread(target=a, args=(self,))
        t.daemon = True
        t.start()
        getattr(self, "__joinables__").append(t)
        return self

    return wrapped


class TorPool(Thread):

    def __init__(self,
                 n_instances=int(os.getenv("TOR_INSTANCES")),
                 start_batch=int(os.getenv("TOR_START_BATCH")),
                 groups=int(os.getenv("TOR_GROUPS"))):
        super().__init__()
        self.n_instances = n_instances
        self.start_batch = start_batch
        self.invalids = []
        self.instances = {}  # control_port, instance
        self.n_groups = groups

        self.haproxy = None
        self.build_haproxy()

    def build_haproxy(self):
        self.haproxy = HAProxy()
        for group in range(self.n_groups):
            for i in range(self.n_instances):
                tor = Tor()
                self.instances[tor.socks_port] = tor
                self.haproxy.add_proxy(group, f"proxy-{group}-{i}", "127.0.0.1",
                                       tor.http_port if tor.is_http else tor.socks_port)
        self.haproxy.generate_config()
        self.haproxy.start()


    def run(self) -> None:

        t = Thread(target=self._refresh_invalids, args=())
        t.start()

        ip_check_interval = 300
        ip_check_next = time.time()

        while True:
            self._spawn_batch()
            self._evaluate_duplicates()

            if time.time() >= ip_check_next:
                try:
                    self._recheck_ip()
                except:
                    pass
                ip_check_next = time.time() + ip_check_interval

            time.sleep(1)

    def _recheck_ip(self):
        keys = self.instances.keys()
        for key in keys:
            self.instances[key]._update_ip()

    def _refresh_invalids(self):

        def refresh(args):
            try:
                idx, instance = args
                is_ok = instance.renew_old()
                return is_ok, idx
            except:
                return False, idx

        while True:

            if len(self.invalids) > 0:
                num_invalid_start = len(self.invalids)
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.map(refresh, [(idx, instance) for idx, instance in enumerate(self.invalids)])

                for_deletion = []
                for is_ok, idx in future:
                    # Check if the IP is now unique
                    instance = self.invalids[idx]
                    alike = [x for x in self.instances.values() if x.ip_address == instance.ip_address]

                    if len(alike) <= 0:
                        self.instances[instance.socks_port] = instance
                        for_deletion.append(idx)

                for idx in for_deletion:
                    try:
                        self.invalids.pop(idx)
                    except IndexError:
                        # this can happen due to concurrency. i should change to somethign that sync well
                        pass

                num_invalids_end = len(self.invalids)
                _LOGGER.info("refresh-invalid: before=%s,after=%s,total=%s", num_invalid_start, num_invalids_end, len(self.instances))

            time.sleep(1)

    def _spawn_batch(self):
        not_started = [x for x in self.instances.values() if x.process is None]
        missing = len(not_started)
        assert missing >= 0
        if missing <= 0:
            return

        started = []

        items = [x for i, x in self.instances.items() if x.process is None]
        random.shuffle(items)
        for v in items:
            if len(started) >= self.start_batch:
                break
            started.append(v)
            v.start()

        wait_for(started)

    def _evaluate_duplicates(self):
        all_instances = [x for x in self.instances.values()]
        all_addresses = [x.ip_address for x in all_instances]
        duplicates = [item for item, count in collections.Counter(all_addresses).items()
                      if count > 1 and item is not None]

        for dup in duplicates:
            dup_idx = all_addresses.index(dup)
            instance = all_instances[dup_idx]

            self.invalids.append(self.instances.pop(instance.socks_port))


class Tor:
    PROCESS_COUNT = 0
    BASE_HTTP_PORT = int(os.getenv("TOR_HTTP_PORT_START"))
    BASE_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT_START"))
    BASE_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT_START"))

    def __init__(self):
        self.process = None
        self.ip_address = None
        self.latency = None

        self.data_dir = os.path.join(c_dir, "tor", str(Tor.PROCESS_COUNT))
        self.circuit_dir = os.path.join(self.data_dir, "circuit")
        self.tor_conf = os.path.join(self.data_dir, "torrc")
        self.privoxy_conf = os.path.join(self.data_dir, "privoxy.cfg")

        self.tor_conf_templ = os.path.join(current_dir, "templates", "torrc.j2")
        self.privoxy_conf_templ = os.path.join(current_dir, "templates", "privoxy.cfg.j2")

        while True:
            self.socks_port = Tor.BASE_SOCKS_PORT + Tor.PROCESS_COUNT
            self.control_port = Tor.BASE_CONTROL_PORT + Tor.PROCESS_COUNT
            self.http_port = Tor.BASE_HTTP_PORT + Tor.PROCESS_COUNT
            Tor.PROCESS_COUNT += 1
            if self.try_port(self.socks_port) and self.try_port(self.control_port) and self.try_port(self.http_port):
                break

        self.is_http = os.getenv("TOR_HTTP") == '1'
        self.is_privoxy = os.getenv("TOR_HTTP_PRIVOXY") == '1'

        os.makedirs(self.data_dir, exist_ok=True)

        if self.is_http:
            self.proxies = dict(
                http=f"http://127.0.0.1:{self.http_port}",
                https=f"http://127.0.0.1:{self.http_port}"
            )
        else:
            self.proxies = dict(
                http=f"socks5://127.0.0.1:{self.socks_port}",
                https=f"socks5://127.0.0.1:{self.socks_port}"
            )
        self._generate_config()

    def _generate_config(self):
        self._generate_privoxy_config()
        self._generate_tor_config()

    def _generate_tor_config(self):
        # Generate privoxy config
        vars = {}
        if self.is_http and not self.is_privoxy:
            vars["http_port"] = self.http_port
        with open(self.tor_conf, "w+") as f:
            privoxy_config = Template(_read_file(self.tor_conf_templ))
            f.write(privoxy_config.render(vars))

    def _generate_privoxy_config(self):
        # Generate privoxy config
        with open(self.privoxy_conf, "w+") as f:
            privoxy_config = Template(_read_file(self.privoxy_conf_templ))
            f.write(privoxy_config.render(dict(
                http_port=self.http_port,
                socks_port=self.socks_port
            )))

    @threaded
    def renew_threaded(self):
        return self.renew()

    def renew(self): # TODO
        self.kill()
        current_ip = self.ip_address
        self.start(start_privoxy=False)
        print(current_ip, self.ip_address)
        return current_ip == self.ip_address


    def renew_old(self):
        current_ip = self.ip_address
        command = "authenticate ""\nsignal newnym\nquit"
        data = netcat("127.0.0.1", self.control_port, command)
        time.sleep(2)
        self._update_ip()
        #_LOGGER.info("ip-renew: before=%s,after=%s", current_ip, self.ip_address)
        return current_ip != self.ip_address

    def __str__(self):
        return f"port={self.http_port},address={self.ip_address}"

    def _update_ip(self):
        response = requests.get("https://api.ipify.org", proxies=self.proxies)
        self.latency = response.elapsed.total_seconds()
        self.ip_address = response.text

    def try_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = False
        try:
            sock.bind(("0.0.0.0", port))
            result = True
        except Exception as e:
            result = False
        sock.close()
        return result

    @threaded
    def start(self, start_privoxy=True):
        if self.is_privoxy:
            privoxy = subprocess.Popen([
                "privoxy", self.privoxy_conf
            ])
        try:
            self.process = launch_tor(args=[
                "-f", f"{self.tor_conf}",
                "--SocksPort", f"{self.socks_port}",
                "--ControlPort", f"{self.control_port}",
                "--NewCircuitPeriod", os.getenv("TOR_NEW_CIRCUIT_PERIOD"),
                "--MaxCircuitDirtiness", os.getenv("TOR_MAX_CIRCUIT_DIRTINESS"),
                "--CircuitBuildTimeout", os.getenv("TOR_CIRCUIT_BUILD_TIMEOUT"),
                "--DataDirectory", self.circuit_dir,
                #"--PidFile",  #{pid_file}",
                "--NumEntryGuards", os.getenv("TOR_NUM_ENTRY_GUARDS"),
                "--ExitRelay", "0",
                "--RefuseUnknownExits", "0",
                "--ClientOnly", "1",
                "--StrictNodes", "1",
                # "--ExcludeSingleHopRelays", "0", # TODO - install old
                # "--AllowSingleHopCircuits",  "1", # TODO obsolete
                # "--Log", "debug",
                # "--RunAsDaemon", "1",
            ], take_ownership=True)
            self.process.stdout = sys.stdout
        except OSError as e:
            print(self.socks_port, self.control_port)
            return self
        self._update_ip()
        return self

    def kill(self):
        os.kill(self.process.pid, 9)
        shutil.rmtree(self.circuit_dir)

    def status(self):
        pass


class HAProxy:
    HAPROXY_PORT = int(os.getenv("HAPROXY_GROUP_PORT_START"))

    def __init__(self):
        self.process = None
        self.pid_file = os.path.join(c_dir, "haproxy", "haproxy.pid")
        self.socket = os.path.join(c_dir, "haproxy", "haproxy.socket")
        self.config_template = os.path.join(current_dir, "templates", "haproxy.cfg.j2")
        self.config = os.path.join(c_dir, "haproxy", "haproxy.cfg")
        self.ssl_pem = os.path.join(c_dir, "haproxy", "server.pem")
        self.private_key = os.path.join(c_dir, "haproxy", "server.key")
        self.public_key = os.path.join(c_dir, "haproxy", "server.crt")
        self.proxies = []
        self.groups = {}

        self._generate_ssl_keys()

    def _generate_ssl_keys(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Minnesota"
        cert.get_subject().L = "Minnetonka"
        cert.get_subject().O = "my company"
        cert.get_subject().OU = "my organization"
        cert.get_subject().CN = "*.insight.io"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        # with open(self.public_key, "wb+") as f:
        #    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        #    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    def add_proxy(self, group, name, address, port):
        if group not in self.groups:
            self.groups[group] = dict(
                id=group,
                port=HAProxy.HAPROXY_PORT + group,
                proxies=[]
            )

        self.groups[group]["proxies"].append((address, port, name))

    def generate_config(self):
        templ = Template(_read_file(self.config_template))
        config = templ.render(
            pid_file=self.pid_file,
            stats_port=os.environ["HAPROXY_STATS_PORT"],
            stats_user=os.environ["HAPROXY_STATS_USER"],
            stats_pass=os.environ["HAPROXY_STATS_PASS"],
            timeout_connect=int(os.getenv("HAPROXY_TIMEOUT_CONNECT")) * 1000,
            timeout_client=int(os.getenv("HAPROXY_TIMEOUT_CLIENT")) * 1000,
            timeout_server=int(os.getenv("HAPROXY_TIMEOUT_SERVER")) * 1000,
            retries=os.environ["HAPROXY_RETRIES"],
            maxconn=os.environ["HAPROXY_MAXCONN"],
            groups=self.groups,
            cert=self.ssl_pem
        )

        with open(self.config, "w") as f:
            f.write(config)

    def clear_groups(self):
        self.groups.clear()

    def stop(self):
        with open(self.pid_file, "w") as f:
            f.write("")

        os.system("killall haproxy")

    def start(self):
        self.stop()

        os.system(' '.join([
            "haproxy",
            "-f", self.config,
            "-p", self.pid_file,  # PID
            "-sf", _read_file(self.pid_file),
        ]))

    def status(self):
        pass


def wait_for(instances):
    joinables = []
    for instance in instances:
        if hasattr(instance, "__joinables__"):
            joinables.extend(getattr(instance, "__joinables__"))

    for join in joinables:
        join.join()


if __name__ == "__main__":
    pool = TorPool()
    pool.start()
    _headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9,nb;q=0.8",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "referer": f"https://mobile.twitter.com/nasa?lang=en",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"
    }
    while True:

        time.sleep(1)
