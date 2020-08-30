import random
import shutil
import subprocess
import threading

from haproxyadmin import haproxy, STATE_DISABLE, STATE_ENABLE
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


def timed_task(fn, args=(), interval=300):

    def wrap():
        fn(*args)

        time.sleep(interval)

    t = Thread(target=wrap, args=())
    t.daemon = True
    t.start()


class TorGroup(Thread):

    def __init__(self, n_instances: int, group: int, haproxy, restart_interval: tuple):
        super().__init__()
        self.n_instances = n_instances
        self.group = group
        self.setup_wait = threading.Event()
        self._haproxy = haproxy
        self.restart_interval = restart_interval
        self.instances = {}  # control_port, instance

    def run(self) -> None:
        self._build_group()

        while True:
            time.sleep(random.randint(*self.restart_interval))
            self.restart_group()

    def _build_group(self):
        temp_instances = []
        for i in range(self.n_instances):
            hostname = "127.0.0.1"
            tor = Tor(hostname=hostname, haproxy=self._haproxy)
            tor.start()
            temp_instances.append(tor)

        wait_for(temp_instances)

        for i, tor in enumerate(temp_instances):
            self.instances[tor.socks_port] = tor
            self._haproxy.add_proxy(self.group, f"proxy-{self.group}-{i}", tor.hostname,
                                    tor.http_port if tor.is_http else tor.socks_port)

        self.setup_wait.set()

    def disable_group(self):
        for tor in self.instances.values():
            tor.disable()

    def enable_group(self):
        for tor in self.instances.values():
            tor.enable()

    def restart_group(self):
        self.disable_group()
        for socks_port, tor in self.instances.items():
            tor.restart()

        self.enable_group()


class TorPool(Thread):

    def __init__(self,
                 n_instances=int(os.getenv("TOR_INSTANCES")),
                 start_batch=int(os.getenv("TOR_START_BATCH")),
                 n_groups=int(os.getenv("TOR_GROUPS")),
                 restart_interval=(
                     int(os.getenv("TOR_GROUPS_RESTART_INTERVAL_MIN")),
                     int(os.getenv("TOR_GROUPS_RESTART_INTERVAL_MAX"))
                 )

                 ):
        super().__init__()
        self.n_instances = n_instances
        self.n_groups = n_groups
        self.start_batch = start_batch
        self.restart_interval = restart_interval  # restart interval on groups.

        self.groups = []
        self.haproxy = HAProxy(tor_groups=self.groups)
        self._build_groups()

    def _build_groups(self):

        for i_group in range(self.n_groups):
            group = TorGroup(
                n_instances=self.n_instances,
                group=i_group,
                haproxy=self.haproxy,
                restart_interval=self.restart_interval
            )
            group.daemon = True
            group.start()

            self.groups.append(group)

        for group in self.groups:
            group.setup_wait.wait()

        self.haproxy.generate_config()
        self.haproxy.start()

    def run(self) -> None:

        while True:
            time.sleep(1)



    """
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
        """

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

    def __init__(self, hostname, haproxy):
        self.hostname = hostname
        self.process = None
        self.ip_address = None
        self.latency = None
        self.haproxy = haproxy
        self.haproxy_server = None # Populated when haproxy starts via update_haproxy function

        self.data_dir = os.path.join(c_dir, "tor", str(Tor.PROCESS_COUNT))
        self.circuit_dir = os.path.join(self.data_dir, "circuit")
        self.tor_conf = os.path.join(self.data_dir, "torrc")
        self.privoxy_conf = os.path.join(self.data_dir, "privoxy.cfg")

        self.tor_conf_templ = os.path.join(current_dir, "templates", "torrc.j2")
        self.privoxy_conf_templ = os.path.join(current_dir, "templates", "privoxy.cfg.j2")

        self._find_available_port()

        self.is_http = os.getenv("TOR_HTTP") == '1'
        self.is_privoxy = os.getenv("TOR_HTTP_PRIVOXY") == '1'

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
        self.generate_config()

        # TASKS
        timed_task(self.update_ip, args=(), interval=300)

    def _find_available_port(self):
        while True:
            self.socks_port = Tor.BASE_SOCKS_PORT + Tor.PROCESS_COUNT
            self.control_port = Tor.BASE_CONTROL_PORT + Tor.PROCESS_COUNT
            self.http_port = Tor.BASE_HTTP_PORT + Tor.PROCESS_COUNT
            Tor.PROCESS_COUNT += 1
            if self.try_port(self.socks_port) and self.try_port(self.control_port) and self.try_port(self.http_port):
                break

    @property
    def haproxy_name(self):
        return f"{self.hostname}:{self.socks_port}"

    def update_haproxy(self):
        self.haproxy_server = self.haproxy.socket.server(self.haproxy_name)[0]

    def disable(self):
        assert self.haproxy_server, "Not set " + self.haproxy_name
        self.haproxy_server.setstate(STATE_DISABLE)

    def enable(self):
        assert self.haproxy_server, "Not set"
        self.haproxy_server.setstate(STATE_ENABLE)

    def generate_config(self):
        os.makedirs(self.data_dir, exist_ok=True)
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

    def update_ip(self):
        try:
            response = requests.get("https://api.ipify.org", proxies=self.proxies)
            self.latency = response.elapsed.total_seconds()
            self.ip_address = response.text
        except requests.exceptions.ConnectionError:
            pass

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
        self.start_(start_privoxy)

    def start_(self, start_privoxy=True):
        if self.is_privoxy:
            privoxy = subprocess.Popen([
                "privoxy", self.privoxy_conf
            ])

        while True:

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
                break

            except OSError as e:
                print("ports is not available.", self.socks_port, self.control_port)
                self._find_available_port()
                return self

        self.update_ip()
        print("server", self.socks_port, self.control_port)
        return self

    def kill(self):
        print(self.process)
        os.kill(self.process.pid, 9)
        shutil.rmtree(self.circuit_dir)

    def restart(self):
        self.kill()
        self.generate_config()
        self.start_()

    def status(self):
        pass


class HAProxy:
    HAPROXY_PORT = int(os.getenv("HAPROXY_GROUP_PORT_START"))

    def __init__(self, tor_groups: list):
        self.process = None
        self.pid_file = os.path.join(c_dir, "haproxy", "haproxy.pid")
        self.socket_path = os.path.join(c_dir, "haproxy")
        self.socket_file = os.path.join(self.socket_path, "haproxy.socket")
        self.config_template = os.path.join(current_dir, "templates", "haproxy.cfg.j2")
        self.config = os.path.join(c_dir, "haproxy", "haproxy.cfg")
        self.ssl_pem = os.path.join(c_dir, "haproxy", "server.pem")
        self.private_key = os.path.join(c_dir, "haproxy", "server.key")
        self.public_key = os.path.join(c_dir, "haproxy", "server.crt")
        self.proxies = []
        self.groups = {}
        self.tor_groups = tor_groups # List of tor objects
        os.makedirs(self.socket_path, exist_ok=True)
        self.socket = None

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
        single_input = int(os.getenv("HAPROXY_SINGLE_INPUT"))

        config = templ.render(
            pid_file=self.pid_file,
            socket=self.socket_file,
            stats_port=os.environ["HAPROXY_STATS_PORT"],
            stats_user=os.environ["HAPROXY_STATS_USER"],
            stats_pass=os.environ["HAPROXY_STATS_PASS"],
            timeout_connect=int(os.getenv("HAPROXY_TIMEOUT_CONNECT")) * 1000,
            timeout_client=int(os.getenv("HAPROXY_TIMEOUT_CLIENT")) * 1000,
            timeout_server=int(os.getenv("HAPROXY_TIMEOUT_SERVER")) * 1000,
            retries=os.environ["HAPROXY_RETRIES"],
            maxconn=os.environ["HAPROXY_MAXCONN"],
            groups=self.groups,
            single_input_port=self.groups[0]["port"],
            single_input=single_input,
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

        self.socket = haproxy.HAProxy(socket_dir=self.socket_path)

        for tor_group in self.tor_groups:
            for tor in tor_group.instances.values():
                tor.update_haproxy()
                tor.enable()


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
