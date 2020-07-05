import random

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

if os.environ["HAPROXY_CONFIG_DIR"] == "":
    c_dir = pathlib.Path(__file__).parent

else:
    c_dir = os.environ["HAPROXY_CONFIG_DIR"]

os.makedirs(os.path.join(c_dir, "tor"), exist_ok=True)
os.makedirs(os.path.join(c_dir, "haproxy"), exist_ok=True)


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

def Threaded(a):
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

        self.haproxy = HAProxy()
        for group in range(self.n_groups):
            for i in range(self.n_instances):
                tor = Tor()
                self.instances[tor.port] = tor
                self.haproxy.add_proxy(group, f"proxy-{group}-{i}", "127.0.0.1", tor.port)
        self.haproxy.generate_config()
        self.haproxy.start()

    def run(self) -> None:

        t = Thread(target=self._refresh_invalids, args=())
        t.start()

        while True:
            self._spawn_batch()
            self._evaluate_duplicates()
            time.sleep(1)

    def _refresh_invalids(self):
        while True:
            print("Number of invalids: ", len(self.invalids))
            if len(self.invalids) > 0:

                for_deletion = []
                for idx in range(len(self.invalids)):
                    instance = self.invalids[idx]
                    if instance.renew():

                        # Check if the IP is now unique
                        alike = [x for x in self.instances.values() if x.ip_address == instance.ip_address]
                        if len(alike) <= 0:
                            for_deletion.append(idx)
                            self.instances[instance.port] = instance
                try:
                    for i in for_deletion:
                        self.invalids.pop(i)
                except IndexError:
                    # this can happen due to concurrency. i should change to somethign that sync well
                    pass
            time.sleep(1)

    def _spawn_batch(self):
        not_started = [x for x in self.instances.values() if x.process is None]
        missing = len(not_started)
        print("Missing: ", missing)
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
        duplicates = [item for item, count in collections.Counter(all_addresses).items() if count > 1 and item is not None]

        for dup in duplicates:
            dup_idx = all_addresses.index(dup)
            instance = all_instances[dup_idx]

            self.invalids.append(self.instances.pop(instance.port))


class Tor:
    PROCESS_COUNT = 0
    BASE_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT_START"))
    BASE_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT_START"))

    def __init__(self):
        self.process = None
        self.ip_address = None
        self.latency = None

        self.port = Tor.BASE_SOCKS_PORT + Tor.PROCESS_COUNT
        self.control_port = Tor.BASE_CONTROL_PORT + Tor.PROCESS_COUNT
        self.data_dir = os.path.join(c_dir, "tor", str(Tor.PROCESS_COUNT))
        self.conf_file = os.path.join(self.data_dir, "torrc")
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.conf_file, "w+") as f:
            f.writelines([
                f"HTTPTunnelPort {self.port}"
            ])
        Tor.PROCESS_COUNT += 1

    @Threaded
    def renew_threaded(self):
        return self.renew()

    def renew(self):

        current_ip = self.ip_address

        command = "authenticate ""\nsignal newnym\nquit"
        data = netcat("127.0.0.1", self.control_port, command)
        time.sleep(2)
        self._update_ip()
        print("Current=",current_ip,"New=",self.ip_address)
        return current_ip != self.ip_address

    def __str__(self):
        return f"port={self.port},address={self.ip_address}"

    def _update_ip(self):
        response = requests.get("https://api.ipify.org", proxies=dict(
            http=f"http://127.0.0.1:{self.port}",
            https=f"http://127.0.0.1:{self.port}"
        ))
        self.latency = response.elapsed.total_seconds()
        self.ip_address = response.text

    @Threaded
    def start(self):
        self.process = launch_tor(args=[
            #"-f", f"{self.conf_file}",
            "--SocksPort", f"{self.port}",
            "--ControlPort", f"{self.control_port}",
            "--NewCircuitPeriod", os.getenv("TOR_NEW_CIRCUIT_PERIOD"),
            "--MaxCircuitDirtiness", os.getenv("TOR_MAX_CIRCUIT_DIRTINESS"),
            "--CircuitBuildTimeout", os.getenv("TOR_CIRCUIT_BUILD_TIMEOUT"),
            "--DataDirectory", self.data_dir,
            # "--PidFile",  #{pid_file}",
             "--NumEntryGuards",  os.getenv("TOR_NUM_ENTRY_GUARDS"),
             "--ExitRelay",  "0",
             "--RefuseUnknownExits", "0",
             "--ClientOnly",  "1",
             "--StrictNodes",  "1",
            # "--ExcludeSingleHopRelays", "0", # TODO - install old
            # "--AllowSingleHopCircuits",  "1", # TODO obsolete
            "--Log", "debug",
            # "--RunAsDaemon", "1",
        ], take_ownership=True)
        self.process.stdout = sys.stdout

        self._update_ip()
        return self

    def status(self):
        pass


class HAProxy:
    HAPROXY_PORT = int(os.getenv("HAPROXY_SOCKS5_PORT"))

    def __init__(self):
        self.process = None
        self.pid_file = os.path.join(c_dir, "haproxy", "haproxy.pid")
        self.socket = os.path.join(c_dir, "haproxy", "haproxy.socket")
        self.config_template = os.path.join(c_dir, "haproxy.cfg.j2")
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
        cert = crypto.X509  ()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Minnesota"
        cert.get_subject().L = "Minnetonka"
        cert.get_subject().O = "my company"
        cert.get_subject().OU = "my organization"
        cert.get_subject().CN = "*.insight.io"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        #with open(self.public_key, "wb+") as f:
        #    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        #    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


    def _read_file(self, path):
        try:
            with open(path, "r") as f:
                pid = f.read()
            return pid
        except FileNotFoundError:
            return ""

    def add_proxy(self, group, name, address, port):
        if group not in self.groups:
            self.groups[group] = dict(
                id=group,
                port=HAProxy.HAPROXY_PORT + group,
                proxies=[]
            )

        self.groups[group]["proxies"].append((address, port, name))

    def generate_config(self):
        templ = Template(self._read_file(self.config_template))
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

    def start(self):

        with open(self.pid_file, "w") as f:
            f.write("")

        os.system("killall haproxy")
        os.system(' '.join([
            "haproxy",
            "-f", self.config,
            "-p", self.pid_file,  # PID
            "-sf", self._read_file(self.pid_file),

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

    while True:
        time.sleep(1)
