import subprocess
import sys
import time
from threading import Thread
from jinja2 import Template

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())
import os
import haproxyadmin
from stem.process import launch_tor
import pathlib

c_dir = pathlib.Path(__file__).parent
os.makedirs(os.path.join(c_dir, "tor"), exist_ok=True)
os.makedirs(os.path.join(c_dir, "haproxy"), exist_ok=True)


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


class Tor:
    PROCESS_COUNT = 0
    BASE_CONTROL_PORT = int(os.environ["TOR_CONTROL_PORT_START"])

    def __init__(self):
        self.process = None
        self.port = None
        self.data_dir = None

    @Threaded
    def start(self):
        Tor.PROCESS_COUNT += 1
        self.port = Tor.BASE_CONTROL_PORT + Tor.PROCESS_COUNT - 1
        self.data_dir = os.path.join(c_dir, "tor", str(Tor.PROCESS_COUNT))
        self.process = launch_tor(args=[
            "--SocksPort", f"{self.port}",
            "--NewCircuitPeriod", "15",
            "--MaxCircuitDirtiness", "60",
            "--CircuitBuildTimeout", "20",
            "--DataDirectory", self.data_dir,
            # "--PidFile",  #{pid_file}",
            # "--NumEntryGuards",  "8",
            # "--ExitRelay",  "0",
            # "--RefuseUnknownExits", "0",
            # "--ClientOnly",  "1",
            # "--StrictNodes",  "1",
            # "--ExcludeSingleHopRelays", "0", # TODO - install old
            # "--AllowSingleHopCircuits",  "1", # TODO obsolete
            "--Log", "debug",
            # "--RunAsDaemon", "1",
        ], take_ownership=True)
        self.process.stdout = sys.stdout
        return self

    def status(self):
        pass


class HAProxy:

    def __init__(self):
        self.process = None
        self.pid_file = os.path.join(c_dir, "haproxy", "haproxy.pid")
        self.socket = os.path.join(c_dir, "haproxy", "haproxy.socket")
        self.config_template = os.path.join(c_dir, "haproxy.cfg.j2")
        self.config = os.path.join(c_dir, "haproxy", "haproxy.cfg")
        self.proxies = []

    def _read_file(self, path):
        try:
            with open(path, "r") as f:
                pid = f.read()
            return pid
        except FileNotFoundError:
            return ""

    def add_proxy(self, address, port):
        self.proxies.append((address, port))

    def generate_config(self):
        templ = Template(self._read_file(self.config_template))
        config = templ.render(
            pid_file=self.pid_file,
            proxies=self.proxies,
            stats_port=os.environ["HAPROXY_STATS_PORT"],
            stats_user=os.environ["HAPROXY_STATS_USER"],
            stats_pass=os.environ["HAPROXY_STATS_PASS"],
            socks5_port=os.environ["HAPROXY_SOCKS5_PORT"],
            timeout_connect=os.environ["HAPROXY_TIMEOUT_CONNECT"],
            timeout_client=os.environ["HAPROXY_TIMEOUT_CLIENT"],
            timeout_server=os.environ["HAPROXY_TIMEOUT_SERVER"],
            retries=os.environ["HAPROXY_RETRIES"],
            maxconn=os.environ["HAPROXY_MAXCONN"]
        )

        with open(self.config, "w") as f:
            f.write(config)

    def start(self):

        self.process = subprocess.Popen(args=[
            "haproxy",
            "-f", self.config,
            "-p", self.pid_file,  # PID
            "-sf", self._read_file(self.pid_file),

        ])

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
    # haproxyadmin.haproxy.HAProxy()
    haproxy = HAProxy()
    tor_instances = [Tor().start() for c in range(int(os.environ["TOR_INSTANCES"]))]
    wait_for(tor_instances)

    for tor_instance in tor_instances:
        haproxy.add_proxy("127.0.0.1", tor_instance.port)

    haproxy.generate_config()
    haproxy.start()
    while True:
        time.sleep(5)
