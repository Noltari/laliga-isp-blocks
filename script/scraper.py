"""La Liga Gate scraper."""

from datetime import datetime
import ipaddress
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
import json
import logging
import optparse
import os
import paramiko
import re
from typing import Any, Final

import requests

DATA: Final[str] = "data"
DESCRIPTION: Final[str] = "description"
IP: Final[str] = "ip"
ISP: Final[str] = "isp"
LAST_UPDATE: Final[str] = "lastUpdate"
STATE: Final[str] = "state"
TIMESTAMP: Final[str] = "timestamp"

HTTP_TIMEOUT: Final[float] = 45.0

OPENWRT_INTERFACE: Final[str] = "cloudflare"
OPENWRT_METRIC: Final[int] = 256
OPENWRT_ROUTE4_RE = re.compile(r"^network.@route\[[0-9]+\]")
OPENWRT_ROUTE6_RE = re.compile(r"^network.@route6\[[0-9]+\]")

OPT_ARGS: list[str]
OPT_OPTS: optparse.Values


_LOGGER = logging.getLogger(__name__)


class LaLigaIP:
    """LaLigaIP class."""

    def __init__(self, data: dict[str, Any]) -> None:
        """LaLigaIP class init."""
        ip = data.get(IP, "")
        self.addr = ipaddress.ip_address(ip)

        self.isp: list[str] = []

        self.update(data)

    def update(self, data: dict[str, Any]) -> None:
        """LaLigaIP class update."""
        isp = data.get(ISP)
        if isp is not None:
            if isp not in self.isp:
                self.isp.append(isp)


class LaLigaGate:
    """LaLigaGate class."""

    def __init__(self) -> None:
        """LaLigaGate class init."""
        self.ipv4_list: list[IPv4Address] = []
        self.ipv6_list: list[IPv6Address] = []
        self.last_update: datetime | None = None

    def update_local(self, json_data: dict[str, Any]):
        """LaLigaGate update from local data."""
        last_update = json_data.get("last_update")
        if last_update is not None:
            self.last_update = datetime.strptime(last_update, "%Y-%m-%d %H:%M:%S")

        ipv4_list = json_data.get("ipv4_list", [])
        for ipv4 in ipv4_list:
            self.ipv4_list.append(IPv4Address(ipv4))

        ipv6_list = json_data.get("ipv6_list", [])
        for ipv6 in ipv6_list:
            self.ipv6_list.append(IPv6Address(ipv6))

        self.ipv4_list.sort()
        self.ipv6_list.sort()

    def update_sources(self, json_data: dict[str, Any]):
        """LaLigaGate update from sources."""
        last_update = json_data.get(LAST_UPDATE)
        if last_update is not None:
            self.last_update = datetime.strptime(last_update, "%Y-%m-%d %H:%M:%S")

        data: list[dict[str, Any]] = json_data.get(DATA, [])
        if len(data) < 1:
            return

        ip_list: dict[str, LaLigaIP] = {}
        for cur_data in data:
            cur_ip = LaLigaIP(cur_data)

            if not cur_ip.addr.is_global:
                _LOGGER.error("IP address must be global!")
                continue

            cur_addr = str(cur_ip.addr)
            if cur_addr not in ip_list:
                ip_list[cur_addr] = cur_ip
            else:
                ip_list[cur_addr].update(cur_data)

        for cur_ip in ip_list.values():
            cur_ip_addr = cur_ip.addr
            if cur_ip_addr.version == 4:
                if cur_ip_addr not in self.ipv4_list:
                    self.ipv4_list.append(cur_ip_addr)
            elif cur_ip_addr.version == 6:
                if cur_ip_addr not in self.ipv6_list:
                    self.ipv6_list.append(cur_ip_addr)

        self.ipv4_list.sort()
        self.ipv6_list.sort()


class OpenWrtRoute:
    """OpenWrt Route class."""

    def __init__(self, ip: type) -> None:
        """OpenWrt Route class init."""
        self.interface: str | None = None
        self.ip: type = ip
        self.metric: int | None = None
        self.target: IPv4Network | IPv6Network | None = None

    def get_ip(self) -> IPv4Address | IPv6Address | None:
        """Get route IP address."""
        if self.target is not None:
            return self.target.network_address
        return None

    def get_target(self) -> str:
        """Get route target."""
        return str(self.target)

    def is_ipv4(self) -> bool:
        """Route is IPv4."""
        return self.ip == IPv4Network

    def is_ipv6(self) -> bool:
        """Route is IPv6."""
        return self.ip == IPv6Network

    def set_uci_value(self, value: str) -> None:
        """Set UCI value."""
        value = value.lstrip().rstrip()

        if value.startswith(".interface="):
            interface = value.removeprefix(".interface=")
            interface = interface.removeprefix("'").removesuffix("'")
            self.interface = interface
        if value.startswith(".metric="):
            metric = value.removeprefix(".metric=")
            metric = metric.removeprefix("'").removesuffix("'")
            self.metric = int(metric)
        elif value.startswith(".target="):
            target = value.removeprefix(".target=")
            target = target.removeprefix("'").removesuffix("'")
            if self.ip == IPv4Network:
                self.target = IPv4Network(target)
            elif self.ip == IPv6Network:
                self.target = IPv6Network(target)

    def __str__(self) -> str:
        """Return class string."""
        data = {
            "interface": self.interface,
            "ip": self.ip.__name__,
            "metric": self.metric,
            "target": str(self.target),
        }
        return str(data)


def openwrt(laliga: LaLigaGate) -> None:
    """OpenWrt function."""
    line: str

    hostname = OPT_OPTS.openwrt
    if hostname is None:
        return

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.connect(
        hostname=hostname,
        username="root",
    )

    stdin, stdout, stderr = ssh.exec_command("uci show network")
    routes_v4: list[OpenWrtRoute] = []
    routes_v6: list[OpenWrtRoute] = []
    cur_route: OpenWrtRoute
    for line in stdout:
        val = None

        if OPENWRT_ROUTE4_RE.match(line):
            val = OPENWRT_ROUTE4_RE.split(line)[1]
            if val.startswith("=route"):
                cur_route = OpenWrtRoute(IPv4Network)
                routes_v4.append(cur_route)
                val = None
        elif OPENWRT_ROUTE6_RE.match(line):
            val = OPENWRT_ROUTE6_RE.split(line)[1]
            if val.startswith("=route6"):
                cur_route = OpenWrtRoute(IPv6Network)
                routes_v6.append(cur_route)
                val = None

        if val is not None:
            cur_route.set_uci_value(val)

    routes: dict[str, OpenWrtRoute] = {}
    for route in routes_v4:
        route_ip = str(route.get_ip())
        routes[route_ip] = route
    for route in routes_v6:
        route_ip = str(route.get_ip())
        routes[route_ip] = route

    new_routes = False
    for ipv4 in laliga.ipv4_list:
        ipv4_str = str(ipv4)
        if ipv4_str not in routes:
            new_routes += 1
            uci = "uci batch << EOI\n"
            uci += "add network route\n"
            uci += f"set network.@route[-1].interface='{OPENWRT_INTERFACE}'\n"
            uci += f"set network.@route[-1].target='{ipv4_str}/32'\n"
            uci += f"set network.@route[-1].metric='{OPENWRT_METRIC}'\n"
            uci += "EOI"
            ssh.exec_command(uci)
    for ipv6 in laliga.ipv6_list:
        ipv6_str = str(ipv6)
        if ipv6_str not in routes:
            new_routes += 1
            uci = "uci batch << EOI\n"
            uci += "add network route6\n"
            uci += f"set network.@route6[-1].interface='{OPENWRT_INTERFACE}'\n"
            uci += f"set network.@route6[-1].target='{ipv6_str}/128'\n"
            uci += f"set network.@route6[-1].metric='{OPENWRT_METRIC}'\n"
            uci += "EOI"
            ssh.exec_command(uci)

    if new_routes > 0:
        ssh.exec_command("uci commit network")
        ssh.exec_command("reload_config")
        _LOGGER.warning("OpenWrt: added %s new routes", new_routes)

    ssh.close()


def scraper() -> LaLigaGate:
    """Scraper function."""
    base_dir = os.path.abspath(os.path.dirname(__file__) + os.path.sep + os.path.pardir)
    data_dir = os.path.abspath(base_dir + os.path.sep + "data")
    json_list_fn = os.path.abspath(data_dir + os.path.sep + "laliga-ip-list.json")

    laliga = LaLigaGate()

    with open(json_list_fn, mode="r") as json_list:
        json_data = json.load(json_list)
        laliga.update_local(json_data)

    url = "https://hayahora.futbol/estado/data.json"
    response: requests.Response = requests.get(url, timeout=HTTP_TIMEOUT)
    data = response.json()
    laliga.update_sources(data)

    with open(json_list_fn, mode="w", encoding="utf-8") as json_list:
        json_data = json.dumps(
            laliga.__dict__,
            indent=4,
            sort_keys=True,
            default=str,
        )
        json_list.write(json_data)
        json_list.write("\n")

    openwrt_routes_fn = os.path.abspath(
        data_dir + os.path.sep + "laliga-openwrt-routes.config"
    )
    with open(openwrt_routes_fn, mode="w", encoding="utf-8") as openwrt_routes:
        for cur_ipv4 in laliga.ipv4_list:
            cur_route = [
                "config route\n",
                f"\toption interface '{OPENWRT_INTERFACE}'\n",
                f"\toption target '{cur_ipv4}/32'\n",
                f"\toption metric '{OPENWRT_METRIC}'\n",
                "\n",
            ]
            openwrt_routes.writelines(cur_route)

        for cur_ipv6 in laliga.ipv6_list:
            cur_route = [
                "config route6\n",
                f"\toption interface '{OPENWRT_INTERFACE}'\n",
                f"\toption target '{cur_ipv6}/128'\n",
                f"option metric '{OPENWRT_METRIC}'\n",
                "\n",
            ]
            openwrt_routes.writelines(cur_route)

    return laliga


def main() -> None:
    """Entry function."""
    global OPT_OPTS, OPT_ARGS

    parser = optparse.OptionParser()
    parser.add_option("-o", "--openwrt")
    OPT_OPTS, OPT_ARGS = parser.parse_args()

    laliga = scraper()
    openwrt(laliga)


if __name__ == "__main__":
    main()
