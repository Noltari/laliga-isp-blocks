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
STATE_CHANGES: Final[str] = "stateChanges"
TIMESTAMP: Final[str] = "timestamp"

HTTP_TIMEOUT: Final[float] = 45.0

OPENWRT_INTERFACE: Final[str] = "cloudflare"
OPENWRT_METRIC: Final[int] = 256

OPENWRT_ROUTE4_IDX_RE = re.compile(r"^network.@route\[([0-9]+)\]")
OPENWRT_ROUTE6_IDX_RE = re.compile(r"^network.@route6\[([0-9]+)\]")
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

        self.isp: dict[str, bool] = {}

        self.update(data)

    def is_blocked(self) -> bool:
        """LaLigaIP check any ISP block."""
        for blocked in self.isp.values():
            if blocked:
                return True
        return False

    def is_isp_blocked(self, isp: str) -> bool:
        """LaLigaIP check ISP block."""
        return self.isp.get(isp, False)

    def is_isp(self, isp: str) -> bool:
        """LaLigaIP check ISP."""
        return isp.lower() in self.isp

    def update(self, data: dict[str, Any]) -> None:
        """LaLigaIP class update."""
        isp: str | None = data.get(ISP)
        if isp is not None:
            isp = isp.lower()
            if isp not in self.isp:
                state_changes = data.get(STATE_CHANGES, [])
                blocked = False
                ts = None
                for cur_state in state_changes:
                    cur_ts_str = cur_state.get(TIMESTAMP, None)
                    if cur_ts_str is not None:
                        cur_ts = datetime.fromisoformat(cur_ts_str)
                        if ts is None or cur_ts > ts:
                            ts = cur_ts
                            blocked = cur_state.get(STATE)
                self.isp[isp] = blocked


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

        arg_blocked = OPT_OPTS.blocked
        arg_isp: str | None = OPT_OPTS.isp

        check_blocked = arg_blocked is not None and arg_blocked
        check_isp = arg_isp is not None

        if check_isp:
            arg_isp = arg_isp.lower()

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

        new_ips = 0
        for cur_ip in ip_list.values():
            cur_ip_addr = cur_ip.addr

            add_ip = True
            if check_blocked and check_isp:
                add_ip = cur_ip.is_isp_blocked(arg_isp)
            elif check_blocked:
                add_ip = cur_ip.is_blocked()
            elif check_isp:
                add_ip = cur_ip.is_isp(arg_isp)

            if not add_ip:
                continue

            if cur_ip_addr.version == 4:
                if cur_ip_addr not in self.ipv4_list:
                    new_ips += 1
                    self.ipv4_list.append(cur_ip_addr)
                    _LOGGER.warning("update_sources: new IPv4 -> %s", cur_ip_addr)
            elif cur_ip_addr.version == 6:
                if cur_ip_addr not in self.ipv6_list:
                    new_ips += 1
                    self.ipv6_list.append(cur_ip_addr)
                    _LOGGER.warning("update_sources: new IPv6 -> %s", cur_ip_addr)
        if new_ips > 0:
            _LOGGER.warning("update_sources: added %s new IPs", new_ips)

        rem_ips = 0
        if arg_blocked:
            isp_list: dict[str, LaLigaIP] = {}
            for key, val in ip_list.items():
                for isp, blocked in val.isp.items():
                    if blocked:
                        isp_list[key] = val
                        continue

            blocked_ipv4: list[IPv4Address] = []
            for cur_ipv4 in self.ipv4_list:
                if str(cur_ipv4) in isp_list:
                    blocked_ipv4.append(cur_ipv4)
                else:
                    rem_ips += 1
            self.ipv4_list = blocked_ipv4

            blocked_ipv6: list[IPv6Address] = []
            for cur_ipv6 in self.ipv6_list:
                if str(cur_ipv6) in isp_list:
                    blocked_ipv6.append(cur_ipv6)
                else:
                    rem_ips += 1
            self.ipv6_list = blocked_ipv6
        if arg_isp is not None:
            isp_list: dict[str, LaLigaIP] = {}
            for key, val in ip_list.items():
                if arg_isp in val.isp:
                    isp_list[key] = val

            isp_ipv4: list[IPv4Address] = []
            for cur_ipv4 in self.ipv4_list:
                if str(cur_ipv4) in isp_list:
                    isp_ipv4.append(cur_ipv4)
                else:
                    rem_ips += 1
            self.ipv4_list = isp_ipv4

            isp_ipv6: list[IPv6Address] = []
            for cur_ipv6 in self.ipv6_list:
                if str(cur_ipv6) in isp_list:
                    isp_ipv6.append(cur_ipv6)
                else:
                    rem_ips += 1
            self.ipv6_list = isp_ipv6
        if rem_ips > 0:
            _LOGGER.warning("update_sources: removed %s IPs", rem_ips)

        self.ipv4_list.sort()
        self.ipv6_list.sort()


class OpenWrtRoute:
    """OpenWrt Route class."""

    def __init__(self, ip: type, index: int) -> None:
        """OpenWrt Route class init."""
        self.index: int = index
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

    def is_laliga(self) -> bool:
        """Route is blocked."""
        return self.interface == OPENWRT_INTERFACE and self.metric == OPENWRT_METRIC

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
            "index": self.index,
            "interface": self.interface,
            "ip": self.ip.__name__,
            "metric": self.metric,
            "target": str(self.target),
        }
        return str(data)


def openwrt_routes_add(laliga: LaLigaGate, ssh: paramiko.SSHClient) -> None:
    """OpenWrt add routes."""
    routes: dict[str, OpenWrtRoute] = {}
    routes_v4, routes_v6 = openwrt_routes_get(ssh)

    for route in routes_v4:
        route_ip = str(route.get_ip())
        routes[route_ip] = route
    for route in routes_v6:
        route_ip = str(route.get_ip())
        routes[route_ip] = route

    new_routes = 0
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
            _LOGGER.warning("openwrt_add: new IPv4 -> %s", ipv4_str)
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
            _LOGGER.warning("openwrt_add: new IPv6 -> %s", ipv6_str)
            ssh.exec_command(uci)

    if new_routes > 0:
        ssh.exec_command("uci commit network")
        ssh.exec_command("reload_config")
        _LOGGER.warning("OpenWrt: added %s new routes", new_routes)


def openwrt_routes_get(
    ssh: paramiko.SSHClient,
) -> tuple[list[OpenWrtRoute], list[OpenWrtRoute]]:
    """OpenWrt get routes."""
    stdin, stdout, stderr = ssh.exec_command("uci show network")
    routes_v4: list[OpenWrtRoute] = []
    routes_v6: list[OpenWrtRoute] = []
    cur_route: OpenWrtRoute
    for line in stdout:
        val = None

        if OPENWRT_ROUTE4_RE.match(line):
            val = OPENWRT_ROUTE4_RE.split(line)[1]
            if val.startswith("=route"):
                route_idx = OPENWRT_ROUTE4_IDX_RE.match(line).group(1)
                cur_route = OpenWrtRoute(IPv4Network, route_idx)
                routes_v4.append(cur_route)
                val = None
        elif OPENWRT_ROUTE6_RE.match(line):
            val = OPENWRT_ROUTE6_RE.split(line)[1]
            if val.startswith("=route6"):
                route_idx = OPENWRT_ROUTE6_IDX_RE.match(line).group(1)
                cur_route = OpenWrtRoute(IPv6Network, route_idx)
                routes_v6.append(cur_route)
                val = None

        if val is not None:
            cur_route.set_uci_value(val)

    return routes_v4, routes_v6


def openwrt_routes_rem(laliga: LaLigaGate, ssh: paramiko.SSHClient) -> None:
    """OpenWrt add routes."""
    routes_v4, routes_v6 = openwrt_routes_get(ssh)

    rem_routes = 0
    for route in reversed(routes_v4):
        if not route.is_laliga():
            continue

        route_ip = route.get_ip()
        if route_ip not in laliga.ipv4_list:
            rem_routes += 1
            uci = f"uci delete network.@route[{route.index}]\n"
            _LOGGER.warning("openwrt_remove: removed IPv4 -> %s", route_ip)
            ssh.exec_command(uci)
    for route in reversed(routes_v6):
        if not route.is_laliga():
            continue

        route_ip = route.get_ip()
        if route_ip not in laliga.ipv6_list:
            rem_routes += 1
            uci = f"uci delete network.@route6[{route.index}]\n"
            _LOGGER.warning("openwrt_remove: removed IPv6 -> %s", route_ip)
            ssh.exec_command(uci)

    if rem_routes > 0:
        ssh.exec_command("uci commit network")
        ssh.exec_command("reload_config")
        _LOGGER.warning("OpenWrt: removed %s routes", rem_routes)


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

    openwrt_routes_rem(laliga, ssh)
    openwrt_routes_add(laliga, ssh)

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
    parser.add_option("--blocked", action="store_true")
    parser.add_option("--isp")
    parser.add_option("-o", "--openwrt")
    OPT_OPTS, OPT_ARGS = parser.parse_args()

    laliga = scraper()
    openwrt(laliga)


if __name__ == "__main__":
    main()
