"""La Liga Gate scraper."""

from datetime import datetime
import ipaddress
from ipaddress import IPv4Address, IPv6Address
import json
import logging
import os
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


_LOGGER = logging.getLogger(__name__)


class LaLigaIP:
    """LaLigaIP class."""

    def __init__(self, data: dict[str, Any]):
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

    def __init__(self):
        """LaLigaGate class init."""
        self.ipv4_list: list[IPv4Address] = []
        self.ipv6_list: list[IPv6Address] = []
        self.last_update: datetime | None = None

    def update_local(self, json_data: dict[str, Any]):
        """LaLigaGate update from local data."""
        last_update = json_data.get("last_update")
        if last_update is not None:
            self.last_update = datetime.strptime(last_update, "%Y-%m-%d %H:%M:%S")

        ipv4_list = json_data.get("ipv4_list")
        for ipv4 in ipv4_list:
            self.ipv4_list.append(IPv4Address(ipv4))

        ipv6_list = json_data.get("ipv6_list")
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


def main() -> None:
    """Screaper entry function."""
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


if __name__ == "__main__":
    main()
