# LaLigaGate scraper

Python scripts that generate IP address lists and OpenWrt configurations for
LaLigaGate ISP blocks.

## Usage

### Fetch latest data

```bash
python script/scraper.py
```

### Fetch latest data and update OpenWrt device

Warning: you must use `ssh-copy-id` for the OpenWrt device before running the following command.

```bash
python script/scraper.py -o openwrt.hostname
```

## Data files

| File                          | Description                 |
| ----------------------------- | --------------------------- |
| laliga-ip-list.json           | Local list of blocked IPs.  |
| laliga-openwrt-routes.config  | OpenWrt routes config.      |

## Sources

https://hayahora.futbol/
