# pia-wg Working fork 

The original project got archived when it stopped working so I updated it for current compatibility and it works as of (05/2026)


A WireGuard configuration utility for Private Internet Access.

This fork generates a Windows-importable WireGuard config while keeping TLS verification enabled. It no longer uses `requests_toolbelt` or the old Python `HostHeaderSSLAdapter`.

PIA's current official manual connection scripts get the account token from:

```
https://www.privateinternetaccess.com/api/client/v2/token
```

This fork follows that model. The token request is not region-specific. The selected region is used only for the WireGuard `addKey` call, which is the call that chooses the server and tunnel endpoint.

For the WireGuard API on Linux/macOS, this fork uses curl `--connect-to` so TLS verifies the real PIA server hostname while connecting to the specific server IP from PIA's live server list:

```
curl --connect-to "<wg_cn>:1337:<wg_ip>:1337" \
     --cacert ca.rsa.4096.crt \
     "https://<wg_cn>:1337/addKey?pt=<token>&pubkey=<publickey>"
```

On Windows, the built-in Schannel curl can reject PIA's private CA or revocation status even when `--cacert` is supplied. To avoid that noisy path during normal use, this fork uses Python/OpenSSL first for the selected WireGuard endpoint, with the same TCP target IP, SNI hostname, and bundled PIA CA verification. curl remains available as a fallback. It does not use `verify=False`.

The token request uses Python `requests` against PIA's public token endpoint so the PIA password is not placed in a curl command line.

## Configuration
Create a `.env` file in this directory:

```
PIA_user=your_pia_username
PIA_pass=your_pia_password
region=your_pia_server_region
```

`region` must match a PIA region name from the live server list. A unique partial name such as `Montana` can also work when it matches only one region.

No `.env` file is included in this clean fork.

## Windows
Install Python 3 and WireGuard, then run:

```
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe generate-config.py
```

The script writes `PIA-wg.conf`, which can be imported into WireGuard for Windows.

## Linux
Install dependencies, then run:

```
sudo apt install curl python3-venv wireguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 generate-config.py
```

## Server List
The script fetches PIA's live server list from:

```
https://serverlist.piaservers.net/vpninfo/servers/v6
```

The bundled `piaservers_v6.json` is only a fallback cache if the live list cannot be fetched. Each successful live fetch updates that cache atomically. To refresh it manually, download the first JSON line from the same URL and save it as `piaservers_v6.json`.

See `NOTES.md` for implementation notes and fork maintenance details.

## Troubleshooting
If `curl not found` appears, install curl or ensure it is on PATH. Modern Windows 10/11 installs include `curl.exe` by default.

If login fails, confirm `PIA_user` and `PIA_pass`. The password and token are not logged or written to the generated config.

If all WireGuard endpoints fail for the selected region, the script fails instead of using another region. That is intentional: the generated config should represent the selected location.

If certificate errors occur, refresh `ca.rsa.4096.crt` from PIA's official manual-connections repo.

The script also refreshes `ca.rsa.4096.crt` automatically from PIA's official manual-connections repo when the local copy is older than 183 days, or after all selected WireGuard endpoints fail with certificate-side errors. If that refresh fails, the current local certificate remains in use.

Do not use `verify=False`.
