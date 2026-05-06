## What Changed

The original archived project used `requests_toolbelt.adapters.host_header_ssl.HostHeaderSSLAdapter` to connect to a raw PIA server IP while sending a different `Host` header. That approach is fragile with modern TLS stacks and current PIA certificates.

This fork removes `requests-toolbelt` and keeps TLS verification enabled.

Token generation now follows PIA's current official manual connection scripts:

```
https://www.privateinternetaccess.com/api/client/v2/token
```

That token endpoint is account authentication, not region selection. The selected region is enforced by the later WireGuard `addKey` request.

WireGuard `addKey` calls use curl `--connect-to` on Linux/macOS:

```
curl --connect-to "<wg_cn>:1337:<wg_ip>:1337" \
     --cacert ca.rsa.4096.crt \
     "https://<wg_cn>:1337/addKey?pt=<token>&pubkey=<publickey>"
```

This lets TLS verify the actual PIA hostname while the TCP connection goes to the selected IP from the live server list.

On Windows, the code uses Python/OpenSSL first for `addKey` because Schannel curl predictably rejects PIA's private CA or revocation status on some systems. The Python/OpenSSL transport preserves the same security property: TCP connects to the selected IP, SNI and hostname verification use the selected PIA hostname, and verification uses `ca.rsa.4096.crt`.

## Windows TLS Behavior

Windows' built-in curl usually uses Schannel. Schannel can reject PIA's private CA or revocation status even when `--cacert ca.rsa.4096.crt` is supplied.

The normal Windows path therefore uses Python/OpenSSL directly for the same selected WireGuard endpoint:

1. TCP connects to the selected server IP.
2. TLS uses `server_hostname=<wg_cn>` for SNI and hostname verification.
3. Verification uses the bundled `ca.rsa.4096.crt`.
4. The HTTP `Host` header remains the selected PIA hostname.

This fallback is not `verify=False`; certificate verification remains required.

If Python/OpenSSL fails on Windows, curl is tried as a diagnostic fallback. If a log line includes both Python/OpenSSL and curl failures, generation did not succeed for that endpoint.

That expected Windows curl failure does not refresh the CA by itself. The CA is refreshed only if all selected WireGuard endpoints fail after their verification attempts.

## Region Guarantee

The fork does not fall back to another region for WireGuard server selection.

For a selected region such as `US Miami`, `addKey` only tries that region's `servers.wg` entries. If all selected-region WireGuard endpoints fail, the script fails cleanly rather than generating a config for another location.

## Server List Cache

The script prefers PIA's live server list:

```
https://serverlist.piaservers.net/vpninfo/servers/v6
```

The bundled `piaservers_v6.json` is a fallback only. Each successful live fetch refreshes that file atomically, so the fallback stays current during normal use.

## Files

- `piawg.py`: API, TLS, server-list, region, key, and WireGuard registration logic.
- `generate-config.py`: CLI entry point, `.env` loading, prompts, and `PIA-wg.conf` writing.
- `ca.rsa.4096.crt`: PIA CA certificate from `pia-foss/manual-connections`.
- `piaservers_v6.json`: bundled fallback cache for the PIA server list.
- `requirements.txt`: Python dependencies.
- `README.md`: user setup and troubleshooting.

## Security Notes

- The PIA password is not printed.
- The PIA password is sent with Python `requests`, not curl command-line arguments.
- The token is not printed.
- Credentials are not written to `PIA-wg.conf`.
- TLS verification is not disabled.
- `.env` and generated `PIA-*` configs are git-ignored.

## CA Certificate Refresh

The local `ca.rsa.4096.crt` is refreshed from:

```
https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt
```

Refresh happens when either condition is true:

- The local certificate file is older than 183 days.
- Every selected WireGuard endpoint fails with a certificate-side error.

The refresh is conservative. The downloaded file must parse as a PEM certificate and its subject must contain `Private Internet Access`. It is written to a temporary file first, then atomically replaces the current CA. If download or validation fails, the existing CA file remains in use.
