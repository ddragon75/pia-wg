import json
import http.client
import os
from pathlib import Path
import requests
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse

BASE_DIR = Path(__file__).resolve().parent
PIA_CA = BASE_DIR / "ca.rsa.4096.crt"
PIA_CA_URL = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"
PIA_CA_MAX_AGE_SECONDS = 183 * 24 * 60 * 60
SERVER_LIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
SERVER_LIST_CACHE = BASE_DIR / "piaservers_v6.json"
TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
HTTP_STATUS_MARKER = "__PIA_HTTP_STATUS__:"


class piawg:
    def __init__(self):
        self.server_list = {}
        self.curl = self._find_curl()
        self.region = None
        self.token = None
        self.publickey = None
        self.privatekey = None
        self.connection = None
        self._ca_age_refresh_checked = False
        self._ca_all_routes_refresh_checked = False
        self.get_server_list()

    @staticmethod
    def _find_curl():
        curl = shutil.which("curl.exe") or shutil.which("curl")
        if not curl:
            raise RuntimeError(
                "curl is required for PIA API calls. Install curl or ensure it is on PATH."
            )
        return curl

    @staticmethod
    def _find_wg():
        wg = shutil.which("wg.exe") or shutil.which("wg")
        if not wg:
            raise RuntimeError(
                "WireGuard's wg executable was not found. Install WireGuard and ensure wg is on PATH."
            )
        return wg

    @staticmethod
    def _brief(value, max_len=500):
        text = " ".join(str(value).split())
        if len(text) > max_len:
            return text[:max_len] + "..."
        return text

    @staticmethod
    def _response_message(data):
        if not isinstance(data, dict):
            return "unexpected response"
        return data.get("message") or data.get("error") or data.get("status") or "unexpected response"

    def _ensure_ca(self, refresh_if_old=True):
        if not PIA_CA.exists():
            self._refresh_ca("missing CA certificate")

        if refresh_if_old and not self._ca_age_refresh_checked and PIA_CA.exists():
            self._ca_age_refresh_checked = True
            age_seconds = time.time() - PIA_CA.stat().st_mtime
            if age_seconds > PIA_CA_MAX_AGE_SECONDS:
                self._refresh_ca("CA certificate is older than 183 days")

        if not PIA_CA.exists():
            raise RuntimeError(
                "PIA CA certificate not found at {}. Refresh ca.rsa.4096.crt from "
                "PIA's official manual-connections repository.".format(PIA_CA)
            )

    def _refresh_ca(self, reason):
        tmp_path = PIA_CA.with_name("{}.{}.tmp".format(PIA_CA.name, os.getpid()))
        try:
            r = requests.get(PIA_CA_URL, timeout=30)
            r.raise_for_status()
            text = r.text.strip() + "\n"
            if "-----BEGIN CERTIFICATE-----" not in text or "-----END CERTIFICATE-----" not in text:
                raise RuntimeError("downloaded file is not a PEM certificate")

            tmp_path.write_text(text, encoding="ascii")
            self._validate_pia_ca(tmp_path)
            tmp_path.replace(PIA_CA)
            print("Refreshed PIA CA certificate because {}.".format(reason))
            return True
        except Exception as exc:
            print(
                "Could not refresh PIA CA certificate after {}; continuing with existing file if available: {}".format(
                    reason, self._brief(exc)
                )
            )
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    @staticmethod
    def _validate_pia_ca(path):
        info = ssl._ssl._test_decode_cert(str(path))
        subject_values = [
            value
            for relative_name in info.get("subject", ())
            for _key, value in relative_name
        ]
        if "Private Internet Access" not in subject_values:
            raise RuntimeError(
                "downloaded certificate subject was not Private Internet Access"
            )

    def get_server_list(self):
        try:
            r = requests.get(SERVER_LIST_URL, timeout=30)
            r.raise_for_status()
            data = json.loads(r.text.splitlines()[0])
            self._validate_server_list_data(data)
            self._write_server_list_cache(data)
        except Exception as exc:
            if not SERVER_LIST_CACHE.exists():
                raise RuntimeError(
                    "Could not fetch PIA server list and no bundled piaservers_v6.json "
                    "cache is available: {}".format(exc)
                ) from exc
            print(
                "Could not fetch live PIA server list; using bundled piaservers_v6.json cache."
            )
            try:
                data = json.loads(SERVER_LIST_CACHE.read_text(encoding="utf-8"))
                self._validate_server_list_data(data)
            except Exception as cache_exc:
                raise RuntimeError(
                    "Could not load bundled piaservers_v6.json cache: {}".format(cache_exc)
                ) from exc

        self.server_list = {server["name"]: server for server in data["regions"]}
        if not self.server_list:
            raise RuntimeError("PIA server list did not contain any regions.")

    @staticmethod
    def _validate_server_list_data(data):
        if not isinstance(data, dict) or not isinstance(data.get("regions"), list):
            raise RuntimeError("PIA server list JSON did not contain a regions list.")
        for server in data["regions"]:
            if not isinstance(server, dict) or "name" not in server:
                raise RuntimeError("PIA server list contained an invalid region entry.")

    def _write_server_list_cache(self, data):
        tmp_path = SERVER_LIST_CACHE.with_name(
            "{}.{}.tmp".format(SERVER_LIST_CACHE.name, os.getpid())
        )
        cache_text = json.dumps(data, indent=2, sort_keys=True) + "\n"
        try:
            if SERVER_LIST_CACHE.exists() and SERVER_LIST_CACHE.read_text(
                encoding="utf-8"
            ) == cache_text:
                return
        except OSError:
            pass

        last_error = None
        for attempt in range(3):
            try:
                tmp_path.write_text(cache_text, encoding="utf-8")
                tmp_path.replace(SERVER_LIST_CACHE)
                return
            except OSError as exc:
                last_error = exc
                try:
                    if SERVER_LIST_CACHE.exists() and SERVER_LIST_CACHE.read_text(
                        encoding="utf-8"
                    ) == cache_text:
                        try:
                            tmp_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                        return
                except OSError:
                    pass
                time.sleep(0.1 * (attempt + 1))

        print(
            "Fetched live PIA server list, but could not update piaservers_v6.json: {}".format(
                self._brief(last_error)
            )
        )
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass

    def set_region(self, region_name):
        if region_name is None:
            raise ValueError("No PIA region was provided.")

        region_name = str(region_name).strip().strip('"').strip("'")
        if not region_name:
            raise ValueError("No PIA region was provided.")

        if region_name in self.server_list:
            self.region = region_name
            return

        lower_names = {name.lower(): name for name in self.server_list}
        if region_name.lower() in lower_names:
            self.region = lower_names[region_name.lower()]
            return

        needle = region_name.lower()
        partial_matches = [
            name for name in self.server_list
            if name.lower().endswith(" " + needle) or needle in name.lower()
        ]
        if len(partial_matches) == 1:
            self.region = partial_matches[0]
            return

        import difflib
        suggestions = partial_matches[:8] or difflib.get_close_matches(
            region_name, sorted(self.server_list.keys()), n=8, cutoff=0.3
        )
        if suggestions:
            raise ValueError(
                "Unknown PIA region '{}'. Did you mean one of these? {}".format(
                    region_name, ", ".join(suggestions)
                )
            )
        raise ValueError(
            "Unknown PIA region '{}'. Available regions include: {}".format(
                region_name, ", ".join(sorted(self.server_list.keys())[:20])
            )
        )

    def _region_servers(self, server_type):
        if not self.region:
            raise RuntimeError("No PIA region selected.")

        servers = self.server_list[self.region].get("servers", {}).get(server_type, [])
        if not servers:
            raise RuntimeError(
                "PIA region '{}' does not list any {} servers.".format(self.region, server_type)
            )
        return servers

    def _curl_json(self, args, timeout=20):
        command = [
            self.curl,
            "-sS",
            "--write-out",
            "\n{}%{{http_code}}".format(HTTP_STATUS_MARKER),
        ] + args

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("curl timed out after {} seconds".format(timeout)) from exc

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        body = stdout
        http_status = None
        if HTTP_STATUS_MARKER in stdout:
            body, status_text = stdout.rsplit(HTTP_STATUS_MARKER, 1)
            status_text = status_text.strip().splitlines()[0] if status_text.strip() else ""
            if status_text.isdigit():
                http_status = int(status_text)

        body = body.strip()
        if result.returncode != 0:
            details = self._brief(stderr or body or "no error output")
            raise RuntimeError("curl exited with code {}: {}".format(result.returncode, details))

        if not body:
            if http_status is not None and not 200 <= http_status < 300:
                details = self._brief(stderr or "no response body")
                raise RuntimeError("HTTP {} from PIA endpoint: {}".format(http_status, details))
            raise RuntimeError("PIA endpoint returned an empty response body")

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            if http_status is not None and not 200 <= http_status < 300:
                raise RuntimeError(
                    "HTTP {} from PIA endpoint: {}".format(http_status, self._brief(body))
                ) from exc
            raise RuntimeError("PIA endpoint returned invalid JSON: {}".format(self._brief(body))) from exc

        if http_status is not None and not 200 <= http_status < 300:
            if isinstance(data, dict):
                data["_http_status"] = http_status
                return data
            details = self._brief(body or stderr or "no response body")
            raise RuntimeError("HTTP {} from PIA endpoint: {}".format(http_status, details))

        return data

    def _request_token(self, username, password):
        try:
            r = requests.post(
                TOKEN_URL,
                data={"username": username, "password": password},
                headers={"Accept": "application/json"},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise RuntimeError("PIA token request failed: {}".format(self._brief(exc))) from exc

        body = r.text.strip()
        try:
            data = r.json() if body else {}
        except ValueError as exc:
            if not r.ok:
                raise RuntimeError(
                    "HTTP {} from PIA token endpoint: {}".format(
                        r.status_code, self._brief(body or r.reason)
                    )
                ) from exc
            raise RuntimeError(
                "PIA token endpoint returned invalid JSON: {}".format(self._brief(body))
            ) from exc

        if not r.ok:
            data["_http_status"] = r.status_code
            data["_http_body"] = body

        return data

    def _curl_pia_get(self, hostname, ip, port, path, timeout=20):
        self._ensure_ca()
        url_host = hostname if port == 443 else "{}:{}".format(hostname, port)
        args = [
            "--connect-timeout",
            "5",
            "--connect-to",
            "{}:{}:{}:{}".format(hostname, port, ip, port),
            "--cacert",
            str(PIA_CA),
            "https://{}{}".format(url_host, path),
        ]
        return self._curl_json(args, timeout=timeout)

    @staticmethod
    def _should_retry_with_python_tls(error):
        message = str(error).lower()
        return (
            "curl exited with code 60" in message
            or "schannel" in message
            or "certificate" in message
            or "tls verification" in message
            or "sslcertverificationerror" in message
        )

    def _python_tls_pia_get(self, hostname, ip, port, path, timeout=20):
        self._ensure_ca()
        context = ssl.create_default_context(cafile=str(PIA_CA))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        host_header = hostname if port == 443 else "{}:{}".format(hostname, port)
        headers = [
            "GET {} HTTP/1.1".format(path),
            "Host: {}".format(host_header),
            "Accept: application/json",
            "Connection: close",
            "User-Agent: pia-wg/modernized",
        ]
        request = "\r\n".join(headers) + "\r\n\r\n"

        raw_sock = None
        try:
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                raw_sock = None
                tls_sock.settimeout(timeout)
                tls_sock.sendall(request.encode("ascii"))
                response = http.client.HTTPResponse(tls_sock, method="GET")
                response.begin()
                body = response.read().decode("utf-8", errors="replace").strip()
                status = response.status
                reason = response.reason
        except ssl.SSLError as exc:
            raise RuntimeError(
                "Python TLS verification failed for {} via {}:{}: {}".format(
                    hostname, ip, port, exc
                )
            ) from exc
        except (OSError, TimeoutError) as exc:
            raise RuntimeError(
                "Python HTTPS request failed for {} via {}:{}: {}".format(
                    hostname, ip, port, exc
                )
            ) from exc
        finally:
            if raw_sock is not None:
                raw_sock.close()

        if not body:
            if not 200 <= status < 300:
                details = self._brief(reason or "no response body")
                raise RuntimeError("HTTP {} from PIA endpoint: {}".format(status, details))
            raise RuntimeError("PIA endpoint returned an empty response body")

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            if not 200 <= status < 300:
                raise RuntimeError(
                    "HTTP {} from PIA endpoint: {}".format(status, self._brief(body))
                ) from exc
            raise RuntimeError("PIA endpoint returned invalid JSON: {}".format(self._brief(body))) from exc

        if not 200 <= status < 300:
            if isinstance(data, dict):
                data["_http_status"] = status
                return data
            details = self._brief(body or reason or "no response body")
            raise RuntimeError("HTTP {} from PIA endpoint: {}".format(status, details))

        return data

    def _pia_get_json(self, hostname, ip, port, path, timeout=20):
        if os.name == "nt":
            try:
                return self._python_tls_pia_get(hostname, ip, port, path, timeout=timeout)
            except RuntimeError as python_exc:
                try:
                    return self._curl_pia_get(hostname, ip, port, path, timeout=timeout)
                except RuntimeError as curl_exc:
                    raise RuntimeError(
                        "Python/OpenSSL request failed: {}; curl fallback also failed: {}".format(
                            python_exc, curl_exc
                        )
                    ) from curl_exc

        try:
            return self._curl_pia_get(hostname, ip, port, path, timeout=timeout)
        except RuntimeError as exc:
            if not self._should_retry_with_python_tls(exc):
                raise

            print(
                "Windows curl/Schannel could not verify TLS for {} / {}; retrying the same endpoint with Python/OpenSSL and the bundled PIA CA.".format(
                    hostname, ip
                )
            )
            try:
                return self._python_tls_pia_get(hostname, ip, port, path, timeout=timeout)
            except RuntimeError as fallback_exc:
                raise RuntimeError(
                    "{}; Python/OpenSSL fallback also failed: {}".format(
                        exc, fallback_exc
                    )
                ) from fallback_exc

    def get_token(self, username, password):
        try:
            data = self._request_token(username, password)
        except RuntimeError as exc:
            message = str(exc).lower()
            if "http 401" in message or "access denied" in message:
                raise RuntimeError("PIA login failed. Check PIA_user and PIA_pass.") from exc
            raise

        http_status = data.get("_http_status")
        if http_status == 401:
            raise RuntimeError("PIA login failed. Check PIA_user and PIA_pass.")
        if http_status and not 200 <= http_status < 300:
            message = self._response_message(data)
            raise RuntimeError(
                "PIA token endpoint returned HTTP {}: {}".format(
                    http_status, self._brief(message)
                )
            )

        token = data.get("token")
        if token:
            self.token = token
            return True

        message = self._response_message(data)
        raise RuntimeError("PIA login failed: {}".format(self._brief(message)))

    def generate_keys(self):
        wg = self._find_wg()
        try:
            private = subprocess.run(
                [wg, "genkey"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            self.privatekey = private.stdout.strip()
            public = subprocess.run(
                [wg, "pubkey"],
                input=self.privatekey + "\n",
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            self.publickey = public.stdout.strip()
        except subprocess.CalledProcessError as exc:
            details = self._brief(exc.stderr or exc.stdout or "no error output")
            raise RuntimeError("WireGuard key generation failed: {}".format(details)) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("WireGuard key generation timed out") from exc

    def addkey(self):
        if not self.token:
            raise RuntimeError("Cannot add WireGuard key before obtaining a PIA token.")
        if not self.publickey:
            raise RuntimeError("Cannot add WireGuard key before generating a public key.")

        wg_servers = self._region_servers("wg")
        token = urllib.parse.quote(self.token, safe="")
        publickey = urllib.parse.quote(self.publickey, safe="")
        path = "/addKey?pt={}&pubkey={}".format(token, publickey)

        status, response, cert_failures, attempts = self._try_addkey(wg_servers, path)
        if status:
            return status, response

        if (
            attempts
            and cert_failures == attempts
            and not self._ca_all_routes_refresh_checked
        ):
            self._ca_all_routes_refresh_checked = True
            if self._refresh_ca("all selected WireGuard endpoints failed TLS verification"):
                print("Retrying selected WireGuard endpoints after refreshing the PIA CA.")
                status, response, _cert_failures, _attempts = self._try_addkey(wg_servers, path)
                if status:
                    return status, response

        return status, response

    def _try_addkey(self, wg_servers, path):
        failures = []
        cert_failures = 0
        attempts = 0

        for index, server in enumerate(wg_servers, start=1):
            cn = server.get("cn")
            ip = server.get("ip")
            if not cn or not ip:
                failures.append("WireGuard endpoint {} is missing cn or ip".format(index))
                continue

            attempts += 1
            try:
                data = self._pia_get_json(cn, ip, 1337, path)
            except RuntimeError as exc:
                message = self._brief(exc)
                if self._should_retry_with_python_tls(exc):
                    cert_failures += 1
                print(
                    "WireGuard endpoint {}/{} failed ({} / {}): {}".format(
                        index, len(wg_servers), cn, ip, message
                    )
                )
                failures.append("{} ({}): {}".format(cn, ip, message))
                continue

            if data.get("status") == "OK":
                self.connection = data
                return True, data, cert_failures, attempts

            message = self._response_message(data)
            print(
                "WireGuard endpoint {}/{} rejected the key ({} / {}): {}".format(
                    index, len(wg_servers), cn, ip, self._brief(message)
                )
            )
            failures.append("{} ({}): {}".format(cn, ip, self._brief(message)))

        return (
            False,
            "All WireGuard endpoints for '{}' failed: {}".format(
                self.region, "; ".join(failures)
            ),
            cert_failures,
            attempts,
        )
