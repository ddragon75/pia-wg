from getpass import getpass
import os
from pathlib import Path

from piawg import piawg

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "PIA-wg.conf"


def load_dotenv(path=BASE_DIR / ".env"):
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def select_region(pia):
    region = (
        os.environ.get("region")
        or os.environ.get("PIA_region")
        or os.environ.get("PIA_REGION")
    )
    if region:
        pia.set_region(region)
        return

    from pick import pick

    option, _index = pick(sorted(pia.server_list.keys()), "Please choose a region: ")
    pia.set_region(option)


def get_credentials():
    username = os.environ.get("PIA_user") or os.environ.get("PIA_USER")
    password = os.environ.get("PIA_pass") or os.environ.get("PIA_PASS")

    if not username:
        username = input("\nEnter PIA username: ")
    if not password:
        password = getpass("Enter PIA password: ")

    if not username or not password:
        raise RuntimeError("PIA_user and PIA_pass are required.")

    return username, password


def write_config(pia):
    required_fields = ["peer_ip", "dns_servers", "server_key", "server_ip"]
    missing = [field for field in required_fields if field not in pia.connection]
    if missing:
        raise RuntimeError("PIA addKey response is missing: {}".format(", ".join(missing)))

    dns_servers = pia.connection["dns_servers"]
    if len(dns_servers) < 2:
        raise RuntimeError("PIA addKey response did not include two DNS servers.")

    print("Saving configuration file {}".format(CONFIG_FILE.name))
    with CONFIG_FILE.open("w", encoding="utf-8", newline="\n") as file:
        file.write("[Interface]\n")
        file.write("Address = {}\n".format(pia.connection["peer_ip"]))
        file.write("PrivateKey = {}\n".format(pia.privatekey))
        file.write("DNS = {}\n\n".format(", ".join(dns_servers[:2])))
        file.write("[Peer]\n")
        file.write("PublicKey = {}\n".format(pia.connection["server_key"]))
        file.write("Endpoint = {}:1337\n".format(pia.connection["server_ip"]))
        file.write("AllowedIPs = 0.0.0.0/0\n")
        file.write("PersistentKeepalive = 25\n")


def main():
    try:
        load_dotenv()
        pia = piawg()
        pia.generate_keys()

        select_region(pia)
        print("Selected '{}'".format(pia.region))

        username, password = get_credentials()
        pia.get_token(username, password)
        print("Login successful!")

        status, response = pia.addkey()
        if not status:
            raise RuntimeError(response)
        print("Added key to server!")

        write_config(pia)
    except Exception as exc:
        raise SystemExit("Error: {}".format(exc))


if __name__ == "__main__":
    main()
