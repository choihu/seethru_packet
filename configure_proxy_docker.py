
import os
import sys
import subprocess
from pathlib import Path
import shutil

WARGAME_DIR = "/cs/services"
TEMPLATE_FILE = "scripts/run_proxy_template.sh"

try:
    import yaml
except ImportError:
    print("PyYAML library not found. Please install it by running: sudo pip3 install PyYAML")
    sys.exit(1)

def get_environments():
    """Scans the wargame directory for available environments."""
    try:
        return [d for d in os.listdir(WARGAME_DIR) if os.path.isdir(os.path.join(WARGAME_DIR, d))]
    except FileNotFoundError:
        print(f"[ERROR] Directory not found: {WARGAME_DIR}")
        return []

def get_wargame_details(env_name):
    """Parses the docker-compose.yml for a given environment."""
    compose_file = os.path.join(WARGAME_DIR, env_name, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return None
    with open(compose_file, 'r') as f:
        try:
            data = yaml.safe_load(f)
            return data['services']
        except yaml.YAMLError as e:
            print(f"[ERROR] Failed to parse {compose_file}: {e}")
            return None

def choose_from_list(options, title):
    """Generic helper to prompt user to choose from a list."""
    print(f"\n--- {title} ---")
    for i, option in enumerate(options):
        print(f"  [{i+1}] {option}")
    while True:
        try:
            choice = int(input(f"Please choose an option (1-{len(options)}): "))
            if 1 <= choice <= len(options):
                return options[choice-1]
        except (ValueError, IndexError):
            pass
        print("Invalid choice. Please try again.")

def main():
    """Main function for the interactive wizard."""
    print("========================================")
    print("=== MITM Proxy Configuration Wizard  ===")
    print("========================================")

    # 1. Choose environment
    environments = get_environments()
    if not environments:
        print("No environments found.")
        return
    env_name = choose_from_list(environments, "Available Wargame Environments")

    # 2. Analyze docker-compose and choose service/port
    services = get_wargame_details(env_name)
    if not services:
        print(f"Could not find or parse docker-compose.yml for '{env_name}'.")
        return

    exposed_services = []
    for service_name, details in services.items():
        if 'ports' in details:
            for port_mapping in details['ports']:
                exposed_services.append(f"{service_name}:{port_mapping.split(':')[0]}")
    
    if not exposed_services:
        print(f"No externally exposed ports found in '{env_name}'.")
        return

    chosen_service_port = choose_from_list(exposed_services, f"Exposed Services in '{env_name}'")
    target_service, listening_port = chosen_service_port.split(':')
    proxy_port = str(int(listening_port) + 10000)
    #target_port = services[target_service]['ports'][0].split(':')[1] # Get internal port

    # 3. Choose protocol
    protocol = choose_from_list(["http", "https", "tcp", "tls"], "Protocol for the selected port")

    # 4. Ask for custom certificate
    custom_cert = ""
    if protocol in ('https', 'tls'):
        if protocol == 'https':
            cert_guess_path = os.path.join(WARGAME_DIR, env_name, "haproxy", "backend.pem")
        else:
            cert_guess_path = ""

        prompt = "Use custom certificate?"
        if protocol == 'tls':
            prompt = "Use custom certificate bundle (PEM with cert+key)?"

        use_cert = input(f"{prompt} (if unsure, say no) [y/N]: ").lower().strip()
        if use_cert == 'y':
            default_hint = f" [default: {cert_guess_path}]" if cert_guess_path else ""
            custom_cert = input(
                f"Enter path to .pem file (relative to MITM_PROXY dir){default_hint}: "
            ).strip()
            if not custom_cert and cert_guess_path:
                custom_cert = cert_guess_path

    # 5. Generate the script
    network_name = f"{env_name}_default"
    output_filename = f"{env_name}/run_{env_name}_{target_service}_proxy.sh"

    with open(TEMPLATE_FILE, 'r') as f:
        template = f.read()

    BASE_DIR = Path(__file__).parent.resolve()
    service_dir = BASE_DIR / env_name
    if not service_dir.is_dir():
        service_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy("src/monitor_http.py", service_dir)
        shutil.copy("src/monitor_tcp.py", service_dir)
        shutil.copy("src/utils.py", service_dir)

    # Ensure TLS wrapper script is available for TLS proxies
    wrapper_src = Path("scripts/tls_wrapper.sh")
    wrapper_dst = service_dir / "tls_wrapper.sh"
    if wrapper_src.is_file():
        shutil.copy(wrapper_src, wrapper_dst)
        wrapper_dst.chmod(0o755)
    log_dir = service_dir / "logs"
    if not log_dir.is_dir():
        log_dir.mkdir(parents=True, exist_ok=True)
    log_dir.chmod(0o777)

    # Replace placeholders - a bit simplistic but works for this template
    script_content = template.replace('LISTENING_PORT=9999', f'LISTENING_PORT={proxy_port}')
    script_content = script_content.replace('PROXY_TYPE="http"', f'PROXY_TYPE="{protocol}"')
    script_content = script_content.replace('TARGET_SERVICE="my_web_service"', f'TARGET_SERVICE="{target_service}"')
    script_content = script_content.replace('TARGET_PORT=8080', f'TARGET_PORT={listening_port}'
    )
    script_content = script_content.replace('NETWORK_NAME="my_wargame_default"', f'NETWORK_NAME="{network_name}"')
    script_content = script_content.replace('CUSTOM_CERT_PATH=""', f'CUSTOM_CERT_PATH="{custom_cert}"')
    script_content = script_content.replace('ENV_NAME="my_docker_environment"', f'ENV_NAME="{env_name}"')

    with open(output_filename, 'w') as f:
        f.write(script_content)

    os.chmod(output_filename, 0o755)

    delete_script_path = service_dir / "delete_iptables.sh"
    delete_script = f"""#!/bin/bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  sudo_cmd={{${{SUDO:-sudo}}}}
else
  sudo_cmd=""
fi

if [[ -n "$sudo_cmd" ]]; then
  "$sudo_cmd" iptables -t nat -D MITM -p tcp ! -s 127.0.0.0/24 --dport {listening_port} -j REDIRECT --to-ports {proxy_port}
else
  iptables -t nat -D MITM -p tcp ! -s 127.0.0.0/24 --dport {listening_port} -j REDIRECT --to-ports {proxy_port}
fi

echo "[INFO] Removed MITM redirect for target port {listening_port} -> proxy port {proxy_port}."
"""

    with open(delete_script_path, 'w') as f:
        f.write(delete_script)
    delete_script_path.chmod(0o755)

    print("\n----------------------------------------")
    print(f"[SUCCESS] Generated proxy script: {output_filename}")
    print("----------------------------------------")
    print("To use it:")
    print(f"  1. In Seethru_Packet dir and run: ./{output_filename}")
    print(f"  2. Check iptables rules: sudo iptables -t nat -L --line-numbers -n -v")
    print(f"  3. If MITM chain doesn't exist: sudo ./set_iptables_rules.sh")
    print(f"  4. Add iptables rules: sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport {listening_port} -j REDIRECT --to-ports {proxy_port}")

if __name__ == "__main__":
    main()
