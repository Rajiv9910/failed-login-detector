import re
from collections import Counter
from pathlib import Path


def detect_failed_logins(log_path, threshold=5):
    """
    Detects potential SSH brute-force attacks by counting failed login attempts per IP.
    """

    path = Path(log_path)
    ip_counter = Counter()

    if not path.exists():
        print(f"[ERROR] Log file not found: {path}")
        return

    # Regex to extract IP address after the word 'from' in SSH failed login logs
    fail_regex = re.compile(
        r"Failed password .* from (\d{1,3}(?:\.\d{1,3}){3})"
    )

    try:
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                match = fail_regex.search(line)
                if match:
                    ip_counter[match.group(1)] += 1
    except Exception as e:
        print(f"[ERROR] Could not read log file: {e}")
        return

    # Identify suspicious IPs
    suspicious_ips = {
        ip: count for ip, count in ip_counter.items() if count > threshold
    }

    # Reporting
    if suspicious_ips:
        print(f"{'IP Address':<20} | {'Attempts':<10}")
        print("-" * 35)
        for ip, count in suspicious_ips.items():
            print(
                f"{ip:<20} | {count:<10} [ALERT] SSH brute-force suspected"
            )
    else:
        print("No suspicious activity detected.")


# ---- Usage ----
LOG_FILE = r"C:\Users\rajiv\OneDrive\Documents\CyberSecurity\Projects\python project\auth.log"
detect_failed_logins(LOG_FILE, threshold=5)
