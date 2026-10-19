#!/usr/bin/env python3
"""Convert trusted-source rule data; never execute upstream contents."""
import ipaddress
import os
from pathlib import Path
import re
import tempfile
import urllib.request

URL = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf"
TARGET = Path("sr_ad_only.sgmodule")

def convert(source):
    lines = source.splitlines()
    if [line.strip() for line in lines if line.strip().startswith("[")] != ["[Rule]"]:
        raise ValueError("Unexpected configuration sections")
    converted, count = [], 0
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or line == "[Rule]":
            converted.append(raw)
            continue
        fields = [p.strip() for p in line.split(",")]
        if len(fields) != 3 or fields[2].upper() != "REJECT":
            raise ValueError("Unexpected rule structure or policy")
        kind, value, _ = fields
        if kind == "IP-CIDR":
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError("Unexpected IP version")
            value = str(network)
        elif kind == "DOMAIN-SUFFIX":
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                raise ValueError("Invalid domain")
        else:
            raise ValueError("Unsupported rule type")
        converted.append(f"{kind},{value},REJECT")
        count += 1
    if count < 10000 or count > 250000:
        raise ValueError(f"Suspicious rule count: {count}")
    header = (
        "#!name=Shadowrocket AD Only (Surge)\n"
        "#!desc=Daily upstream conversion; may cause false positives.\n"
        f"# Source: {URL}\n"
        "# Attribution: Johnshall/Shadowrocket-ADBlock-Rules-Forever, based on h2y/Shadowrocket-ADBlock-Rules.\n"
        "# License: CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/\n"
        "# Changes: Surge metadata, REJECT capitalization and equivalent canonical IPv4 networks.\n"
        "# No no-resolve added; source IP matching behavior preserved.\n\n"
    )
    return header + "\n".join(converted) + "\n", count

def main():
    with urllib.request.urlopen(URL, timeout=60) as response:
        data = response.read(20_000_001)
    if len(data) > 20_000_000:
        raise ValueError("Source exceeds size limit")
    result, count = convert(data.decode("utf-8-sig"))
    if TARGET.exists():
        previous = TARGET.read_text(encoding="utf-8")
        old_count = sum(line.startswith(("DOMAIN-SUFFIX,", "IP-CIDR,")) for line in previous.splitlines())
        if old_count and not 0.5 * old_count <= count <= 2 * old_count:
            raise ValueError("Rule count changed by more than safety threshold")
        if previous == result:
            print(f"Unchanged: {count} validated rules")
            return
    fd, temporary = tempfile.mkstemp(prefix=".surge-", dir=TARGET.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(result)
        os.replace(temporary, TARGET)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print(f"Updated: {count} validated rules")

if __name__ == "__main__":
    main()
