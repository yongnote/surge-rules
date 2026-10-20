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
        if len(fields) < 3 or fields[2].upper() != "REJECT" or not all(fields):
            raise ValueError("Unexpected rule structure or policy")
        kind, value = fields[:2]
        params = fields[3:]
        if kind in ("IP-CIDR", "IP-CIDR6"):
            network = ipaddress.ip_network(value, strict=False)
            if network.version != (4 if kind == "IP-CIDR" else 6):
                raise ValueError("Unexpected IP version")
            value = str(network)
            # Preserve other parameters and emit exactly one no-resolve flag.
            params = [p for p in params if p.lower() != "no-resolve"]
            params.append("no-resolve")
        elif kind == "DOMAIN-SUFFIX":
            if params or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                raise ValueError("Invalid domain")
        else:
            raise ValueError("Unsupported rule type")
        converted.append(",".join([kind, value, "REJECT", *params]))
        count += 1
    if count < 10000 or count > 250000:
        raise ValueError(f"Suspicious rule count: {count}")
    header = (
        "#!name=Shadowrocket AD Only (Surge)\n"
        "#!desc=Weekly upstream conversion; may cause false positives.\n"
        f"# Source: {URL}\n"
        "# Attribution: Johnshall/Shadowrocket-ADBlock-Rules-Forever, based on h2y/Shadowrocket-ADBlock-Rules.\n"
        "# License: CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/\n"
        "# Changes: Surge metadata, REJECT capitalization and equivalent canonical IP networks.\n"
        "# IP rules use no-resolve to avoid triggering DNS; unresolved domains skip IP rules.\n\n"
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
        old_count = sum(line.startswith(("DOMAIN-SUFFIX,", "IP-CIDR,", "IP-CIDR6,")) for line in previous.splitlines())
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
