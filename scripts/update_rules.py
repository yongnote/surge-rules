#!/usr/bin/env python3
"""Convert trusted-source rule data; never execute upstream contents."""
import ipaddress
import os
from pathlib import Path
import re
import tempfile
import urllib.request

URL = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf"
MODULE = Path("sr_ad_only.sgmodule")
RULES = Path("sr_ad_only.list")
RULES_URL = "https://raw.githubusercontent.com/yongnote/surge-rules/main/sr_ad_only.list"
RULE_TYPES = ("DOMAIN-SUFFIX,", "IP-CIDR,", "IP-CIDR6,")
# Google account UI requests: leave this host to the profile’s normal routing.
EXCLUDED_DOMAIN_SUFFIXES = {"ogads-pa.googleapis.com"}
MODULE_HEADER = (
    "#!name=Shadowrocket AD Only (Surge)\n"
    "#!desc=Weekly upstream conversion; may cause false positives.\n"
)
ATTRIBUTION = (
    f"# Source: {URL}\n"
    "# Attribution: Johnshall/Shadowrocket-ADBlock-Rules-Forever, based on h2y/Shadowrocket-ADBlock-Rules.\n"
    "# License: CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/\n"
    "# Changes: external rule set, canonical IP networks, and no-resolve for IP rules.\n"
)

ZHIHU_SPLASH_PATHS = ("launch_v2", "real_time_launch_v2")


def module_text():
    zhihu_rules = "".join(
        rf"^https://api\.zhihu\.com/commercial_api/{path}/?(?:[?#]|$) _ reject" + "\n"
        for path in ZHIHU_SPLASH_PATHS
    )
    return (
        f"{MODULE_HEADER}{ATTRIBUTION}\n[Rule]\nRULE-SET,{RULES_URL},REJECT\n"
        "\n[URL Rewrite]\n"
        "# Zhihu launch ads; HTTPS decryption for api.zhihu.com is opt-in in the profile.\n"
        f"{zhihu_rules}"
    )


def convert(source):
    lines = source.splitlines()
    if [line.strip() for line in lines if line.strip().startswith("[")] != ["[Rule]"]:
        raise ValueError("Unexpected configuration sections")
    converted, count = [], 0
    for raw in lines:
        line = raw.strip()
        if line == "[Rule]":
            continue
        if not line or line.startswith(("#", ";", "//")):
            # Keep upstream comments as comments, including lines that look like directives.
            converted.append("# " + line if line.startswith("#!") else raw)
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
            if value.lower().rstrip(".") in EXCLUDED_DOMAIN_SUFFIXES:
                continue
        else:
            raise ValueError("Unsupported rule type")
        converted.append(",".join([kind, value, *params]))
        count += 1
    if count < 10000 or count > 250000:
        raise ValueError(f"Suspicious rule count: {count}")
    return ATTRIBUTION + "\n" + "\n".join(converted) + "\n", count

def write_atomic(path, content):
    fd, temporary = tempfile.mkstemp(prefix=".surge-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

def main():
    with urllib.request.urlopen(URL, timeout=60) as response:
        data = response.read(20_000_001)
    if len(data) > 20_000_000:
        raise ValueError("Source exceeds size limit")
    result, count = convert(data.decode("utf-8-sig"))
    previous = RULES.read_text(encoding="utf-8") if RULES.exists() else ""
    baseline = previous or (MODULE.read_text(encoding="utf-8") if MODULE.exists() else "")
    old_count = sum(line.startswith(RULE_TYPES) for line in baseline.splitlines())
    if old_count and not 0.5 * old_count <= count <= 2 * old_count:
        raise ValueError("Rule count changed by more than safety threshold")
    module = module_text()
    if previous == result and MODULE.exists() and MODULE.read_text(encoding="utf-8") == module:
        print(f"Unchanged: {count} validated rules")
        return
    write_atomic(RULES, result)
    write_atomic(MODULE, module)
    print(f"Updated: {count} validated rules")

if __name__ == "__main__":
    main()
