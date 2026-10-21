#!/usr/bin/env python3
"""Offline conversion of sr_cnip_ad.conf data. Never execute upstream contents."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile

SOURCE_URL = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
MAX_BYTES = 20_000_000
MIN_RULES, MAX_RULES = 10_000, 250_000
KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP", "FINAL"}
POLICIES = {"PROXY", "DIRECT", "REJECT"}
SOURCE_SECTIONS = ["General", "Rule", "URL Rewrite", "MITM"]
GENERAL_KEYS = {"ipv6", "bypass-system", "skip-proxy", "bypass-tun", "dns-server"}
GENERAL = """[General]
# Keep your existing DNS/IPv6 settings when integrating only the .dconf file.
ipv6 = false
dns-server = system
# Optional upstream DoH endpoints, using the Surge key (not enabled):
# encrypted-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query

[Proxy Group]
# REQUIRED: replace REJECT with your existing, working proxy/group name.
# No nodes or credentials are supplied. PROXY traffic is blocked until configured.
# Never use DIRECT as the placeholder or add a group reference cycle.
PROXY = select, REJECT

"""


def split_comment(raw):
    """These rule types have no quoted/regex values; retain inline comment text."""
    match = re.search(r"\s+(?:#|;|//)", raw)
    return (raw[:match.start()], raw[match.start():]) if match else (raw, "")


def sections(source):
    if len(source.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Source exceeds size limit")
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", source):
        raise ValueError("Control character in source")
    result = {None: []}
    current = None
    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        # Surge directives are executable configuration, not ordinary comments.
        if line.lower().startswith("#!"):
            raise ValueError(f"Configuration directive on line {number}")
        if line.startswith("["):
            if not re.fullmatch(r"\[[A-Za-z ]+\]", line):
                raise ValueError(f"Malformed section on line {number}")
            current = line[1:-1]
            if current in result:
                raise ValueError(f"Duplicate section: {current}")
            result[current] = []
        else:
            if current is None and line and not is_comment(line):
                raise ValueError(f"Unexpected preamble on line {number}")
            result[current].append(raw)
    return result


def is_comment(line):
    return line.startswith(("#", ";", "//"))


def active_lines(lines):
    return [raw for raw in lines if raw.strip() and not is_comment(raw.strip())]


def parse_rule(raw):
    body, comment = split_comment(raw)
    fields = [part.strip() for part in body.split(",")]
    kind = fields[0]
    if kind not in KINDS:
        raise ValueError(f"Unsupported rule type: {kind}")
    offset = 1 if kind == "FINAL" else 2
    if len(fields) < offset + 1 or not all(fields):
        raise ValueError(f"Invalid {kind} structure")
    policy = fields[offset].upper()
    if policy not in POLICIES:
        raise ValueError(f"Unsupported policy: {fields[offset]}")
    params = [p.lower() for p in fields[offset + 1:]]
    allowed = ({"no-resolve"} if kind in {"IP-CIDR", "IP-CIDR6", "GEOIP"}
               else {"dns-failed"} if kind == "FINAL" else {"extended-matching"})
    if any(p not in allowed for p in params):
        raise ValueError(f"Unsupported {kind} parameter; review upstream change")
    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", fields[1]):
            raise ValueError("Invalid domain/keyword")
    elif kind in {"IP-CIDR", "IP-CIDR6"}:
        if "/" not in fields[1]:
            raise ValueError("CIDR mask is required")
        network = ipaddress.ip_network(fields[1], strict=False)
        # Shadowrocket labels five IPv6 rules IP-CIDR. Repair only this direction.
        if kind == "IP-CIDR6" and network.version != 6:
            raise ValueError("IPv4 address in IP-CIDR6")
    elif kind == "GEOIP" and not re.fullmatch(r"[A-Za-z]{2}", fields[1]):
        raise ValueError("Invalid GEOIP country")
    return fields, policy, params, comment


def validate_rules(lines):
    rules = active_lines(lines)
    if not MIN_RULES <= len(rules) <= MAX_RULES:
        raise ValueError(f"Suspicious rule count: {len(rules)}")
    types, policies = Counter(), Counter()
    for raw in rules:
        fields, policy, params, _ = parse_rule(raw)
        kind = fields[0]
        if fields[1 if kind == "FINAL" else 2] != policy:
            raise ValueError("Policy is not canonical")
        if len(params) != len(set(params)):
            raise ValueError("Duplicate parameters")
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(fields[1], strict=True)
            if network.version != (4 if kind == "IP-CIDR" else 6) or str(network) != fields[1]:
                raise ValueError("Noncanonical CIDR or incorrect IP version")
            if params.count("no-resolve") != 1:
                raise ValueError("CIDR requires exactly one no-resolve")
        types[kind] += 1
        policies[policy] += 1
    if types["FINAL"] != 1 or not rules[-1].startswith("FINAL,"):
        raise ValueError("FINAL must be unique and last")
    # Identity/safety guard for this CNIP variant, not a top500 whitelist conversion.
    if (types["GEOIP"] != 1 or split_comment(rules[-2])[0] != "GEOIP,CN,DIRECT"
            or split_comment(rules[-1])[0] != "FINAL,PROXY"
            or policies["DIRECT"] != 1 or policies["REJECT"] < MIN_RULES
            or policies["PROXY"] < 2):
        raise ValueError("Unexpected CNIP routing structure; review upstream change")
    return {"rule_count": len(rules), "rule_types": dict(sorted(types.items())),
            "policies": dict(sorted(policies.items()))}


def validate_outputs(detached, profile):
    dparts, pparts = sections(detached), sections(profile)
    if list(dparts)[1:] != ["Rule"] or list(pparts)[1:] != ["General", "Proxy Group", "Rule"]:
        raise ValueError("Unexpected generated sections")
    if active_lines(pparts["General"]) != ["ipv6 = false", "dns-server = system"]:
        raise ValueError("Unexpected General settings")
    if active_lines(pparts["Proxy Group"]) != ["PROXY = select, REJECT"]:
        raise ValueError("PROXY must reference the safe built-in placeholder")
    if dparts["Rule"] != pparts["Rule"]:
        raise ValueError("Detached and standalone rules differ")
    # Every policy is DIRECT/REJECT or the declared PROXY group. No node definitions.
    return validate_rules(dparts["Rule"])


def convert(source):
    parts = sections(source)
    if list(parts)[1:] != SOURCE_SECTIONS:
        raise ValueError("Unexpected upstream sections/order")
    keys = []
    for raw in active_lines(parts["General"]):
        body, _ = split_comment(raw)
        key, separator, value = body.partition("=")
        if not separator or key.strip() not in GENERAL_KEYS or not value.strip():
            raise ValueError("Unexpected upstream General setting")
        keys.append(key.strip())
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate General setting")

    changes = {"ipv6_type_repairs": [], "canonical_networks": [],
               "no_resolve_added": 0, "duplicate_no_resolve_removed": 0}
    converted = []
    geoip_before, geoip_after = [], []
    for raw in parts["Rule"]:
        if not raw.strip() or is_comment(raw.strip()):
            converted.append(raw)
            continue
        fields, policy, params, comment = parse_rule(raw)
        kind = fields[0]
        if kind == "FINAL":
            fields = [kind, policy, *params]
        else:
            value = fields[1]
            if kind in {"IP-CIDR", "IP-CIDR6"}:
                network = ipaddress.ip_network(value, strict=False)
                if kind == "IP-CIDR" and network.version == 6:
                    changes["ipv6_type_repairs"].append(value)
                    kind = "IP-CIDR6"
                if value != str(network):
                    changes["canonical_networks"].append({"from": value, "to": str(network)})
                value = str(network)
                copies = params.count("no-resolve")
                changes["no_resolve_added"] += not copies
                changes["duplicate_no_resolve_removed"] += max(0, copies - 1)
                params = [p for p in params if p != "no-resolve"] + ["no-resolve"]
            elif kind == "GEOIP":
                # Never add no-resolve to GEOIP: doing so changes CN/direct matching.
                geoip_before.append((value, policy, tuple(dict.fromkeys(params))))
                params = list(dict.fromkeys(params))
                geoip_after.append((value, policy, tuple(params)))
            fields = [kind, value, policy, *params]
        converted.append(",".join(fields) + comment)
    if geoip_before != geoip_after:
        raise ValueError("GEOIP matching changed")
    stats = validate_rules(converted)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    header = (
        "# Shadowrocket CNIP + AD rules converted for Surge (not a module).\n"
        f"# Source: {SOURCE_URL}\n"
        f"# Source SHA-256 (UTF-8): {digest}\n"
        "# Attribution: Moshel, Johnshall and contributors; based on h2y/Shadowrocket-ADBlock-Rules.\n"
        "# License: CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/\n"
        "# Changes: canonical policies/CIDRs, IPv6 rule types, CIDR no-resolve.\n"
        "# Order and comments retained. GEOIP resolution unchanged. See docs/sr_cnip_ad.md.\n"
        "# PROXY requires a configured proxy/group; the template uses REJECT until configured.\n\n"
    ) + "\n".join(parts[None]) + "\n"
    appendix = ["", "# Inactive upstream settings, preserved as reference only.",
                "# General bypass settings are NOT imported; retain your existing Surge settings.",
                "# Google URL redirection is optional and NOT ad/routing filtering.",
                "# HTTPS rewriting needs MITM; no MITM or certificate setup is enabled here."]
    for section in ("General", "URL Rewrite", "MITM"):
        appendix.append(f"# [{section}]")
        appendix.extend("# " + raw if raw.strip() else "#" for raw in parts[section])
    rule_body = "[Rule]\n" + "\n".join(converted + appendix) + "\n"
    detached = header + rule_body
    profile = header + GENERAL + rule_body
    validate_outputs(detached, profile)
    report = {"source_url": SOURCE_URL, "source_sha256": digest,
              "license": "CC BY-SA 4.0", **stats, "changes": changes,
              "surge_client_tested": False}
    return {"sr_cnip_ad.dconf": detached, "sr_cnip_ad.conf": profile,
            "sr_cnip_ad.validation.json": json.dumps(report, indent=2, ensure_ascii=False) + "\n"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Local upstream text; not executed")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true", help="Verify existing generated files without writing")
    args = parser.parse_args(argv)
    with args.source.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Source exceeds size limit")
    result = convert(data.decode("utf-8-sig"))
    if args.check:
        for name, contents in result.items():
            if (args.output_dir / name).read_text(encoding="utf-8") != contents:
                raise ValueError(f"Generated file differs: {name}")
        print("All three generated files match the validated source")
        return
    # Finish all parsing, conversion and validation before preparing any file writes.
    pending = []
    try:
        for name, contents in result.items():
            fd, temporary = tempfile.mkstemp(prefix=".cnip-", dir=args.output_dir)
            pending.append((Path(temporary), args.output_dir / name))
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                output.write(contents)
        for temporary, target in pending:
            os.replace(temporary, target)
    finally:
        for temporary, _ in pending:
            temporary.unlink(missing_ok=True)
    stats = json.loads(result["sr_cnip_ad.validation.json"])
    print(f"Prepared {stats['rule_count']} validated rules; no network/device changes")


if __name__ == "__main__":
    main()
