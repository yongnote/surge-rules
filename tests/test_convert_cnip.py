import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.convert_cnip import convert, main, sections, validate_outputs, validate_rules


def fixture(*rules):
    # Keep the real minimum-count safety check in every conversion test.
    return (
        "# by Moshel and Johnshall\n# build time: fixture\n\n"
        "[General]\nipv6 = false\nbypass-system = true\n"
        "skip-proxy = localhost\nbypass-tun = 10.0.0.0/8\n"
        "dns-server = https://dns.example/dns-query\n[Rule]\n"
        "# Ordered exceptions must precede ad rules\n"
        "DOMAIN-SUFFIX,exception.example,Proxy # reason #237\n"
        + "\n".join(rules) + "\n"
        + "DOMAIN-SUFFIX,ad.example,Reject\n" * 10_000
        + "\nGEOIP,CN,DIRECT\nFINAL,proxy\n\n"
        "[URL Rewrite]\n^http://google.cn https://www.google.com 302\n"
        "[MITM]\nhostname = *.google.cn\n# Original footer\n"
    )


class ConvertCnipTests(unittest.TestCase):
    def test_order_comments_duplicates_and_policy_names(self):
        result = convert(fixture(
            "DOMAIN-SUFFIX,exception.example,Reject",
            "DOMAIN-KEYWORD,google,proxy // inline",
            "; original standalone comment",
            "DOMAIN,one.example,pRoXy ; inline",
        ))
        body = sections(result["sr_cnip_ad.dconf"])["Rule"]
        self.assertEqual(body[:5], [
            "# Ordered exceptions must precede ad rules",
            "DOMAIN-SUFFIX,exception.example,PROXY # reason #237",
            "DOMAIN-SUFFIX,exception.example,REJECT",
            "DOMAIN-KEYWORD,google,PROXY // inline",
            "; original standalone comment",
        ])
        self.assertIn("DOMAIN,one.example,PROXY ; inline", body)
        self.assertEqual(body.count("DOMAIN-SUFFIX,ad.example,REJECT"), 10_000)
        self.assertIn("# by Moshel and Johnshall", result["sr_cnip_ad.conf"])
        self.assertIn("# # Original footer", result["sr_cnip_ad.conf"])

    def test_ipv6_type_repair_canonical_cidrs_and_no_resolve_dedup(self):
        result = convert(fixture(
            "IP-CIDR,2001:db8::1/64,Proxy,No-Resolve,no-resolve # IPv6",
            "IP-CIDR6,2001:db8:1234::1/48,Reject",
            "IP-CIDR,117.139.18.141/22,Reject",
            "IP-CIDR,123.125.117.0/22,Reject,no-resolve",
            "IP-CIDR,183.221.247.189/22,Reject",
        ))
        output = result["sr_cnip_ad.dconf"]
        self.assertIn("IP-CIDR6,2001:db8::/64,PROXY,no-resolve # IPv6\n", output)
        self.assertIn("IP-CIDR6,2001:db8:1234::/48,REJECT,no-resolve\n", output)
        for network in ("117.139.16.0/22", "123.125.116.0/22", "183.221.244.0/22"):
            self.assertIn(f"IP-CIDR,{network},REJECT,no-resolve\n", output)
        changes = json.loads(result["sr_cnip_ad.validation.json"])["changes"]
        self.assertEqual(changes["ipv6_type_repairs"], ["2001:db8::1/64"])
        self.assertEqual(changes["no_resolve_added"], 3)
        self.assertEqual(changes["duplicate_no_resolve_removed"], 1)

    def test_geoip_keeps_dns_matching_and_final_has_no_added_flags(self):
        output = convert(fixture("IP-CIDR,192.0.2.1/32,Proxy"))["sr_cnip_ad.dconf"]
        rules = [line for line in sections(output)["Rule"] if line.startswith(("GEOIP,", "FINAL,"))]
        self.assertEqual(rules, ["GEOIP,CN,DIRECT", "FINAL,PROXY"])
        self.assertNotIn("DOMAIN-SUFFIX,ad.example,REJECT,no-resolve", output)

    def test_supported_domain_flag_retained(self):
        output = convert(fixture("DOMAIN-SUFFIX,sni.example,Proxy,extended-matching"))["sr_cnip_ad.conf"]
        self.assertIn("DOMAIN-SUFFIX,sni.example,PROXY,extended-matching\n", output)

    def test_no_active_bypass_rewrite_mitm_or_credentials(self):
        result = convert(fixture())
        parts = sections(result["sr_cnip_ad.conf"])
        self.assertEqual(list(parts)[1:], ["General", "Proxy Group", "Rule"])
        self.assertIn("PROXY = select, REJECT", parts["Proxy Group"])
        self.assertNotIn("PROXY = select, DIRECT", result["sr_cnip_ad.conf"])
        self.assertIn("# [MITM]", result["sr_cnip_ad.conf"])
        self.assertIn("# hostname = *.google.cn", result["sr_cnip_ad.conf"])
        self.assertIn("# bypass-system = true", result["sr_cnip_ad.conf"])
        self.assertNotIn("#!name=", result["sr_cnip_ad.conf"])

    def test_invalid_rules_and_unresolved_policies_fail(self):
        for rule in (
            "RULE-SET,https://example.com/list,PROXY",
            "SCRIPT,remote,PROXY",
            "IP-CIDR6,192.0.2.0/24,Proxy",
            "IP-CIDR,192.0.2.1/99,Reject",
            "IP-CIDR,192.0.2.1,Reject",
            "IP-CIDR,192.0.2.0/24,Reject,",
            "IP-CIDR,192.0.2.0/24,Reject,unknown-param",
            "DOMAIN-SUFFIX,ad.example,MissingGroup",
            "DOMAIN-SUFFIX,ad.example,Proxy,no-resolve",
            "DOMAIN-SUFFIX,bad value,REJECT",
            "GEOIP,China,DIRECT",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                convert(fixture(rule))

    def test_final_unique_last_and_not_direct(self):
        for source in (
            fixture("FINAL,PROXY"),
            fixture().replace("FINAL,proxy", ""),
            fixture().replace("FINAL,proxy", "FINAL,DIRECT"),
            fixture().replace("FINAL,proxy", "FINAL,proxy\nDOMAIN,after.example,PROXY"),
        ):
            with self.subTest(tail=source[-250:]), self.assertRaises(ValueError):
                convert(source)

    def test_upstream_configuration_directives_and_extra_sections_fail(self):
        for source in (
            fixture("#!include https://example.com/untrusted.dconf"),
            fixture().replace("# by Moshel", "  #!MANAGED-CONFIG https://example.com\n# by Moshel"),
            fixture().replace("[MITM]", "[Script]"),
            fixture() + "\n[Rule]\nFINAL,PROXY\n",
            fixture().replace("bypass-system = true", "unknown-setting = true"),
            fixture().replace("ipv6 = false", "ipv6 = false\nipv6 = true"),
            fixture().replace("# build time: fixture", "\x00"),
        ):
            with self.subTest(tail=source[-150:]), self.assertRaises(ValueError):
                convert(source)

    def test_whitelist_variant_and_geoip_semantic_drift_fail(self):
        for source in (
            fixture("DOMAIN-SUFFIX,whitelist.example,DIRECT"),
            fixture().replace("GEOIP,CN,DIRECT", "GEOIP,CN,DIRECT,no-resolve"),
            fixture().replace("GEOIP,CN,DIRECT", "GEOIP,US,DIRECT"),
        ):
            with self.subTest(tail=source[-200:]), self.assertRaises(ValueError):
                convert(source)

    def test_truncated_source_fails(self):
        with self.assertRaisesRegex(ValueError, "Suspicious rule count"):
            convert(fixture().replace("DOMAIN-SUFFIX,ad.example,Reject\n" * 10_000, ""))

    def test_determinism_attribution_digest_and_report(self):
        source = fixture()
        result = convert(source)
        self.assertEqual(convert(source), result)
        report = json.loads(result["sr_cnip_ad.validation.json"])
        self.assertEqual(report["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(report["rule_count"], 10_003)
        for name in ("sr_cnip_ad.conf", "sr_cnip_ad.dconf"):
            self.assertIn("# License: CC BY-SA 4.0", result[name])
            self.assertIn(report["source_sha256"], result[name])
        self.assertFalse(report["surge_client_tested"])

    def test_output_validator_catches_reference_and_cidr_corruption(self):
        result = convert(fixture("IP-CIDR,192.0.2.0/24,REJECT"))
        for before, after in (
            ("PROXY = select, REJECT", "PROXY = select, MissingGroup"),
            ("PROXY = select, REJECT", "PROXY = select, DIRECT"),
            ("FINAL,PROXY", "FINAL,MissingGroup"),
        ):
            with self.subTest(after=after), self.assertRaises(ValueError):
                validate_outputs(result["sr_cnip_ad.dconf"], result["sr_cnip_ad.conf"].replace(before, after))
        bad_rules = sections(result["sr_cnip_ad.dconf"])["Rule"]
        for before, after in (
            ("192.0.2.0/24", "192.0.2.1/24"),
            ("IP-CIDR,192.0.2.0", "IP-CIDR6,192.0.2.0"),
            (",REJECT,no-resolve", ",REJECT,no-resolve,no-resolve"),
        ):
            with self.subTest(after=after), self.assertRaises(ValueError):
                validate_rules([raw.replace(before, after) for raw in bad_rules])

    def test_cli_check_and_failure_do_not_overwrite_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.conf"
            source.write_text(fixture(), encoding="utf-8")
            args = ["--source", str(source), "--output-dir", directory]
            main(args)
            saved = {p.name: p.read_bytes() for p in root.glob("sr_cnip_ad.*")}
            main([*args, "--check"])
            source.write_text("[Script]\nmalicious = ignored\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                main(args)
            self.assertEqual(saved, {p.name: p.read_bytes() for p in root.glob("sr_cnip_ad.*")})
            source.write_text(fixture("DOMAIN,extra.example,Proxy"), encoding="utf-8")
            with self.assertRaises(ValueError):
                main([*args, "--check"])
            self.assertEqual(saved, {p.name: p.read_bytes() for p in root.glob("sr_cnip_ad.*")})

    def test_checked_in_artifacts_share_valid_rules_and_report(self):
        root = Path(__file__).resolve().parents[1]
        stats = validate_outputs((root / "sr_cnip_ad.dconf").read_text(encoding="utf-8"),
                                 (root / "sr_cnip_ad.conf").read_text(encoding="utf-8"))
        report = json.loads((root / "sr_cnip_ad.validation.json").read_text(encoding="utf-8"))
        self.assertEqual(stats, {key: report[key] for key in stats})


if __name__ == "__main__":
    unittest.main()
