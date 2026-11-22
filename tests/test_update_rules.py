import unittest

from scripts.update_rules import convert, module_text, RULES_URL


class ConvertTests(unittest.TestCase):
    def convert_rules(self, *rules):
        # Retain the production minimum-rule-count safety check.
        source = "[Rule]\n" + "\n".join(rules) + "\n"
        source += "DOMAIN-SUFFIX,example.com,REJECT\n" * (10000 - sum(not rule.startswith("#") for rule in rules))
        result, count = convert(source)
        self.assertEqual(count, 10000)
        return result

    def test_ipv4_and_ipv6_get_no_resolve(self):
        result = self.convert_rules(
            "IP-CIDR,60.211.211.1/32,Reject",
            "IP-CIDR6,2001:db8::1/64,Reject",
        )
        self.assertIn("IP-CIDR,60.211.211.1/32,no-resolve\n", result)
        self.assertIn("IP-CIDR6,2001:db8::/64,no-resolve\n", result)
        self.assertIn("DOMAIN-SUFFIX,example.com\n", result)
        self.assertNotIn("DOMAIN-SUFFIX,example.com,no-resolve", result)

    def test_existing_parameters_preserved_and_no_resolve_not_duplicated(self):
        result = self.convert_rules(
            "IP-CIDR,192.0.2.1/32,REJECT,extended-matching,no-resolve,no-resolve",
            "IP-CIDR6,2001:db8::/32,REJECT,no-resolve",
        )
        self.assertIn(
            "IP-CIDR,192.0.2.1/32,extended-matching,no-resolve\n", result
        )
        self.assertIn("IP-CIDR6,2001:db8::/32,no-resolve\n", result)
        self.assertNotIn("[Rule]", result)
        self.assertNotIn(",REJECT", result)

    def test_module_only_references_external_set(self):
        self.assertEqual(module_text().split("[Rule]\n", 1)[1],
                         f"RULE-SET,{RULES_URL},REJECT\n")

    def test_order_and_comments(self):
        result = self.convert_rules(
            "DOMAIN-SUFFIX,first.example,REJECT",
            "#!unsafe=ignored",
            "IP-CIDR,192.0.2.1/24,REJECT",
        )
        self.assertIn("DOMAIN-SUFFIX,first.example\n# #!unsafe=ignored\n"
                      "IP-CIDR,192.0.2.0/24,no-resolve\n", result)

    def test_google_storage_exception_only_removes_matching_suffix_rules(self):
        source = "[Rule]\n" + "DOMAIN-SUFFIX,example.com,REJECT\n" * 10000
        source += (
            "DOMAIN-SUFFIX,ogads-pa.googleapis.com,REJECT\n"
            "DOMAIN-SUFFIX,OGADS-PA.GOOGLEAPIS.COM.,REJECT\n"
            "DOMAIN-SUFFIX,mail-ads.google.com,REJECT\n"
            "DOMAIN-SUFFIX,another-ogads-pa.googleapis.com,REJECT\n"
        )
        result, count = convert(source)
        self.assertEqual(count, 10002)
        self.assertNotIn("DOMAIN-SUFFIX,ogads-pa.googleapis.com", result)
        self.assertNotIn("DOMAIN-SUFFIX,OGADS-PA.GOOGLEAPIS.COM.", result)
        self.assertIn("DOMAIN-SUFFIX,mail-ads.google.com\n", result)
        self.assertIn("DOMAIN-SUFFIX,another-ogads-pa.googleapis.com\n", result)

    def test_invalid_rules_still_rejected(self):
        for rule in (
            "IP-CIDR,2001:db8::/32,REJECT",
            "IP-CIDR6,192.0.2.1/32,REJECT",
            "IP-CIDR,192.0.2.1/32,DIRECT",
            "IP-CIDR,192.0.2.1/32,REJECT,",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.convert_rules(rule)


if __name__ == "__main__":
    unittest.main()
