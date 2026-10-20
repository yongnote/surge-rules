import unittest

from scripts.update_rules import convert


class ConvertTests(unittest.TestCase):
    def convert_rules(self, *rules):
        # Retain the production minimum-rule-count safety check.
        source = "[Rule]\n" + "\n".join(rules) + "\n"
        source += "DOMAIN-SUFFIX,example.com,REJECT\n" * (10000 - len(rules))
        result, count = convert(source)
        self.assertEqual(count, 10000)
        return result

    def test_ipv4_and_ipv6_get_no_resolve(self):
        result = self.convert_rules(
            "IP-CIDR,60.211.211.1/32,Reject",
            "IP-CIDR6,2001:db8::1/64,Reject",
        )
        self.assertIn("IP-CIDR,60.211.211.1/32,REJECT,no-resolve\n", result)
        self.assertIn("IP-CIDR6,2001:db8::/64,REJECT,no-resolve\n", result)
        self.assertIn("DOMAIN-SUFFIX,example.com,REJECT\n", result)
        self.assertNotIn("DOMAIN-SUFFIX,example.com,REJECT,no-resolve", result)

    def test_existing_parameters_preserved_and_no_resolve_not_duplicated(self):
        result = self.convert_rules(
            "IP-CIDR,192.0.2.1/32,REJECT,extended-matching,no-resolve,no-resolve",
            "IP-CIDR6,2001:db8::/32,REJECT,no-resolve",
        )
        self.assertIn(
            "IP-CIDR,192.0.2.1/32,REJECT,extended-matching,no-resolve\n", result
        )
        self.assertIn("IP-CIDR6,2001:db8::/32,REJECT,no-resolve\n", result)
        rule_body = "[Rule]" + result.split("[Rule]", 1)[1]
        again, _ = convert(rule_body)
        self.assertEqual(again, result)

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
