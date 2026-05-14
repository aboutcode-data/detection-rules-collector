#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from pipeline import BaseRulePipeline
from suricataparser import parse_rules
from pipeline import get_related_vulnerabilities

class SuricataRulesPipeline(BaseRulePipeline):
    rule_type = "suricata"
    rglob_patterns = ["**/*.rules", "**/*.rule"]

    def extract_metadata(self, rule):
        """
        Extract Suricata metadata from a parsed Suricata rule
        """
        return {
            "name": rule.msg,
            "version": rule.rev,
            "id": rule.sid,
            "enabled": rule.enabled,
        }

    def to_json(self, raw_text):
        rules_data = []
        for current_rule in parse_rules(raw_text):
            rules_data.append({
                "rule_metadata": self.extract_metadata(current_rule),
                "rule_text": current_rule.raw,
                "vulnerabilities": get_related_vulnerabilities(current_rule.raw)
            })
        return rules_data

class SudohyakSuricataPipeline(SuricataRulesPipeline):
    repo_url = "https://github.com/sudohyak/suricata-rules"
    license_url = "https://github.com/sudohyak/suricata-rules/blob/main/LICENSE"
    license_expression = "GPL-3.0-only"

class OISFSuricataPipeline(SuricataRulesPipeline):
    repo_url = "https://github.com/OISF/suricata"
    rglob_patterns = ["rules/**/*.rules"]
    license_url = "https://github.com/OISF/suricata?tab=GPL-2.0-2-ov-file"
    license_expression = "GPL-2.0-only"
