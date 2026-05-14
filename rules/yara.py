#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pipeline import BaseRulePipeline
from pipeline import get_related_vulnerabilities
import plyara
from plyara.utils import rebuild_yara_rule
from plyara.exceptions import ParseTypeError

class YaraRulesPipeline(BaseRulePipeline):
    rule_type = "yara"
    rglob_patterns = [
        "**/*.yara",
        "**/*.yar",
    ]

    def extract_metadata(self, parsed_rule):
        """
        Extract Yara metadata from a parsed Yara rule
        """
        metadata = {
            "name": parsed_rule.get("rule_name"),
            "tags": parsed_rule.get("tags", [])
        }
        for entry in parsed_rule.get("metadata", []):
            metadata.update(entry)
        return metadata

    def to_json(self, raw_text):
        parser = plyara.Plyara()
        try:
            parsed_rules = parser.parse_string(raw_text)
        except ParseTypeError as e:
            self.log(f"Skipping malformed YARA rule due to parser error: {e}")
            return []

        results = []
        for rule in parsed_rules:
            rule_metadata = self.extract_metadata(rule)
            rule_text = rebuild_yara_rule(rule)
            results.append({
                "rule_metadata": rule_metadata,
                "rule_text": rule_text,
                "vulnerabilities": get_related_vulnerabilities(raw_text)
            })
        return results


class ProtectionsArtifactsYara(YaraRulesPipeline):
    repo_url = "https://github.com/elastic/protections-artifacts"
    rglob_patterns = ["yara/rules/**/*.yar"]
    license_url = "https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt"
    license_expression = "elastic-license-v2"

class YaraRulesYara(YaraRulesPipeline):
    repo_url = "https://github.com/Yara-Rules/rules"
    license_url = "https://github.com/Yara-Rules/rules/blob/master/LICENSE"
    rglob_patterns = [
        "antidebug_antivm/**/*.yar",
        "capabilities/**/*.yar",
        "crypto/**/*.yar",
        "cve_rules/**/*.yar",
        "deprecated/**/*.yar",
        "email/**/*.yar",
        "exploit_kits/**/*.yar",
        "maldocs/**/*.yar",
        "malware/**/*.yar",
        "mobile_malware/**/*.yar",
        "packers/**/*.yar",
        "utils/**/*.yar",
        "webshells/**/*.yar",
    ]
    license_expression = "GPL-3.0-only"


class XumeiquerForensicsYara(YaraRulesPipeline):
    repo_url = "https://github.com/Xumeiquer/yara-forensics"
    license_url = "https://github.com/Xumeiquer/yara-forensics/blob/master/LICENSE"
    license_expression = "GPL-3.0-only"

class ReversinglabsYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/reversinglabs/reversinglabs-yara-rules"
    license_url = (
        "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/LICENSE"
    )
    license_expression = "MIT"


class AdvancedThreatResearchYara(YaraRulesPipeline):
    repo_url = "https://github.com/advanced-threat-research/Yara-Rules"
    license_url = (
        "https://github.com/advanced-threat-research/Yara-Rules/blob/master/LICENSE"
    )
    license_expression = "Apache-2.0"


class BartblazeYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/bartblaze/Yara-rules"
    license_url = "https://github.com/bartblaze/Yara-rules/blob/master/LICENSE"
    license_expression = "MIT"

class GodaddyYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/godaddy/yara-rules"  # archived
    license_url = "https://github.com/godaddy/yara-rules/blob/master/LICENSE.md"
    license_expression = "MIT"

class SupportIntelligenceIcewaterYara(YaraRulesPipeline):
    repo_url = "https://github.com/SupportIntelligence/Icewater"
    license_url = "https://github.com/SupportIntelligence/Icewater/blob/master/LICENSE"
    license_expression = "LicenseRef-scancode-ril-2019"

class Jeff0FalltradesSignaturesYara(YaraRulesPipeline):
    repo_url = "https://github.com/jeFF0Falltrades/YARA-Signatures"
    license_url = (
        "https://github.com/jeFF0Falltrades/YARA-Signatures/blob/master/LICENSE.md"
    )
    license_expression = "DRL-1.1"

class TjnelRepoYara(YaraRulesPipeline):
    repo_url = "https://github.com/tjnel/yara_repo"
    license_url = "https://github.com/tjnel/yara_repo/blob/master/LICENSE"
    license_expression = "MIT"

class JpcertccJpcertYara(YaraRulesPipeline):
    repo_url = "https://github.com/JPCERTCC/jpcert-yara"
    license_url = "https://github.com/JPCERTCC/jpcert-yara/blob/main/LICENSE"
    license_expression = "BSD-3-Clause"

class MikesxrsOpenSourceYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/mikesxrs/Open-Source-YARA-rules"

class FboldewinYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/fboldewin/YARA-rules"

class H3x2bYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/h3x2b/yara-rules"

class RoadwyDefenderYara(YaraRulesPipeline):
    repo_url = "https://github.com/roadwy/DefenderYara"

class MthchtThreatHuntingKeywordsYara(YaraRulesPipeline):
    repo_url = "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules"
    license_url = (
        "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules/blob/main/LICENSE"
    )
    license_expression = "LicenseRef-scancode-drul-1.0"

class Neo23x0SignatureBaseYara(YaraRulesPipeline):
    repo_url = "https://github.com/Neo23x0/signature-base"

class MalpediaSignatorRulesYara(YaraRulesPipeline):
    repo_url = "https://github.com/malpedia/signator-rules"
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"
    license_expression = "CC-BY-SA-4.0"

class BaderjYara(YaraRulesPipeline):
    repo_url = "https://github.com/baderj/yara"
    license_url = "https://github.com/baderj/yara/blob/main/LICENSE"
    license_expression = "MIT"

class DeadbitsYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/deadbits/yara-rules"
    license_url = "https://github.com/deadbits/yara-rules/blob/master/UNLICENSE"
    license_expression = "Unlicense"

class PmelsonYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/pmelson/yara_rules"

class SbousseadenYaraHunts(YaraRulesPipeline):
    repo_url = "https://github.com/sbousseaden/YaraHunts"

class EmbeeResearchYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/embee-research/Yara-detection-rules"
    license_url = "https://github.com/embee-research/Yara-detection-rules/tree/main?tab=readme-ov-file#detection-rule-license-drl-11"
    license_expression = "DRL-1.1"

class RussianPanda95YaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/RussianPanda95/Yara-Rules"

class AilProjectAilYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/ail-project/ail-yara-rules"
    license_url = "https://github.com/ail-project/ail-yara-rules?tab=AGPL-3.0-1-ov-file"
    license_expression = "AGPL-3.0-only"

class MalgamyYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/MalGamy/YARA_Rules"
    license_url = "https://github.com/MalGamy/YARA_Rules/blob/main/LICENSE.md"
    license_expression = "DRL-1.1"

class ElceefYaraRulz(YaraRulesPipeline):
    repo_url = "https://github.com/elceef/yara-rulz"
    license_url = "https://github.com/elceef/yara-rulz/tree/main?tab=MIT-1-ov-file"
    license_expression = "MIT"

class TenableYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/tenable/yara-rules"
    license_url = (
        "https://github.com/tenable/yara-rules/tree/master?tab=BSD-3-Clause-1-ov-file"
    )
    license_expression = "BSD-3-Clause"

class Dr4k0niaYaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/dr4k0nia/yara-rules"
    license_url = "https://github.com/dr4k0nia/yara-rules/blob/main/LICENSE.md"
    license_expression = "DRL-1.1"

class Umair9747YaraRules(YaraRulesPipeline):
    repo_url = "https://github.com/umair9747/yara-rules"
    license_url = "https://github.com/umair9747/yara-rules?tab=GPL-3.0-1-ov-file"
    license_expression = "GPL-3.0-only"