#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import yaml
from pipeline import BaseRulePipeline
from pipeline import get_related_vulnerabilities


class CollectSigmaRulesPipeline(BaseRulePipeline):
    rule_type = "sigma"
    rglob_patterns = ["**/*.yml"]

    def extract_metadata(self, document):
        """
        Extract Sigma metadata from a parsed Sigma YAML document
        """
        if not isinstance(document, dict):
            return {}

        metadata = {
            "status": document.get("status"),
            "author": document.get("author"),
            "date": document.get("date"),
            "title": document.get("title"),
            "id": document.get("id"),
        }

        rule_date = metadata.get("date")

        if isinstance(rule_date, (datetime.date, datetime.datetime)):
            metadata["date"] = rule_date.isoformat()

        return metadata

    def to_json(self, raw_text):
        results = []
        try:
            rule_documents = yaml.safe_load_all(raw_text)
            for document in rule_documents:
                specific_rule_text = yaml.dump(document, sort_keys=False)
                results.append({
                    "rule_metadata": self.extract_metadata(document),
                    "rule_text": specific_rule_text,
                    "vulnerabilities": get_related_vulnerabilities(specific_rule_text)
                })

        except yaml.YAMLError as e:
            self.log(f"Failed to parse Sigma YAML: {e}")

        return results

class SigmaHQImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/SigmaHQ/sigma"
    rglob_patterns = [
        "rules/**/*.yml",
        "rules-emerging-threats/**/*.yml",
        "rules-placeholder/**/*.yml",
        "rules-threat-hunting/**/*.yml",
        "rules-compliance/**/*.yml",
        "other/**/*.yml",
    ] # Ignore deprecated and unsupported directories.
    license_url = "https://github.com/SigmaHQ/Detection-Rule-License"
    license_expression = "DRL-1.1"


class SigmaSamuraiMDRImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/SamuraiMDR/sigma-rules"
    license_urls = "https://github.com/SamuraiMDR/sigma-rules/blob/main/LICENSE"
    license_expression = "DRL-1.1"

class SigmaMbabinskiImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/mbabinski/Sigma-Rules"
    license_urls = "https://github.com/mbabinski/Sigma-Rules/blob/main/LICENSE"
    license_expression = "GPL-3.0-only"

class P4T12ICKSigmaImproverPipeline(CollectSigmaRulesPipeline):
    repo_url = "https://github.com/P4T12ICK/Sigma-Rule-Repository"
    license_urls = (
        "https://github.com/P4T12ICK/Sigma-Rule-Repository/blob/master/LICENSE.md"
    )
    license_expression = "GPL-3.0-only"
