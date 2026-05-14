#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from rules.suricata import SuricataRulesPipeline


class TestSuricataRulesPipeline:
    @pytest.fixture
    def suricata_pipeline(self):
        return SuricataRulesPipeline()

    def test_to_json_suricata_rules(self, suricata_pipeline):
        raw_text = """
# Decoder event signatures for Suricata.
# SID's fall in the 2200000+ range. See http://doc.emergingthreats.net/bin/view/Main/SidAllocation        
alert pkthdr any any -> any any (msg:"SURICATA IPv4 malformed option"; decode-event:ipv4.opt_malformed; classtype:protocol-command-decode; sid:2200006; rev:2;)
#alert pkthdr any any -> any any (msg:"SURICATA IPv4 padding required "; decode-event:ipv4.opt_pad_required; classtype:protocol-command-decode; sid:2200007; rev:2;)
        """

        results = suricata_pipeline.to_json(raw_text)

        assert results == [
            {
                "vulnerabilities": [],
                "rule_metadata": {
                    "enabled": True,
                    "id": 2200006,
                    "name": "SURICATA IPv4 malformed option",
                    "version": 2,
                },
                "rule_text": 'alert pkthdr any any -> any any (msg:"SURICATA IPv4 malformed '
                'option"; decode-event:ipv4.opt_malformed; '
                "classtype:protocol-command-decode; sid:2200006; rev:2;)",
            },
            {
                "vulnerabilities": [],
                "rule_metadata": {
                    "enabled": False,
                    "id": 2200007,
                    "name": "SURICATA IPv4 padding required ",
                    "version": 2,
                },
                "rule_text": 'alert pkthdr any any -> any any (msg:"SURICATA IPv4 padding '
                'required "; decode-event:ipv4.opt_pad_required; '
                "classtype:protocol-command-decode; sid:2200007; rev:2;)",
            },
        ]

    def test_to_json_empty_rules(self, suricata_pipeline):
        results = suricata_pipeline.to_json("text invalid suricata rule")
        assert results == []
