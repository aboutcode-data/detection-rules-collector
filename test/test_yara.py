#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock

import pytest

from rules.yara import YaraRulesPipeline


class TestYaraRulesPipeline:
    @pytest.fixture
    def yara_pipeline(self):
        return YaraRulesPipeline()

    def test_to_json_single_yara_rule(self, yara_pipeline):
        raw_text = """
        rule Linux_Exploit_CVE_2009_1897_6cf0a073 {
    meta:
        author = "Elastic Security"
        id = "6cf0a073-571e-48ef-be58-807bff1a5e97"
        fingerprint = "8fcb3687d4ec5dd467d937787f0659448a91446f92a476ff7ba471a02d6b07a9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Exploit.CVE-2009-1897"
        reference_sample = "85f371bf73ee6d8fcb6fa9a8a68b38c5e023151257fd549855c4c290cc340724"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 31 C0 85 DB 78 28 45 31 C9 41 89 D8 B9 02 00 00 00 BA 01 00 }
    condition:
        all of them
}
        """
        assert yara_pipeline.to_json(raw_text) == [
            {
                "rule_metadata": {
                    "arch_context": "x86",
                    "author": "Elastic Security",
                    "creation_date": "2021-01-12",
                    "fingerprint": "8fcb3687d4ec5dd467d937787f0659448a91446f92a476ff7ba471a02d6b07a9",
                    "id": "6cf0a073-571e-48ef-be58-807bff1a5e97",
                    "last_modified": "2021-09-16",
                    "license": "Elastic License v2",
                    "os": "linux",
                    "reference_sample": "85f371bf73ee6d8fcb6fa9a8a68b38c5e023151257fd549855c4c290cc340724",
                    "name": "Linux_Exploit_CVE_2009_1897_6cf0a073",
                    "scan_context": "file, memory",
                    "severity": 100,
                    "tags": [],
                    "threat_name": "Linux.Exploit.CVE-2009-1897",
                },
                "rule_text": "rule Linux_Exploit_CVE_2009_1897_6cf0a073\n"
                "{\n"
                "\tmeta:\n"
                '\t\tauthor = "Elastic Security"\n'
                '\t\tid = "6cf0a073-571e-48ef-be58-807bff1a5e97"\n'
                "\t\tfingerprint = "
                '"8fcb3687d4ec5dd467d937787f0659448a91446f92a476ff7ba471a02d6b07a9"\n'
                '\t\tcreation_date = "2021-01-12"\n'
                '\t\tlast_modified = "2021-09-16"\n'
                '\t\tthreat_name = "Linux.Exploit.CVE-2009-1897"\n'
                "\t\treference_sample = "
                '"85f371bf73ee6d8fcb6fa9a8a68b38c5e023151257fd549855c4c290cc340724"\n'
                "\t\tseverity = 100\n"
                '\t\tarch_context = "x86"\n'
                '\t\tscan_context = "file, memory"\n'
                '\t\tlicense = "Elastic License v2"\n'
                '\t\tos = "linux"\n'
                "\n"
                "\tstrings:\n"
                "\t\t$a = { 31 C0 85 DB 78 28 45 31 C9 41 89 D8 B9 02 00 00 00 "
                "BA 01 00 }\n"
                "\n"
                "\tcondition:\n"
                "\t\tall of them\n"
                "}\n",
                "vulnerabilities": ["CVE-2009-1897"],
            }
        ]

    def test_to_json_multiple_yara_rule(self, yara_pipeline):
        raw_text = """
rule Linux_Cryptominer_Roboto_0b6807f8 {
    meta:
        author = "Elastic Security"
        id = "0b6807f8-49c1-485f-9233-1a14f98935bc"
        fingerprint = "65f373b6e820c2a1fa555182b8e4547bf5853326bdf3746c7592d018dc2ed89f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Roboto"
        reference_sample = "c2542e399f865b5c490ee66b882f5ff246786b3f004abb7489ec433c11007dda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FB 49 89 CF 4D 0F AF FC 4D 01 DF 4D 89 CB 4C 0F AF D8 4D 01 FB 4D }
    condition:
        all of them
}

rule Linux_Cryptominer_Roboto_1f1cfe9a {
    meta:
        author = "Elastic Security"
        id = "1f1cfe9a-ab4a-423c-a62b-ead6901e2a86"
        fingerprint = "8dd9f4a091713b8992abd97474f66fdc7d34b0124f06022ab82942f88f3b330c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Roboto"
        reference_sample = "497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 20 85 FF 74 0D 39 FE 73 13 83 FE 0F 77 0E 01 F6 EB F3 BF 01 00 }
    condition:
        all of them
}
        """
        assert yara_pipeline.to_json(raw_text) == [
            {
                "rule_metadata": {
                    "arch_context": "x86",
                    "author": "Elastic Security",
                    "creation_date": "2021-01-12",
                    "fingerprint": "65f373b6e820c2a1fa555182b8e4547bf5853326bdf3746c7592d018dc2ed89f",
                    "id": "0b6807f8-49c1-485f-9233-1a14f98935bc",
                    "last_modified": "2021-09-16",
                    "license": "Elastic License v2",
                    "os": "linux",
                    "reference_sample": "c2542e399f865b5c490ee66b882f5ff246786b3f004abb7489ec433c11007dda",
                    "name": "Linux_Cryptominer_Roboto_0b6807f8",
                    "scan_context": "file, memory",
                    "severity": 100,
                    "tags": [],
                    "threat_name": "Linux.Cryptominer.Roboto",
                },
                "rule_text": "rule Linux_Cryptominer_Roboto_0b6807f8\n"
                "{\n"
                "\tmeta:\n"
                '\t\tauthor = "Elastic Security"\n'
                '\t\tid = "0b6807f8-49c1-485f-9233-1a14f98935bc"\n'
                "\t\tfingerprint = "
                '"65f373b6e820c2a1fa555182b8e4547bf5853326bdf3746c7592d018dc2ed89f"\n'
                '\t\tcreation_date = "2021-01-12"\n'
                '\t\tlast_modified = "2021-09-16"\n'
                '\t\tthreat_name = "Linux.Cryptominer.Roboto"\n'
                "\t\treference_sample = "
                '"c2542e399f865b5c490ee66b882f5ff246786b3f004abb7489ec433c11007dda"\n'
                "\t\tseverity = 100\n"
                '\t\tarch_context = "x86"\n'
                '\t\tscan_context = "file, memory"\n'
                '\t\tlicense = "Elastic License v2"\n'
                '\t\tos = "linux"\n'
                "\n"
                "\tstrings:\n"
                "\t\t$a = { FB 49 89 CF 4D 0F AF FC 4D 01 DF 4D 89 CB 4C 0F AF "
                "D8 4D 01 FB 4D }\n"
                "\n"
                "\tcondition:\n"
                "\t\tall of them\n"
                "}\n",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {
                    "arch_context": "x86",
                    "author": "Elastic Security",
                    "creation_date": "2021-01-12",
                    "fingerprint": "8dd9f4a091713b8992abd97474f66fdc7d34b0124f06022ab82942f88f3b330c",
                    "id": "1f1cfe9a-ab4a-423c-a62b-ead6901e2a86",
                    "last_modified": "2021-09-16",
                    "license": "Elastic License v2",
                    "os": "linux",
                    "reference_sample": "497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5",
                    "name": "Linux_Cryptominer_Roboto_1f1cfe9a",
                    "scan_context": "file, memory",
                    "severity": 100,
                    "tags": [],
                    "threat_name": "Linux.Cryptominer.Roboto",
                },
                "rule_text": "rule Linux_Cryptominer_Roboto_1f1cfe9a\n"
                "{\n"
                "\tmeta:\n"
                '\t\tauthor = "Elastic Security"\n'
                '\t\tid = "1f1cfe9a-ab4a-423c-a62b-ead6901e2a86"\n'
                "\t\tfingerprint = "
                '"8dd9f4a091713b8992abd97474f66fdc7d34b0124f06022ab82942f88f3b330c"\n'
                '\t\tcreation_date = "2021-01-12"\n'
                '\t\tlast_modified = "2021-09-16"\n'
                '\t\tthreat_name = "Linux.Cryptominer.Roboto"\n'
                "\t\treference_sample = "
                '"497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5"\n'
                "\t\tseverity = 100\n"
                '\t\tarch_context = "x86"\n'
                '\t\tscan_context = "file, memory"\n'
                '\t\tlicense = "Elastic License v2"\n'
                '\t\tos = "linux"\n'
                "\n"
                "\tstrings:\n"
                "\t\t$a = { 24 20 85 FF 74 0D 39 FE 73 13 83 FE 0F 77 0E 01 F6 "
                "EB F3 BF 01 00 }\n"
                "\n"
                "\tcondition:\n"
                "\t\tall of them\n"
                "}\n",
                "vulnerabilities": [],
            },
        ]

    def test_to_json_invalid_yara_rule(self, yara_pipeline):
        yara_pipeline.log = MagicMock()
        raw_text = "malformed YARA rule raw text"
        assert yara_pipeline.to_json(raw_text) == []
        yara_pipeline.log.assert_called_once()
        log_message = yara_pipeline.log.call_args[0][0]
        assert "Skipping malformed YARA rule due to parser error" in log_message
