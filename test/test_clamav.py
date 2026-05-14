#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from rules.clamav import parse_hdb_file, parse_ldb_file, parse_ndb_file


class TestClamAVParsers:
    def test_parse_ldb_file(self, tmp_path):
        ldb_content = """
Win.Exploit.CVE_2016_7185-1;Engine:51-255,Target:1;(0&1&2&3);44616e6765726f757347657448616e646c65;5361666548616e646c655a65726f4f724d696e75734f6e654973496e76616c6964;52656c6561736548616e646c65;5c004400650076006900630065005c0044006600730043006c00690065006e007400
Doc.Trojan.Agent-1383193;Engine:53-255,Target:2;0&1&2&3&4;57683370314d4c73576c69454b30626476376d707563704156724856585141694f30383755365a48556f;507a33593934674e796c784e724d5937706a3068;586c49766b65446349324259514d5169556b764d436165345144415452746d3842;434c70577561534d6f4c4845437a4172754d4d6466484b3334444e78;4256504271623368394c6e6c
Doc.Trojan.Agent-1383194;Engine:53-255,Target:2;0&1>50;28373835362920417320427974652c20;3d2059656172284e6f77292027
Win.Trojan.Generic-39;Engine:51-255,IconGroup1:FAKESEC,Target:1;(0|1);EP+0:558bec6aff68{-150}148bcd87cc588be8ff1508200014ff1508200014cd2e;EP+0:558bec6aff68{-150}148bc881e1ff000000890d
        """
        ldb_file = tmp_path / "main.ldb"
        ldb_file.write_text(ldb_content)

        results = list(parse_ldb_file(ldb_file))
        assert (
            results
            == [
                {
                    "rule_metadata": {
                        "line_num": 2,
                        "name": "Win.Exploit.CVE_2016_7185-1",
                    },
                    "rule_text": "Win.Exploit.CVE_2016_7185-1;Engine:51-255,Target:1;(0&1&2&3);44616e6765726f757347657448616e646c65;5361666548616e646c655a65726f4f724d696e75734f6e654973496e76616c6964;52656c6561736548616e646c65;5c004400650076006900630065005c0044006600730043006c00690065006e007400",
                    "vulnerabilities": ["CVE-2016-7185"],
                },
                {
                    "rule_metadata": {
                        "line_num": 3,
                        "name": "Doc.Trojan.Agent-1383193",
                    },
                    "rule_text": "Doc.Trojan.Agent-1383193;Engine:53-255,Target:2;0&1&2&3&4;57683370314d4c73576c69454b30626476376d707563704156724856585141694f30383755365a48556f;507a33593934674e796c784e724d5937706a3068;586c49766b65446349324259514d5169556b764d436165345144415452746d3842;434c70577561534d6f4c4845437a4172754d4d6466484b3334444e78;4256504271623368394c6e6c",
                    "vulnerabilities": [],
                },
                {
                    "rule_metadata": {
                        "line_num": 4,
                        "name": "Doc.Trojan.Agent-1383194",
                    },
                    "rule_text": "Doc.Trojan.Agent-1383194;Engine:53-255,Target:2;0&1>50;28373835362920417320427974652c20;3d2059656172284e6f77292027",
                    "vulnerabilities": [],
                },
                {
                    "rule_metadata": {"line_num": 5, "name": "Win.Trojan.Generic-39"},
                    "rule_text": "Win.Trojan.Generic-39;Engine:51-255,IconGroup1:FAKESEC,Target:1;(0|1);EP+0:558bec6aff68{-150}148bcd87cc588be8ff1508200014ff1508200014cd2e;EP+0:558bec6aff68{-150}148bc881e1ff000000890d",
                    "vulnerabilities": [],
                },
            ]
            != [
                {
                    "raw_text": "Win.Exploit.CVE_2016_7185-1;Engine:51-255,Target:1;(0&1&2&3);44616e6765726f757347657448616e646c65;5361666548616e646c655a65726f4f724d696e75734f6e654973496e76616c6964;52656c6561736548616e646c65;5c004400650076006900630065005c0044006600730043006c00690065006e007400",
                    "rule_metadata": {
                        "line_num": 2,
                        "name": "Win.Exploit.CVE_2016_7185-1",
                    },
                    "vulnerabilities": ["CVE-2016-7185"],
                },
                {
                    "raw_text": "Doc.Trojan.Agent-1383193;Engine:53-255,Target:2;0&1&2&3&4;57683370314d4c73576c69454b30626476376d707563704156724856585141694f30383755365a48556f;507a33593934674e796c784e724d5937706a3068;586c49766b65446349324259514d5169556b764d436165345144415452746d3842;434c70577561534d6f4c4845437a4172754d4d6466484b3334444e78;4256504271623368394c6e6c",
                    "rule_metadata": {
                        "line_num": 3,
                        "name": "Doc.Trojan.Agent-1383193",
                    },
                    "vulnerabilities": [],
                },
                {
                    "raw_text": "Doc.Trojan.Agent-1383194;Engine:53-255,Target:2;0&1>50;28373835362920417320427974652c20;3d2059656172284e6f77292027",
                    "rule_metadata": {
                        "line_num": 4,
                        "name": "Doc.Trojan.Agent-1383194",
                    },
                    "vulnerabilities": [],
                },
                {
                    "raw_text": "Win.Trojan.Generic-39;Engine:51-255,IconGroup1:FAKESEC,Target:1;(0|1);EP+0:558bec6aff68{-150}148bcd87cc588be8ff1508200014ff1508200014cd2e;EP+0:558bec6aff68{-150}148bc881e1ff000000890d",
                    "rule_metadata": {"line_num": 5, "name": "Win.Trojan.Generic-39"},
                    "vulnerabilities": [],
                },
            ]
        )

    def test_parse_ndb_file(self, tmp_path):
        ndb_content = """
Legacy.Trojan.Agent-1:0:*:dd6d70241f674d8fc13e1eb3af731a7b5c43173c1cdd75722fa556c373b65c5275d513147b070077757064080386898ae75c6fb7f717b562ef636f6d6d613f2e0e202f6336c5eed52064f120228e2f6d27c101
Win.Trojan.Hotkey-1:0:*:c01640006a3cffb684000000ff159cef420089869800000089be940000008bc75f5ec20400565733ff8bf1397c240c741fff762089be8c000000ff1560ef42
Doc.Trojan.Nori-1:0:*:6d706f6e656e74732e4974656d28556e292e436f64654d6f64756c652e4c696e657328322c203129203c3e20222749726f6e22205468656e
Doc.Trojan.Layla-1:0:*:6572436f707920536f757263653a3d4b544f2c2044657374696e6174696f6e3a3d4b4f474f2c204e616d653a3d224d6143524f534f4654222c204f626a6563743a3d77644f7267616e697a
Win.Worm.Gaobot-1:0:*:3467072092830ddc2d8a88a47d904500811b760af9089389402573087f2bb8fc4e49434b200d0abf626f742e7365ffdbfff263757265656c657465207368610d73202f206469736162dbdf7b6b1207636f6d3b2b666c751f64dcd6c5de6e730f0b297404201bfb597bd70817206361630e2b7175697427ff60c9de0725476c6f        
        """
        ndb_file = tmp_path / "main.ndb"
        ndb_file.write_text(ndb_content)

        results = list(parse_ndb_file(ndb_file))
        assert results == [
            {
                "rule_metadata": {"line_num": 2, "name": "Legacy.Trojan.Agent-1"},
                "rule_text": "Legacy.Trojan.Agent-1:0:*:dd6d70241f674d8fc13e1eb3af731a7b5c43173c1cdd75722fa556c373b65c5275d513147b070077757064080386898ae75c6fb7f717b562ef636f6d6d613f2e0e202f6336c5eed52064f120228e2f6d27c101",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 3, "name": "Win.Trojan.Hotkey-1"},
                "rule_text": "Win.Trojan.Hotkey-1:0:*:c01640006a3cffb684000000ff159cef420089869800000089be940000008bc75f5ec20400565733ff8bf1397c240c741fff762089be8c000000ff1560ef42",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 4, "name": "Doc.Trojan.Nori-1"},
                "rule_text": "Doc.Trojan.Nori-1:0:*:6d706f6e656e74732e4974656d28556e292e436f64654d6f64756c652e4c696e657328322c203129203c3e20222749726f6e22205468656e",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 5, "name": "Doc.Trojan.Layla-1"},
                "rule_text": "Doc.Trojan.Layla-1:0:*:6572436f707920536f757263653a3d4b544f2c2044657374696e6174696f6e3a3d4b4f474f2c204e616d653a3d224d6143524f534f4654222c204f626a6563743a3d77644f7267616e697a",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 6, "name": "Win.Worm.Gaobot-1"},
                "rule_text": "Win.Worm.Gaobot-1:0:*:3467072092830ddc2d8a88a47d904500811b760af9089389402573087f2bb8fc4e49434b200d0abf626f742e7365ffdbfff263757265656c657465207368610d73202f206469736162dbdf7b6b1207636f6d3b2b666c751f64dcd6c5de6e730f0b297404201bfb597bd70817206361630e2b7175697427ff60c9de0725476c6f",
                "vulnerabilities": [],
            },
        ]

    def test_parse_hdb_file(self, tmp_path):
        hdb_content = """
c2dce914a3803fd30cc6ce06a37ba987:53248:Win.Trojan.Agent-29922
c6f7026877251295e38b6c778621139a:33508:Win.Trojan.Agent-29924
850afc62ff1830009eb54ea4990750fe:37376:Win.Trojan.Oficla-1
139cde5b3f607e75f55bddbb066f953b:38400:Win.Trojan.VB-178
ad1a3f6849e957a7a8e010bda7c9f3a3:1171:Win.Trojan.SMS-40
854226cb25a9cc7f8d614bf66c81cf91:417280:Win.Exploit.CVE_2008_0081-1
        """
        hdb_file = tmp_path / "main.hdb"
        hdb_file.write_text(hdb_content)

        results = list(parse_hdb_file(hdb_file))
        assert results == [
            {
                "rule_metadata": {"line_num": 2, "name": "Win.Trojan.Agent-29922"},
                "rule_text": "c2dce914a3803fd30cc6ce06a37ba987:53248:Win.Trojan.Agent-29922",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 3, "name": "Win.Trojan.Agent-29924"},
                "rule_text": "c6f7026877251295e38b6c778621139a:33508:Win.Trojan.Agent-29924",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 4, "name": "Win.Trojan.Oficla-1"},
                "rule_text": "850afc62ff1830009eb54ea4990750fe:37376:Win.Trojan.Oficla-1",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 5, "name": "Win.Trojan.VB-178"},
                "rule_text": "139cde5b3f607e75f55bddbb066f953b:38400:Win.Trojan.VB-178",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 6, "name": "Win.Trojan.SMS-40"},
                "rule_text": "ad1a3f6849e957a7a8e010bda7c9f3a3:1171:Win.Trojan.SMS-40",
                "vulnerabilities": [],
            },
            {
                "rule_metadata": {"line_num": 7, "name": "Win.Exploit.CVE_2008_0081-1"},
                "rule_text": "854226cb25a9cc7f8d614bf66c81cf91:417280:Win.Exploit.CVE_2008_0081-1",
                "vulnerabilities": ["CVE-2008-0081"],
            },
        ]
