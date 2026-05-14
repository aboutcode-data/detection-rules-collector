#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
import re
from pathlib import Path

from aboutcode.pipeline import BasePipeline
from fetchcode.vcs import fetch_via_vcs


class BaseRulePipeline(BasePipeline):
    repo_url = None
    license_url = None
    license_expression = None
    rule_type = None
    rglob_patterns = []

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_rules,
        )

    def clone_repo(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(f"git+{self.repo_url}")

    def collect_and_store_rules(self):
        base_directory = Path(self.vcs_response.dest_dir)
        repo_hash = hashlib.sha256(str(self.repo_url).encode('utf-8')).hexdigest()
        output_dir = Path("data") / self.rule_type / repo_hash

        file_paths = set()
        for pattern in self.rglob_patterns:
            file_paths.update(p for p in base_directory.glob(pattern) if p.is_file())

        for file_path in file_paths:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
            rules_data = self.to_json(raw_text)

            relative_path = file_path.relative_to(base_directory)
            target_path = (output_dir / relative_path).with_suffix('.json')
            target_path.parent.mkdir(parents=True, exist_ok=True)

            source_url = f"{self.repo_url}/blob/master/{relative_path}"
            processed_data = {
                "source_url": source_url,
                "rules": rules_data
            }

            with open(target_path, 'w', encoding='utf-8') as f:
                json.dump(processed_data, f, indent=4, ensure_ascii=False)

    def extract_metadata(self, raw_text):
       raise NotImplementedError

    def to_json(self, text):
        raise NotImplementedError


def get_related_vulnerabilities(raw_text):
    """
    Find all CVE-id or GHSA-id in a rule text
    ex:
    >>> get_related_vulnerabilities("rule LOG_SUSP_EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22_")
    ['CVE-2022-22954']

    >>> get_related_vulnerabilities("Detects payload as seen in PoC code to exploit Workspace ONE Access freemarker server-side template injection CVE-2022-22954")
    ['CVE-2022-22954']

    >>> sorted(get_related_vulnerabilities("Detects suspicious file writes ... such as CVE-2025-49704, CVE-2025-49706 or CVE-2025-53770. "))
    ['CVE-2025-49704', 'CVE-2025-49706', 'CVE-2025-53770']

    >>> get_related_vulnerabilities("Found a GitHub advisory GHSA-cxv9-cxv9-cxv9 in the text")
    ['GHSA-CXV9-CXV9-CXV9']

    >>> get_related_vulnerabilities("No valid CVE- in this text")
    set()
    """
    patterns = [
        r"CVE[-_]\d{4}[-_]\d{4,19}",
        r"GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}"
    ]

    vuln_regex = re.compile(r"|".join(patterns), re.IGNORECASE)
    matches = vuln_regex.findall(raw_text)
    unique_matches = list(set([vuln.upper().replace("_", "-") for vuln in matches]))
    return unique_matches if unique_matches else []
