#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import gzip
import io
import json
import tarfile
import tempfile
from pathlib import Path

import requests
from aboutcode.pipeline import BasePipeline
from pipeline import get_related_vulnerabilities


def extract_cvd(cvd_path, output_dir):
    """
    Extract a CVD file. CVD format: 512-byte header + gzipped tar archive and returns Path to output directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(cvd_path, "rb") as f:
        f.seek(512)  # Skip header
        compressed_data = f.read()

    decompressed_data = gzip.decompress(compressed_data)
    tar_buffer = io.BytesIO(decompressed_data)

    with tarfile.open(fileobj=tar_buffer, mode="r:") as tar:
        tar.extractall(path=output_path)

    for file in output_path.rglob("*"):
        if file.is_file():
            file.chmod(0o644)  # rw-r--r--
    return output_path


def parse_ndb_file(ndb_path: Path):
    """Parse a .ndb file (extended signatures) and yields dicts"""
    with ndb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, raw_text in enumerate(f, 1):
            raw_text = raw_text.strip()
            if not raw_text:
                continue

            parts = raw_text.split(":")
            rule_metadata = {
                "name": parts[0],
                "line_num": line_num,
            }

            if raw_text.startswith("#"):
                rule_metadata['enabled'] = True

            yield {
                "rule_metadata": rule_metadata,
                "rule_text": raw_text,
                "vulnerabilities": get_related_vulnerabilities(raw_text),
            }


def parse_hdb_file(hdb_path: Path):
    """Parse a .hdb file (MD5 hash signatures) and yields dicts"""
    with hdb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, raw_text in enumerate(f, 1):
            raw_text = raw_text.strip()
            if not raw_text:
                continue

            parts = raw_text.split(":")
            rule_metadata = {
                "name": parts[2],
                "line_num": line_num,
            }

            if raw_text.startswith("#"):
                rule_metadata['enabled'] = True

            yield {
                "rule_metadata": rule_metadata,
                "rule_text": raw_text,
                "vulnerabilities": get_related_vulnerabilities(raw_text),
            }


def parse_ldb_file(ldb_path: Path):
    """Parse a .ldb file ( Logical signatures ) and yields dicts"""
    with ldb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, raw_text in enumerate(f, 1):
            raw_text = raw_text.strip()
            if not raw_text:
                continue

            parts = raw_text.split(";")
            rule_metadata = {
                "name": parts[0],
                "line_num": line_num,
            }

            if raw_text.startswith("#"):
                rule_metadata['enabled'] = True

            yield {
                "rule_metadata": rule_metadata,
                "rule_text": raw_text,
                "vulnerabilities": get_related_vulnerabilities(raw_text),
            }


class ClamAVPipeline(BasePipeline):
    """
    Pipeline that downloads ClamAV database (main.cvd), extracts signatures,
    parses .ndb , .hdb and ldb files and save the in json files
    """

    database_url = "https://database.clamav.net/main.cvd?api-version=1"
    license_url = "https://github.com/Cisco-Talos/clamav/blob/c73755d3fc130b0c60ccf4e8f8d28c62fc58c95b/README.md#licensing"
    license_expression = "GPL-2.0-only"
    rule_type = "clamv"

    @classmethod
    def steps(cls):
        return (
            cls.download_database,
            cls.extract_database,
            cls.collect_and_store,
        )

    def download_database(self):
        """Download ClamAV database using the supported API with proper headers."""

        self.log("Downloading ClamAV database…")
        self.db_dir = Path(tempfile.mkdtemp()) / "clamav_db"
        self.db_dir.mkdir(parents=True, exist_ok=True)

        headers = {
            "User-Agent": "ClamAV-Client/1.0",
            "Accept": "*/*",
        }

        filename = self.db_dir / "main.cvd"
        self.log(f"Downloading {self.database_url} → {filename}")

        resp = requests.get(self.database_url, headers=headers, stream=True, timeout=30)
        resp.raise_for_status()

        with filename.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        self.log("ClamAV DB file downloaded successfully.")

    def extract_database(self):
        """Extract the downloaded CVD into a directory"""
        out_dir = self.db_dir / "extracted"
        self.extract_cvd_dir = extract_cvd(self.db_dir / "main.cvd", out_dir)
        self.log(f"Extracted CVD to {self.extract_cvd_dir}")

    def collect_and_store(self):
        """Parse .ldb, .ndb and .hdb files and store rules in a JSON file"""
        target_path = Path("data") / self.rule_type
        target_path.mkdir(parents=True, exist_ok=True)

        clamav_parser_map = {
            "main_ldb.json": (parse_ldb_file, "main.ldb"),
            "main_hdb.json": (parse_hdb_file, "main.hdb"),
            "main_ndb.json": (parse_ndb_file, "main.ndb"),
        }

        for output_filename, (parser_func, source_filename) in clamav_parser_map.items():
            source_file_path = self.extract_cvd_dir / source_filename

            rules = list(parser_func(source_file_path))
            output_file = target_path / output_filename

            with output_file.open("w", encoding="utf-8") as f:
                json.dump({
                    "source_url": self.database_url,
                    "source_filename": source_filename,
                    "rules": rules,
                }, f, indent=4)

            self.log(f"Successfully saved {len(rules)} ClamAV entries to {output_file}")