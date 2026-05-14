# detection-rules-collector
Collect vulnerability scanner rules (Sigma, YARA, Suricata, ClamAV entries)

## File structure:
We store the collected and parsed data in the `data` directory. For each Git repository URL, we generate a SHA-256 hash of the URL.

For example, for: `https://github.com/SigmaHQ/sigma` we store it as:
`data/sigma/006d8a4d6e3ea24949907ea9c22f1d5b06467ceaa9e35c49aa44866c854c8901`

For ClamAV entries, we store the parsed data in JSON files  
(e.g., `data/main_ldb.json`, `data/main_hdb.json`).

## JSON file structure
For (Sigma, YARA, Suricata):
```json
{
    "source_url": "https://...",
    "rules": [
        {
            "rule_metadata": {...},
            "rule_text": "...",
            "vulnerabilities": ["CVE-...", "GHSA-..."]
        }, 
      ...
    ]
}
```
For ClamAV entries, the JSON structure has an additional field called `source_filename` to indicate the origin file (e.g., main.ldb).

## Testing

Ensure you have `pytest` installed by running this command:
```bash
pip install pytest
```

Then, you can run the tests using this command:
```bash
python -m pytest test/ -v
```
