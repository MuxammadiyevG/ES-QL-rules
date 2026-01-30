# ES|QL Rules: GDPR + PCI DSS

A curated set of Elastic ES|QL detection rules mapped to GDPR and PCI DSS controls, plus a lightweight Flask dashboard to browse rules, test them against Elasticsearch, and preview sample hits.

## Features
- GDPR and PCI DSS rule packs in ES|QL
- Rule metadata embedded in each `.esql` file (mapping, rule id, title, description, MITRE)
- Flask dashboard for browsing, testing, and previewing hits
- All-time or time-window scans (dashboard uses all-time by default)

## Repository Layout
```
/dashboard          Flask app + static UI
/rules              ES|QL rule packs (GDPR, PCI-DSS)
/docs               Standard references
requirements.txt    Python deps
```

## Quick Start

### 1) Create venv and install deps
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Configure Elasticsearch
Update the connection in `dashboard/app.py`:
- `ELASTIC_URL`
- `ELASTIC_USER`
- `ELASTIC_PASS`

### 3) Run the dashboard
```
python dashboard/app.py
```
Then open: `http://127.0.0.1:5000`

## How Rules Work
Each rule file is a standalone ES|QL query with metadata headers:
```esql
// GDPR Mapping: Article ...
// GDPR Rule ID: RULE-XX
// Qoida nomi: ...
// Tavsif: ...
// MITRE ATT&CK: ...

FROM ...
| WHERE ...
| STATS ...
| EVAL rule_name = "..."
| EVAL severity = "..."
| KEEP ...
```

The dashboard parses these headers and displays them in the UI.

## Rule Testing Notes
- The dashboard runs each rule and shows hit count + sample rows.
- For full-history scans, the backend removes time filters and applies a safe `LIMIT 1000`.
- If you want time-bounded checks, add explicit time filters inside the rule.

## Adding New Rules
1. Create a new `.esql` file under the appropriate standard and category.
2. Include the metadata header fields.
3. Keep queries compatible with your index mappings.
4. Reload the dashboard (or refresh the page) to pick it up.

## Tips for Accuracy
- Use the correct index pattern and dataset for each rule.
- Narrow matches with precise `message RLIKE` patterns when full fields are not available.
- Avoid multi-value field pitfalls by using `MV_CONTAINS` for arrays.

## License
Internal / private use by default. Add a license if you plan to distribute.
