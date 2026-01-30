import os
import re

import urllib3
from elasticsearch import Elasticsearch
from elasticsearch import ApiError
from flask import Flask, jsonify, render_template, request

# Suppress insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

RULES_BASE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "rules"))

# Elasticsearch Configuration
ELASTIC_URL = ""
ELASTIC_USER = ""
ELASTIC_PASS = ""

es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(ELASTIC_USER, ELASTIC_PASS),
    request_timeout=60,  # Increase timeout for heavy ES|QL queries
)


def parse_esql_metadata(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    metadata = {
        "mapping": "",
        "rule_id": "",
        "title": "",
        "description": "",
        "mitre": "",
        "query": "",
    }

    mapping_match = re.search(r"// (?:GDPR|PCI DSS) Mapping: (.*)", content)
    id_match = re.search(r"// (?:GDPR|PCI DSS) Rule ID: (.*)", content)
    title_match = re.search(r"// Qoida nomi: (.*)", content)
    desc_match = re.search(r"// Tavsif: (.*)", content)
    mitre_match = re.search(r"// MITRE ATT&CK: (.*)", content)

    if mapping_match:
        metadata["mapping"] = mapping_match.group(1).strip()
    if id_match:
        metadata["rule_id"] = id_match.group(1).strip()
    if title_match:
        metadata["title"] = title_match.group(1).strip()
    if desc_match:
        metadata["description"] = desc_match.group(1).strip()
    if mitre_match:
        metadata["mitre"] = mitre_match.group(1).strip()

    query = re.sub(r"//.*?\n", "", content).strip()
    metadata["query"] = query

    return metadata


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/rules")
def get_rules():
    all_rules = []
    for source in ["GDPR", "PCI-DSS"]:
        source_path = os.path.join(RULES_BASE_DIR, source)
        if not os.path.exists(source_path):
            continue

        for category in os.listdir(source_path):
            cat_path = os.path.join(source_path, category)
            if not os.path.isdir(cat_path):
                continue

            for rule_file in os.listdir(cat_path):
                if rule_file.endswith(".esql"):
                    file_path = os.path.join(cat_path, rule_file)
                    metadata = parse_esql_metadata(file_path)
                    metadata["source"] = source
                    metadata["category"] = category
                    metadata["filename"] = rule_file
                    metadata["status"] = "idle"
                    metadata["hits"] = 0
                    all_rules.append(metadata)

    return jsonify(all_rules)


@app.route("/api/test_rule", methods=["POST"])
def test_rule():
    data = request.json
    query = data.get("query") if isinstance(data, dict) else None
    all_time = bool(data.get("all_time")) if isinstance(data, dict) else False

    if not query or not isinstance(query, str):
        return jsonify({"status": "error", "message": "Query is missing or invalid."}), 400

    if all_time:
        # Remove standalone time filters for full-history scans.
        lines = query.splitlines()
        lines = [ln for ln in lines if not re.search(r"^\s*\|\s*WHERE\s+@timestamp\s*>=\s*NOW\(\)\s*-", ln)]
        query = "\n".join(lines)
        # Remove inline time filter segments (one-line queries).
        query = re.sub(
            r"\|\s*WHERE\s+@timestamp\s*>=\s*NOW\(\)\s*-[^|\n]+",
            "",
            query,
        )

    try:
        # Ensure a limit to avoid huge scans.
        if " LIMIT " not in query.upper():
            query = f"{query}\n| LIMIT 1000"
        # Execute ES|QL query
        client = es.options(request_timeout=180 if all_time else 60)
        res = client.esql.query(query=query)
        hits_count = len(res.get("values", []))
        return jsonify(
            {
                "status": "success",
                "hits": hits_count,
                # Return first 10 for preview
                "details": res.get("values", [])[:10],
            }
        )
    except ApiError as e:
        app.logger.exception("ES|QL query failed")
        status = e.status_code if isinstance(e.status_code, int) else 500
        return jsonify({"status": "error", "message": str(e)}), status
    except Exception as e:
        app.logger.exception("Unexpected error while executing ES|QL query")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=5000, use_reloader=debug)
