import argparse
import json
import sys
from pathlib import Path

from soc_automation.enrichment.engine import enrich_alert
from soc_automation.ingestion import ingest_wazuh_alert_file
from soc_automation.integrity import calculate_sha256
from soc_automation.triage import filter_by_severity, generate_summary_report


def main() -> int:
    """
    Command-line interface for the Python SOC Automation Engine.

    Accepts a Wazuh JSON alert file, processes it,
    and optionally enables enrichment, SHA-256,
    alert triage, and output export.
    """

    parser = argparse.ArgumentParser(
        description="Python SOC Automation Engine - Wazuh Alert Processor"
    )

    parser.add_argument(
        "input_file",
        help="Path to the Wazuh JSON alert file.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional path to save the processed output.",
    )

    parser.add_argument(
        "--sha256",
        action="store_true",
        help="Calculate SHA-256 integrity hash of the original file.",
    )

    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Enable alert enrichment using local datasets.",
    )

    parser.add_argument(
        "--triage",
        action="store_true",
        help="Enable severity triage filtering and summary report generation.",
    )

    parser.add_argument(
        "--min-level",
        type=int,
        default=8,
        help="Minimum Wazuh rule level threshold for triage (default: 8).",
    )

    parser.add_argument(
        "--report-format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format for triage summary report ('markdown' or 'json', default: markdown).",
    )

    args = parser.parse_args()

    try:
        # Triage mode: filters alerts and generates aggregated summary report
        if args.triage:
            from soc_automation.triage import (
                build_v07_triage_context,
                format_v07_context_markdown,
            )

            input_path = Path(args.input_file)
            raw_bytes = input_path.read_bytes()
            sha256_hash = calculate_sha256(raw_bytes) if args.sha256 else None
            content = raw_bytes.decode("utf-8-sig")
            try:
                data = json.loads(content)
                alerts = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                alerts = []
                for line_no, raw_line in enumerate(content.splitlines(), start=1):
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    try:
                        alerts.append(json.loads(stripped))
                    except json.JSONDecodeError as line_err:
                        raise json.JSONDecodeError(
                            f"Line {line_no}: {line_err.msg}",
                            line_err.doc,
                            line_err.pos,
                        ) from line_err
                if not alerts:
                    raise json.JSONDecodeError("Empty NDJSON input", content, 0)

            triaged = filter_by_severity(alerts, min_level=args.min_level)
            v07_context = build_v07_triage_context(alerts)
            report = generate_summary_report(triaged, output_format=args.report_format)

            enrichment_records = []
            if args.enrich:
                for item in triaged:
                    if not isinstance(item, dict):
                        continue
                    inner = item.get("alert") if isinstance(item.get("alert"), dict) else item
                    rule_obj = inner.get("rule") if isinstance(inner.get("rule"), dict) else {}
                    agent_obj = inner.get("agent") if isinstance(inner.get("agent"), dict) else {}
                    enrichment_payload = {
                        "alert": {
                            "rule_id": inner.get("rule_id") or rule_obj.get("id"),
                            "severity": inner.get("severity") if inner.get("severity") is not None else rule_obj.get("level"),
                            "agent_name": inner.get("agent_name")
                            or (inner.get("agent") if isinstance(inner.get("agent"), str) else None)
                            or agent_obj.get("name"),
                            "description": inner.get("description") or rule_obj.get("description"),
                        }
                    }
                    enriched = enrich_alert(enrichment_payload)
                    enrichment_records.append(enriched.get("enrichment", enriched))

            if args.report_format == "json":
                payload = report if isinstance(report, dict) else json.loads(str(report))
                payload["v07_triage_context"] = v07_context
                if sha256_hash is not None:
                    payload["source_sha256"] = sha256_hash
                if args.enrich:
                    payload["enrichments"] = enrichment_records
                report_str = json.dumps(payload, indent=4)
            else:
                extra_sections = [format_v07_context_markdown(v07_context)]
                if sha256_hash is not None:
                    extra_sections.append(f"## Source Integrity\n- **SHA-256:** `{sha256_hash}`")
                if args.enrich:
                    extra_sections.append(
                        f"## Enrichment Summary\n- **Enriched Triaged Alerts:** {len(enrichment_records)}"
                    )
                report_str = f"{report}\n\n" + "\n\n".join(extra_sections)

            if args.output:
                output_path = Path(args.output)
                output_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                output_path.write_text(
                    report_str + "\n",
                    encoding="utf-8",
                )
                print("Successfully generated triage summary report.")
                print(f"Output saved to: {output_path}")
            else:
                print(report_str)

            return 0

        # Normal mode: single alert ingestion & normalization pipeline
        # 1. Ingest and process the Wazuh alert
        result = ingest_wazuh_alert_file(
            file_path=args.input_file,
            include_sha256=args.sha256,
            include_enrichment=args.enrich,
        )

        # 2. Convert the processed result into formatted JSON
        output_json = json.dumps(
            result,
            indent=4,
            ensure_ascii=False,
        )

        # 3. Save the result if an output path is provided
        if args.output:
            output_path = Path(args.output)

            # Automatically create missing output directories
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            # Write the processed JSON file
            output_path.write_text(
                output_json + "\n",
                encoding="utf-8",
            )

            print("Successfully processed alert.")
            print(f"Output saved to: {output_path}")

        # 4. Otherwise, display JSON in the terminal
        else:
            print(output_json)

        return 0

    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())