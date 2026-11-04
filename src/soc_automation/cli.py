import argparse
import json
import sys
from pathlib import Path

from soc_automation.ingestion import ingest_wazuh_alert_file


def main() -> int:
    """
    Command-line interface for the Python SOC Automation Engine.

    Accepts a Wazuh JSON alert file, processes it,
    and optionally enables enrichment, SHA-256,
    and JSON output export.
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
        help="Optional path to save the processed JSON output.",
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

    args = parser.parse_args()

    try:
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