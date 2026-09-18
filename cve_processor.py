#!/usr/bin/env python3
"""Child-process CVE processor.

Input:
    CSV/XLSX converted to CSV by app.py
    --name IncidentNumber
    --architecture OL8|OL9
    --release-version 1.1.13|1.2.4|2.1

The processor loads releasebuilds/releasepackages_{ReleaseVersion}.csv,
queries Red Hat securitydata, compares package state/fixed versions, and
writes {Name}_{Architecture}_{ReleaseVersion}.csv.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

try:
    import rpm
except ImportError as exc:
    raise SystemExit(
        "The Python rpm module is required. Install the OS package that "
        "provides python3-rpm on the host running this service."
    ) from exc


API_HOST = "https://access.redhat.com/hydra/rest/securitydata"

# Set by set_architecture(). The user requested ARCH to contain the full
# Red Hat product name while the API query uses that value.
ARCH: str | None = None

OUTPUT_FIELDS = [
    "CVE_Number",
    "Severity",
    "CVE_Reported_Severity",
    "Package_Name",
    "Architecture",
    "Package_State",
    "Affected_Fixed_Release",
    "Product_Release_Version",
    "Release_Package_Name",
    "Release_Package_Version",
    "Release_Number",
    "Release_ARCH",
    "Release_Size_Bytes",
    "Release_Source_RPM",
    "Notes",
]

RELEASE_FIELDS = [
    "ReleasePackageName",
    "ReleasePackageVersion",
    "ReleaseNumber",
    "ReleaseARCH",
    "ReleaseSizeBytes",
    "ReleaseSourceRPM",
]


def set_architecture(value: str) -> None:
    global ARCH
    if value == "OL8":
        ARCH = "Red Hat Enterprise Linux 8"
    elif value == "OL9":
        ARCH = "Red Hat Enterprise Linux 9"
    else:
        raise ValueError("Architecture has not been provided")


def clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def load_input_rows(path: Path) -> list[dict[str, str]]:
    """Load CSV rows. XLSX is also supported for direct CLI use."""
    if path.suffix.lower() == ".xlsx":
        try:
            from openpyxl import load_workbook
        except ImportError as exc:
            raise RuntimeError("openpyxl is required for direct XLSX processing.") from exc

        workbook = load_workbook(path, read_only=True, data_only=True)
        sheet = workbook.active
        rows = sheet.iter_rows(values_only=True)
        try:
            headers = [clean(v) for v in next(rows)]
        except StopIteration:
            return []
        return [
            {headers[i]: clean(row[i]) if i < len(row) else "" for i in range(len(headers))}
            for row in rows
        ]

    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def validate_input_headers(rows: list[dict[str, str]]) -> None:
    if not rows:
        raise ValueError("Input CSV/XLSX contains no data rows.")
    normalized = {clean(k).lower().replace(" ", "_") for k in rows[0]}
    required = {"cve_number", "severity", "package_name"}
    if not required.issubset(normalized):
        raise ValueError(
            "Input must contain columns: CVE Number, Severity, Package Name."
        )


def normalized_input_row(row: dict[str, str]) -> tuple[str, str, str]:
    lookup = {clean(k).lower().replace(" ", "_"): clean(v) for k, v in row.items()}
    cve = lookup.get("cve_number", "")
    severity = lookup.get("severity", "")
    package = lookup.get("package_name", "")
    return cve, severity, package


def load_releasepackages(release_version: str) -> list[dict[str, str]]:
    path = Path(__file__).resolve().parent / "releasebuilds" / f"releasepackages_{release_version}.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"Required release package inventory was not found: {path}"
        )

    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))

    if rows:
        missing = [field for field in RELEASE_FIELDS if field not in rows[0]]
        if missing:
            raise ValueError(f"releasepackages file is missing columns: {missing}")
    return rows


def cve_url(cve: str, package: str) -> str:
    # The requested API product value is ARCH, which is the full RHEL name.
    return (
        f"{API_HOST}/cve.json"
        f"?ids={quote(cve.upper())}"
        f"&product={quote(ARCH or '')}"
        f"&package={quote(package)}"
        f"&include_package_state=true"
    )


def fetch_json(url: str, retries: int = 3) -> Any:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "CVE-Comparison-Service/1.0",
        },
    )
    last_error = None
    for attempt in range(retries):
        try:
            with urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Red Hat API request failed: {last_error}")


def first_cve_object(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        return payload[0] if payload else {}
    if isinstance(payload, dict):
        return payload
    return {}


def package_state_matches(
    cve_data: dict[str, Any],
    package_name: str,
) -> list[dict[str, Any]]:
    states = cve_data.get("package_state") or []
    arch_name = (ARCH or "").casefold()
    package_name_cf = package_name.casefold()

    matches = []
    for state in states:
        product = clean(state.get("product_name"))
        pkg = clean(state.get("package_name"))
        if product.casefold() == arch_name and package_name_cf in pkg.casefold():
            matches.append(state)
    return matches


def release_matches(
    releasepackages: list[dict[str, str]],
    package_name: str,
) -> list[dict[str, str]]:
    needle = package_name.casefold()
    return [
        row for row in releasepackages
        if needle in clean(row.get("ReleasePackageName")).casefold()
    ]


def rpm_evr(value: str) -> tuple[str, str, str] | None:
    """Return (epoch, version, release) suitable for rpm.labelCompare()."""
    value = clean(value)
    if not value:
        return None

    # Remove common RPM filename suffix.
    value = re.sub(r"\.(?:src|noarch|x86_64|aarch64|ppc64le|s390x)\.rpm$", "", value)

    # Examples handled:
    #   python-pip-0:25.2-3.el9_8.5
    #   0:25.2-3.el9_8.5
    #   25.2-3.el9_8.5
    #   package-1:2.3-4.el9
    m = re.search(r"(?:(\d+):)?([0-9][^-]*?)-([^-]+)$", value)
    if not m:
        return None
    epoch = m.group(1) or "0"
    version = m.group(2)
    release = m.group(3)
    return epoch, version, release


def rpm_compare(left: str, right: str) -> int | None:
    """Compare RPM EVR values: -1, 0, 1, or None when parsing fails."""
    l = rpm_evr(left)
    r = rpm_evr(right)
    if not l or not r:
        return None
    try:
        return rpm.labelCompare(l, r)
    except Exception:
        return None


def extract_fixed_versions(
    cve_data: dict[str, Any],
    package_name: str,
) -> list[str]:
    fixed = []
    for item in cve_data.get("affected_packages") or []:
        item_s = clean(item)
        if package_name.casefold() in item_s.casefold():
            # Keep the portion after the final colon. For package:EVR style
            # entries this is the fixed EVR; for image-like entries it remains
            # the image/build value and is simply ignored by RPM comparison.
            candidate = item_s.rsplit(":", 1)[-1]
            if candidate and candidate not in fixed:
                fixed.append(candidate)
    return fixed


def select_closest_fixed_release(
    package_name: str,
    product_release: str,
    fixed_versions: list[str],
) -> str:
    """Pick the fixed version associated with the closest package-name match."""
    if not fixed_versions:
        return "UNAVAILABLE"
    # A deterministic selection is used because the API's affected_packages
    # values do not carry the platform release version as a separate field.
    return fixed_versions[0]


def choose_release_match(
    matches: list[dict[str, str]],
    package_name: str,
) -> dict[str, str] | None:
    if not matches:
        return None
    needle = package_name.casefold()

    def score(row: dict[str, str]) -> tuple[int, int]:
        candidate = clean(row.get("ReleasePackageName")).casefold()
        exact = int(candidate == needle)
        return exact, -len(candidate)

    return sorted(matches, key=score, reverse=True)[0]


def build_entry(cve: str, severity: str, package: str) -> dict[str, str]:
    return {
        "CVE_Number": cve,
        "Severity": severity,
        "CVE_Reported_Severity": "UNAVAILABLE",
        "Package_Name": package,
        "Architecture": "",
        "Package_State": "UNAVAILABLE",
        "Affected_Fixed_Release": "UNAVAILABLE",
        "Product_Release_Version": "UNAVAILABLE",
        "Release_Package_Name": "UNAVAILABLE",
        "Release_Package_Version": "UNAVAILABLE",
        "Release_Number": "UNAVAILABLE",
        "Release_ARCH": "UNAVAILABLE",
        "Release_Size_Bytes": "UNAVAILABLE",
        "Release_Source_RPM": "UNAVAILABLE",
        "Notes": "UNAVAILABLE",
    }


def process_one(
    entry: dict[str, str],
    releasepackages: list[dict[str, str]],
    release_version: str,
) -> dict[str, str]:
    cve = entry["CVE_Number"].upper()
    package = entry["Package_Name"]

    entry["CVE_Number"] = cve
    entry["Architecture"] = ARCH or ""
    entry["Product_Release_Version"] = release_version

    data = first_cve_object(fetch_json(cve_url(cve, package)))

    entry["CVE_Reported_Severity"] = clean(data.get("severity")) or "UNAVAILABLE"

    matches = package_state_matches(data, package)
    if not matches:
        entry["Package_State"] = "Architecture/Package Name not in RHEL CVE Database"
        entry["Notes"] = (
            f"False Positive. Product not affected by Vulnerabilities, "
            f"{cve} specific package or package version not install on our systems"
        )
        return entry

    release_match = choose_release_match(
        release_matches(releasepackages, package),
        package,
    )

    if not release_match:
        entry["Notes"] = (
            "Unable to merge on Package Names from provided CSV and Release Package. "
            "The provided package name doesn't match the Product's installed package. "
            f"Provided:{package} Release Package:UNAVAILABLE"
        )
        return entry

    entry["Release_Package_Name"] = clean(release_match.get("ReleasePackageName"))
    entry["Release_Package_Version"] = clean(release_match.get("ReleasePackageVersion"))
    entry["Release_Number"] = clean(release_match.get("ReleaseNumber"))
    entry["Release_ARCH"] = clean(release_match.get("ReleaseARCH"))
    entry["Release_Size_Bytes"] = clean(release_match.get("ReleaseSizeBytes"))
    entry["Release_Source_RPM"] = clean(release_match.get("ReleaseSourceRPM"))

    # Start with the first matched package state's fix_state as requested.
    entry["Package_State"] = clean(matches[0].get("fix_state")) or "UNAVAILABLE"
    entry["Notes"] = f"{cve} has noted the package {package} to be {entry['Package_State']}."

    if not any(clean(m.get("fix_state")).casefold() == "affected" for m in matches):
        return entry

    entry["Package_State"] = "AFFECTED"
    fixed_versions = extract_fixed_versions(data, package)
    entry["Affected_Fixed_Release"] = select_closest_fixed_release(
        package, release_version, fixed_versions
    )

    comparisons = [
        (fixed, rpm_compare(fixed, entry["Release_Source_RPM"]))
        for fixed in fixed_versions
    ]
    newer = [fixed for fixed, comparison in comparisons if comparison is not None and comparison > 0]
    patched = [fixed for fixed, comparison in comparisons if comparison is not None and comparison <= 0]

    severity = entry["CVE_Reported_Severity"].casefold()

    if newer and severity in {"important", "critical"}:
        entry["Notes"] += (
            f" Package Affected and has not been patched in {release_version}. "
            "Further investigation is needed, will engage the Surity Team and "
            "return with results of investigation."
        )
    elif newer and severity in {"moderate", "low"}:
        entry["Notes"] += (
            f" Package Affected and has not been patched in {release_version}. "
            "Will be patched in a furture release of the Product."
        )
        entry["Package_State"] = "Affected"
    elif newer:
        entry["Notes"] += (
            f" False Positive. Package is reporting as Affected and has not been "
            f"patched in {release_version} but {cve} is reporting a non-standard "
            f"severity {entry['CVE_Reported_Severity']}. This means it is not of "
            "significant impact."
        )
        entry["Package_State"] = "Affected"
    elif patched:
        entry["Affected_Fixed_Release"] = patched[0]
        entry["Notes"] += (
            f" Package Affected and has been patched in {release_version}. "
            "Please update to the patched version of the Product."
        )

    return entry


def process_file(
    input_file: Path,
    name: str,
    architecture: str,
    release_version: str,
    output: Path | None = None,
) -> Path:
    set_architecture(architecture)

    releasepackages = load_releasepackages(release_version)
    rows = load_input_rows(input_file)
    validate_input_headers(rows)

    # Unique CVE_Number processing: preserve first occurrence's severity/package
    # while preventing duplicate API processing for the same CVE/package pair.
    unique_rows: dict[tuple[str, str], tuple[str, str, str]] = {}
    for row in rows:
        cve, severity, package = normalized_input_row(row)
        if not cve or not package:
            continue
        key = (cve.upper(), package.casefold())
        unique_rows.setdefault(key, (cve.upper(), severity, package))

    processed = []
    for cve, severity, package in unique_rows.values():
        entry = build_entry(cve, severity, package)
        processed.append(process_one(entry, releasepackages, release_version))

    if output is None:
        output = Path(f"{name}_{architecture}_{release_version}.csv")

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(processed)

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process a CVE CSV/XLSX report.")
    parser.add_argument("--csv-file", required=True, help="Input CSV or XLSX file")
    parser.add_argument("--name", required=True, help="IncidentNumber")
    parser.add_argument("--architecture", required=True, choices=["OL8", "OL9"])
    parser.add_argument("--release-version", required=True, choices=["1.1.13", "1.2.4", "2.1"])
    parser.add_argument("--output", help="Output CSV path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        output = process_file(
            Path(args.csv_file),
            args.name,
            args.architecture,
            args.release_version,
            Path(args.output) if args.output else None,
        )
        print(output)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
