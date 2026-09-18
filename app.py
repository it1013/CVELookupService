#!/usr/bin/env python3
"""NiceGUI front-end for the CVE Lookup service."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from nicegui import ui, events
import nicegui

"""
# Configuration
"""

BASE_DIR = Path(__file__).resolve().parent
PROCESSOR = BASE_DIR / "cve_processor.py"
RELEASE_BUILDS_DIR = BASE_DIR / "releasebuilds"
CONFIG_DIR = BASE_DIR / "config"
PLATFORM_VERSIONS_FILE = CONFIG_DIR / "platform_versions.json"
PORT = 3251

DEFAULT_PLATFORM_VERSIONS = ["1.1.13", "1.2.4", "2.1"]
ARCHITECTURES = ["OL8", "OL9"]

# Global UI State
uploaded_path: Path | None = None
uploaded_name: str | None = None
status_label = None
process_button: nicegui.ui.button = None
uploaded_cve_file: Path | None = None
uploaded_cve_filename: str | None = None
cve_status_label = None
release_build_status_label = None
release_build_version_input: nicegui.ui.input = None
platform_version_select: nicegui.ui.select = None
architecture_select: nicegui.ui.select = None
incident_number_input: nicegui.ui.select = None

RELEASE_BUILD_FIELDS = [
    "ReleasePackageName",
    "ReleasePackageVersion",
    "ReleaseNumber",
    "ReleaseARCH",
    "ReleaseSizeBytes",
    "ReleaseSourceRPM",
]

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

def set_status(message: str, *, error: bool = False) -> None:
    status_label.set_text(message)
    status_label.classes(remove="text-negative text-positive")
    status_label.classes(add="text-negative" if error else "text-positive")

def version_sort_key(version: str):
    """Return a numeric sort key for MAJOR.MINOR.PATCH versions."""
    return tuple(int(part) for part in version.split("."))

def normalize_version(version: str) -> str:
    """
    Normalize a platform version, expects MAJOR.MINOR.PATCH.
    1.2.4 -> 1.2.4
    2.1   -> 2.1.0
    """
    version = version.strip()
    if re.fullmatch(r"\d+\.\d+", version):
        version = f"{version}.0"
    return version

def validate_platform_version(version: str) -> tuple[bool, str]:
    """Validate a platform version against MAJOR.MINOR.PATCH."""
    version = version.strip()
    if not version:
        return False, "Platform Version is required."
    if not VERSION_PATTERN.fullmatch(version):
        return False, "Platform Version must use MAJOR.MINOR.PATCH format (example: 2.2.0)."
    return True, ""

def ensure_config_directory():
    """Create the configuration directory if it does not exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def save_platform_versions(versions: list[str]):
    """Persist platform versions to platform_versions.json."""
    ensure_config_directory()
    versions = sorted(set(versions),key=version_sort_key)
    with PLATFORM_VERSIONS_FILE.open("w",encoding="utf-8") as file:
        json.dump(versions,file,indent=4)
        file.write("\n")

def load_platform_versions() -> list[str]:
    """
    Load platform versions from the persistent JSON configuration.
    If the configuration file does not exist, create it using the
    default versions.
    """
    ensure_config_directory()
    if not PLATFORM_VERSIONS_FILE.exists():
        save_platform_versions(DEFAULT_PLATFORM_VERSIONS)
        return sorted(DEFAULT_PLATFORM_VERSIONS,key=version_sort_key)
    try:
        with PLATFORM_VERSIONS_FILE.open("r",encoding="utf-8") as file:
            versions = json.load(file)
    except (OSError, json.JSONDecodeError):
        # If the file is invalid, restore the defaults.
        save_platform_versions(DEFAULT_PLATFORM_VERSIONS)
        return sorted(DEFAULT_PLATFORM_VERSIONS,key=version_sort_key)
    if not isinstance(versions, list):
        save_platform_versions(DEFAULT_PLATFORM_VERSIONS)
        return sorted(DEFAULT_PLATFORM_VERSIONS,key=version_sort_key,)
    valid_versions = []
    for version in versions:
        if not isinstance(version, str):
            continue
        version = version.strip()
        if VERSION_PATTERN.fullmatch(version):
            valid_versions.append(version)
    # Make sure there is always at least one configured version.
    if not valid_versions:
        valid_versions = DEFAULT_PLATFORM_VERSIONS.copy()
    valid_versions = sorted(set(valid_versions),key=version_sort_key)
    # Rewrite the file if invalid entries were found.
    if valid_versions != versions:
        save_platform_versions(valid_versions)
    return valid_versions

def add_platform_version(version: str) -> bool:
    """
    Add a platform version to the persistent configuration.
    Returns: True - version was newly added; False - version already existed
    """
    version = version.strip()
    versions = load_platform_versions()
    if version in versions:
        return False
    versions.append(version)
    save_platform_versions(versions)
    return True

def validate_releasebuild_csv(content: bytes) -> tuple[bool, str]:
    """
    Validate a release-build CSV. Required columns: ReleasePackageName, ReleasePackageVersion, ReleaseNumber, ReleaseARCH, ReleaseSizeBytes, ReleaseSourceRPM
    """
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False, "CSV file must be UTF-8 encoded."

    if not text.strip():
        return False, "CSV file is empty."

    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error as exc:
        return False, f"Unable to parse CSV: {exc}"

    if reader.fieldnames is None:
        return False, "CSV file does not contain a header row."

    # Strip whitespace from column names.
    headers = [
        header.strip()
        if header is not None
        else ""
        for header in reader.fieldnames
    ]

    missing_columns = [
        column
        for column in RELEASE_BUILD_FIELDS
        if column not in headers
    ]

    if missing_columns:
        return False, "CSV is missing required column(s): " + ", ".join(missing_columns)

    # Ensure the CSV contains at least one data row.
    try:
        first_row = next(reader)
    except StopIteration:
        return False, "CSV does not contain any data rows."
    except csv.Error as exc:
        return False, f"Unable to read CSV data: {exc}"

    if not first_row:
        return False, "CSV contains an invalid data row."

    return True, "CSV validation successful. All six required columns are present."

async def handle_cve_upload(e: nicegui.events.UploadEventArguments):
    """Save the uploaded CVE CSV/XLSX file to a temporary directory."""
    global uploaded_cve_file
    global uploaded_cve_filename

    filename = e.file.name

    if not filename.lower().endswith((".csv", ".xlsx")):
        cve_status_label.text = "Error: Only CSV and XLSX files are supported."
        ui.notify("Only CSV and XLSX files are supported.",type="negative")
        return

    try:
        content = await e.file.read()
        temp_dir = Path(tempfile.mkdtemp(prefix="cve_upload_"))
        uploaded_file = temp_dir / filename
        uploaded_file.write_bytes(content)
        uploaded_cve_file = uploaded_file
        uploaded_cve_filename = filename
        cve_status_label.text = f"Uploaded: {filename}"
        process_button.enable()
        ui.notify(f"Uploaded {filename}",type="positive")
    except Exception as exc:
        uploaded_cve_file = None
        uploaded_cve_filename = None
        process_button.disable()
        cve_status_label.text = f"Error uploading file: {exc}"
        ui.notify(f"Upload failed: {exc}",type="negative")

# Release Build Upload
async def handle_releasebuild_upload(e: events.UploadEventArguments):
    """
    Validate and save a release-build CSV.

    The file is saved as:

        releasebuilds/releasepackages_{version}.csv

    The version is also persisted to platform_versions.json.
    """
    version = release_build_version_input.value.strip()
    valid, message = validate_platform_version(version)

    if not valid:
        release_build_status_label.text = message
        ui.notify(message,type="negative")

        return

    filename = e.file.name

    if not filename.lower().endswith(".csv"):
        message = "Only CSV files are supported for release builds."
        release_build_status_label.text = message
        ui.notify(message,type="negative")
        return

    try:
        content = await e.file.read()
        valid, message = validate_releasebuild_csv(content)
        if not valid:
            release_build_status_label.text = f"Validation failed: {message}"
            ui.notify(message,type="negative")
            return

        # Ensure releasebuilds directory exists.
        RELEASE_BUILDS_DIR.mkdir(parents=True,exist_ok=True)

        output_file = (RELEASE_BUILDS_DIR/ f"releasepackages_{version}.csv")

        output_file.write_bytes(content)

        # Register the version persistently.
        was_added = add_platform_version(version)

        # Refresh the CVE Processing dropdown.
        refresh_platform_versions()

        if was_added:
            registration_message = f"Platform version {version} was added to the configuration."
        else:
            registration_message = f"Platform version {version} already exists in the configuration."

        release_build_status_label.text = f"Successfully uploaded {filename}. Saved as {output_file.name}. {registration_message}"

        ui.notify(f"Release build {version} uploaded successfully.",type="positive",)

    except Exception as exc:
        release_build_status_label.text = f"Error processing release build: {exc}"
        ui.notify(f"Release build upload failed: {exc}",type="negative")

# Refresh Platform Version Dropdown
def refresh_platform_versions():
    """
    Reload platform versions from the JSON configuration and update
    the CVE Processing dropdown.
    """
    if platform_version_select is None:
        return
    versions = load_platform_versions()
    current_value = platform_version_select.value
    platform_version_select.options = versions
    if current_value in versions:
        platform_version_select.value = current_value
    elif versions:
        platform_version_select.value = versions[0]
    platform_version_select.update()

# CVE Processing
async def process_file():
    """Launch cve_processor.py as a separate child process."""
    if uploaded_cve_file is None:
        cve_status_label.text = "Error: Please upload a CSV or XLSX file."
        ui.notify("Please upload a CSV or XLSX file.",type="negative")
        return

    incident_number = (incident_number_input.value or "").strip()
    release_version = (platform_version_select.value or "").strip()
    architecture = (architecture_select.value or "").strip()

    # Validate IncidentNumber.
    if not incident_number:
        cve_status_label.text = "Error: IncidentNumber is required."
        ui.notify("IncidentNumber is required.",type="negative")
        return

    # Validate Platform Version.
    valid, message = validate_platform_version(release_version)
    if not valid:
        cve_status_label.text = message
        ui.notify(message,type="negative")
        return

    # Validate Architecture.
    if architecture not in ("OL8", "OL9"):
        cve_status_label.text = "Error: Architecture must be OL8 or OL9."
        ui.notify("Architecture must be OL8 or OL9.",type="negative")
        return

    # Make sure the release build exists.
    release_build_file = (RELEASE_BUILDS_DIR/f"releasepackages_{release_version}.csv")
    if not release_build_file.exists():
        message = f"Release build file was not found: {release_build_file.name}"
        cve_status_label.text = message
        ui.notify(message,type="negative")
        return

    output_file = (uploaded_cve_file.parent / f"{incident_number}_{architecture}_{release_version}.csv")

    command = [
        sys.executable,
        str(PROCESSOR),
        "--csv-file",
        str(uploaded_cve_file),
        "--name",
        incident_number,
        "--architecture",
        architecture,
        "--release-version",
        release_version,
        "--output",
        str(output_file),
    ]
    cve_status_label.text = "Processing CVE comparison..."
    process_button.disable()

    try:
        result = await asyncio.to_thread(subprocess.run,command,capture_output=True,text=True)

        if result.returncode != 0:
            error_message = (result.stderr.strip() or result.stdout.strip() or "CVE processor returned an unknown error.")
            cve_status_label.text = f"Processing failed: {error_message}"
            ui.notify("CVE processing failed.",type="negative")
            return

        if not output_file.exists():
            message = "CVE processor completed, but the expected output CSV was not created."
            cve_status_label.text = message
            ui.notify(message,type="negative",)
            return

        cve_status_label.text = f"Processing complete: {output_file.name}"
        ui.notify("CVE comparison completed successfully.",type="positive",)
        ui.download(output_file,filename=output_file.name,)

    except Exception as exc:
        cve_status_label.text = f"Processing error: {exc}"

        ui.notify(f"Processing error: {exc}",type="negative")

    finally:
        process_button.enable()

# UI
@ui.page("/")
def index():
    global cve_status_label
    global process_button
    global release_build_status_label
    global release_build_version_input
    global platform_version_select
    global architecture_select
    global incident_number_input

    # Load persistent configuration.
    platform_versions = load_platform_versions()
    ui.page_title("CVE Lookup Service")
    with ui.column().classes("w-full max-w-5xl mx-auto p-6"):
        ui.label("CVE Lookup Service").classes("text-3xl font-bold")
        ui.label("Process CVE information against Red Hat security data and release package information.").classes("text-gray-600 mb-4")

        # Tabs
        with ui.tabs().classes("w-full") as tabs:
            cve_tab = ui.tab("CVE Processing")
            release_tab = ui.tab("Release Builds")

        # Tab Panels
        with ui.tab_panels(tabs,value=cve_tab,).classes("w-full"):
            # CVE Processing Tab
            with ui.tab_panel(cve_tab):
                ui.label("CVE Input File").classes("text-xl font-semibold")
                #todo
                #fix upload bug https://nicegui.io/documentation/upload
                ui.upload(label="Upload CVE CSV or XLSX",on_upload=handle_cve_upload,auto_upload=True,).props("accept=.csv,.xlsx").classes("w-full")
                ui.label("Example CSV format: CVE Number, Severity, Package Name").classes("text-sm text-gray-600")
                cve_status_label = ui.label("No CVE input file uploaded.").classes("text-sm mt-2")
                ui.separator().classes("my-4")
                ui.label("Processing Parameters").classes("text-xl font-semibold")
                incident_number_input = ui.input(label="IncidentNumber",placeholder="Enter incident number").props("outlined").classes("w-full")
                platform_version_select = ui.select(options=platform_versions,label="Platform Version",value=platform_versions[0] if platform_versions else None).props("outlined").classes("w-full")
                architecture_select = ui.select(options=["OL8","OL9"],label="Architecture",value="OL8").props("outlined").classes("w-full")
                process_button = ui.button("Process CVEs",on_click=process_file,).classes("mt-4")
                process_button.disable()
            # Release Builds Tab
            with ui.tab_panel(release_tab):
                ui.label("Release Build Upload").classes("text-xl font-semibold")
                ui.label("Upload a release-build CSV containing all six required columns.").classes("text-gray-600")
                release_build_version_input = ui.input(label="Platform Version",placeholder="MAJOR.MINOR.PATCH (example: 2.2.0)").props("outlined maxlength=32").classes("w-full")

                # Validate while the user types.
                def validate_release_version_input():
                    version = (release_build_version_input.value or "").strip()
                    if not version:
                        release_build_version_input.error = False
                        release_build_version_input.error_message = ""
                        return
                    if not VERSION_PATTERN.fullmatch(version):
                        release_build_version_input.error = True
                        release_build_version_input.error_message = "Use MAJOR.MINOR.PATCH format (example: 2.2.0)"
                    else:
                        release_build_version_input.error = False
                        release_build_version_input.error_message = ""
                release_build_version_input.on("update:model-value",validate_release_version_input)
                ui.label("Required CSV columns:").classes("font-semibold mt-4")
                ui.label(", ".join(RELEASE_BUILD_FIELDS)).classes("text-sm font-mono")
                ui.upload(label="Upload Release Build CSV",on_upload=handle_releasebuild_upload,auto_upload=True,).props("accept=.csv").classes("w-full mt-4")

                release_build_status_label = ui.label("No release build uploaded.").classes("text-sm mt-2")


# Application Startup
if __name__ in {"__main__", "__mp_main__"}:
    # Make sure persistent directories exist before starting NiceGUI.
    ensure_config_directory()
    RELEASE_BUILDS_DIR.mkdir(parents=True,exist_ok=True)
    # Initialize the configuration file if necessary.
    load_platform_versions()
    ui.run(host="0.0.0.0",port=PORT,title="CVE Comparison Service")