#!/usr/bin/env python3
"""NiceGUI front-end for the CVE Lookup service."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import rpm
import re
import subprocess
import sys
import tempfile
import logging
import traceback
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

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
APP_LOG_FILE = LOG_DIR / "app.log"

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

# Debugging / Logging

DEBUG_ENABLED = os.getenv("CVE_DEBUG", "0").lower() in {"1","true","yes","on"}
LOG_LEVEL = logging.DEBUG if DEBUG_ENABLED else logging.INFO
logging.basicConfig(level=LOG_LEVEL,format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("cve_app")
logger.setLevel(LOG_LEVEL)
logger.propagate = False
def debug_log(message: str, *args):
    """Write a DEBUG message when CVE_DEBUG is enabled."""
    logger.debug(message, *args)
def info_log(message: str, *args):
    """Write an INFO message."""
    logger.info(message, *args)
def error_log(message: str, *args):
    """Write an ERROR message."""
    logger.error(message, *args)
def exception_log(message: str, *args):
    """Write an ERROR message including the current traceback."""
    logger.exception(message, *args)
if not logger.handlers:
    file_handler = logging.FileHandler(APP_LOG_FILE,encoding="utf-8")
    file_handler.setLevel(LOG_LEVEL)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
debug_log("Debug logging enabled: %s",DEBUG_ENABLED)
debug_log("BASE_DIR=%s",BASE_DIR)
debug_log("PROCESSOR=%s",PROCESSOR)
debug_log("CONFIG_DIR=%s",CONFIG_DIR)
debug_log("PLATFORM_VERSIONS_FILE=%s",PLATFORM_VERSIONS_FILE)
debug_log("RELEASE_BUILDS_DIR=%s",RELEASE_BUILDS_DIR)



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
    debug_log("Loading platform versions from %s",PLATFORM_VERSIONS_FILE)
    ensure_config_directory()
    if not PLATFORM_VERSIONS_FILE.exists():
        save_platform_versions(DEFAULT_PLATFORM_VERSIONS)
        return sorted(DEFAULT_PLATFORM_VERSIONS,key=version_sort_key)
    try:
        with PLATFORM_VERSIONS_FILE.open("r",encoding="utf-8") as file:
            versions = json.load(file)
    except (OSError, json.JSONDecodeError):
        # If the file is invalid, restore the defaults.
        exception_log("Unable to load platform versions from %s. Restoring defaults.")
        save_platform_versions(DEFAULT_PLATFORM_VERSIONS)
        return sorted(DEFAULT_PLATFORM_VERSIONS,key=version_sort_key)
    if not isinstance(versions, list):
        error_log("Platform version configuration is not a list: %r",versions)
        save_platform_versions(DEFAULT_PLATFORM_VERSIONS)
        return sorted(DEFAULT_PLATFORM_VERSIONS,key=version_sort_key,)
    valid_versions = []
    for version in versions:
        if not isinstance(version, str):
            debug_log("Ignoring non-string platform version: %r",version)
            continue
        version = version.strip()
        if VERSION_PATTERN.fullmatch(version):
            valid_versions.append(version)
        else:
            debug_log("Ignoring invalid platform version: %r",version)
    # Make sure there is always at least one configured version.
    if not valid_versions:
        info_log("No valid platform versions found. Using defaults.")
        valid_versions = DEFAULT_PLATFORM_VERSIONS.copy()
    valid_versions = sorted(set(valid_versions),key=version_sort_key)
    debug_log("Loaded platform versions: %s",valid_versions)
    # Rewrite the file if invalid entries were found.
    if valid_versions != versions:
        debug_log("Normalized platform version configuration.")
        save_platform_versions(valid_versions)
    return valid_versions

def add_platform_version(version: str) -> bool:
    """
    Add a platform version to the persistent configuration.
    Returns: True - version was newly added; False - version already existed
    """
    debug_log("Attempting to register platform version: %s",version)
    version = version.strip()
    versions = load_platform_versions()
    if version in versions:
        debug_log("Platform version already registered: %s",version)
        return False
    versions.append(version)
    save_platform_versions(versions)
    info_log("Registered new platform version: %s",version)
    return True

def validate_releasebuild_csv(content: bytes) -> tuple[bool, str]:
    """
    Validate a release-build CSV. Required columns: ReleasePackageName, ReleasePackageVersion, ReleaseNumber, ReleaseARCH, ReleaseSizeBytes, ReleaseSourceRPM
    """
    debug_log("Validating release-build CSV: %d bytes",len(content))
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        error_log("Release-build CSV is not UTF-8 encoded.")
        return False, "CSV file must be UTF-8 encoded."

    if not text.strip():
        error_log("Release-build CSV is empty.")
        return False, "CSV file is empty."

    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error as exc:
        error_log("CSV parser error: %s",exc)
        return False, f"Unable to parse CSV: {exc}"

    if reader.fieldnames is None:
        error_log("Release-build CSV has no header row.")
        return False, "CSV file does not contain a header row."

    # Strip whitespace from column names.
    headers = [
        header.strip()
        if header is not None
        else ""
        for header in reader.fieldnames
    ]
    debug_log("Release-build CSV headers: %s",headers)
    missing_columns = [
        column
        for column in RELEASE_BUILD_FIELDS
        if column not in headers
    ]

    if missing_columns:
        error_log("Release-build CSV missing columns: %s",missing_columns)
        return False, "CSV is missing required column(s): " + ", ".join(missing_columns)

    # Ensure the CSV contains at least one data row.
    try:
        first_row = next(reader)
    except StopIteration:
        error_log("Release-build CSV contains no data rows.")
        return False, "CSV does not contain any data rows."
    except csv.Error as exc:
        error_log("Unable to read CSV data. CSV parser error: %s",exc)
        return False, f"Unable to read CSV data: {exc}"
    debug_log("First release-build CSV row: %s",first_row)
    if not first_row:
        error_log("CSV contains an invalid data row.")
        return False, "CSV contains an invalid data row."
    info_log("Release-build CSV validation successful.")
    return True, "CSV validation successful. All six required columns are present."

async def handle_cve_upload(e: nicegui.events.UploadEventArguments):
    """Save the uploaded CVE CSV/XLSX file to a temporary directory."""
    global uploaded_cve_file
    global uploaded_cve_filename

    filename = e.file.name
    debug_log("CVE upload received: filename=%s",filename)
    if not filename.lower().endswith((".csv", ".xlsx")):
        error_log("Rejected CVE upload with unsupported extension: %s",filename)
        cve_status_label.text = "Error: Only CSV and XLSX files are supported."
        ui.notify("Only CSV and XLSX files are supported.",type="negative")
        return

    try:
        content = await e.file.read()
        debug_log("CVE upload read successfully: filename=%s size=%d bytes",filename,len(content))
        temp_dir = Path(tempfile.mkdtemp(prefix="cve_upload_"))
        uploaded_file = temp_dir / filename
        uploaded_file.write_bytes(content)
        uploaded_cve_file = uploaded_file
        uploaded_cve_filename = filename
        info_log("CVE input saved: %s",uploaded_file)
        cve_status_label.text = f"Uploaded: {filename}"
        process_button.enable()
        ui.notify(f"Uploaded {filename}",type="positive")
    except Exception as exc:
        uploaded_cve_file = None
        uploaded_cve_filename = None
        process_button.disable()
        exception_log("Exception while processing CVE upload: %s",filename)
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
    debug_log("Release-build upload started: version=%s",version)
    if not valid:
        error_log("Invalid release-build version: %s - %s",version,message)
        release_build_status_label.text = message
        ui.notify(message,type="negative")
        return

    filename = e.file.name
    debug_log("Release-build upload received: %s",filename)
    if not filename.lower().endswith(".csv"):
        error_log("Rejected release-build file: %s",filename)
        message = "Only CSV files are supported for release builds."
        release_build_status_label.text = message
        ui.notify(message,type="negative")
        return

    try:
        content = await e.file.read()
        debug_log("Release-build file read: %d bytes",len(content))
        valid, message = validate_releasebuild_csv(content)
        if not valid:
            error_log("Release-build validation failed: %s",message)
            release_build_status_label.text = f"Validation failed: {message}"
            ui.notify(message,type="negative")
            return

        # Ensure releasebuilds directory exists.
        RELEASE_BUILDS_DIR.mkdir(parents=True,exist_ok=True)

        output_file = (RELEASE_BUILDS_DIR/ f"releasepackages_{version}.csv")
        debug_log("Saving release build to: %s",output_file)
        output_file.write_bytes(content)
        debug_log("Saved successfully: version=%s added=%s",version,output_file)
        # Register the version persistently.
        was_added = add_platform_version(version)
        debug_log("Platform versions added: %s",version,was_added)
        # Refresh the CVE Processing dropdown.
        refresh_platform_versions()
        info_log("Release-build processing completed: version=%s file=%s",version,output_file)
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
    debug_log("Starting CVE processor.")
    debug_log("Input file: %s",uploaded_cve_file)
    debug_log("IncidentNumber: %s",incident_number)
    debug_log("Architecture: %s",architecture)
    debug_log("ReleaseVersion: %s",release_version)
    debug_log("Release build file: %s",release_build_file)
    debug_log("Output file: %s",output_file)
    debug_log("Processor path: %s",PROCESSOR)
    debug_log("Python executable: %s",sys.executable)
    debug_log("Processor command: %r",command)
    process_button.disable()

    try:
        result = await asyncio.to_thread(subprocess.run,command,capture_output=True,text=True)
        debug_log("CVE processor return code: %d",result.returncode,)
        if result.stdout:
            debug_log("CVE processor stdout:\n%s",result.stdout)
        if result.stderr:
            debug_log("CVE processor stderr:\n%s",result.stderr)
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
        exception_log("Exception while executing CVE processor.")

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
                #fix upload bug https://nicegui.io/documentation/upload
                ui.upload(label="Upload CVE CSV or XLSX",on_upload=handle_cve_upload,auto_upload=True).props("accept=.csv,.xlsx").classes("w-full")
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
    ui.run(host="0.0.0.0",port=PORT,title="CVE Comparison Service",favicon="/config/favicon.ico")

"""
App explained
NiceGUI Python service 
	that requires the upload of a CSV or .XLSX file on the web UI listening on port 3251, 
	The format of the CSV File should be Formatted (CVE Number, Severity, Package Name), having a label under the upload with example of CSV Format, 
	with a required text field to enter IncidentNumber Field, 
	with a Dropdown menu to select Platform versions options equal to [1.1.13, 1.2.4, 2.1], 
	with a Dropdown menu to select Architecture options equal to [OL8, OL9], 
	include a 'Process' button to verify that all required information was provided and start separate python script, 
	The web service application most call a separate python script, passing 
		CSV file as parameter, 
		IncidentNumber as Name, 
		the Architecture as string OL8 or OL9, 
		and the Platform Version as ReleaseVersion, 
	that separate python script should start as a child process to process the CSV file entries, 
	Child Process Python script is expected to return a processed CSV file with the name {Name}_{Architecture}_{ReleaseVersion}.csv, 
	return comparison output CSV File as a Download.

The Child Process Python script is used to look up all entries/rows for unique CVE_Number, 
	input parameters are CSV_file of format [CVE_Number, Severity, Package_Name] and Name, Architecture, ReleaseVersion from the UI; 
	set global constant variable ARCH equal to "Red Hat Enterprise Linux 8" if Architecture string parameter is OL8 OR "Red Hat Enterprise Linux 9" Architecture string parameter is OL9, raise "Architecture has not been provided" otherwise
	set global constant variable API_HOST = 'https://access.redhat.com/hydra/rest/securitydata', 
	expect to load into dictionary memory a /releasebuilds/releasepackages_{ReleaseVersion}.csv file for future comparison refered to as releasepackages, 
		releasepackages file format should be (ReleasePackageName, ReleasePackageVersion, ReleaseNumber, ReleaseARCH, ReleaseSizeBytes, ReleaseSourceRPM) 
		derived from 'rpm -qa --qf "%{name},%{version},%{release},%{arch},%{size},%{sourcerpm}\n"' of a system
To process the CSV_file first load into a dictionary variable each row of incoming CSV_file, each entry formated, as CVE_Entry
	[CVE_Number:CVE_Number from CSV_file, 
	Severity:Severity from CSV_file, 
	CVE_Reported_Severity:"UNAVAILABLE",
	Package_Name:Package_Name from CSV_file, 
	Architecture:Architecture from passed value,
	Package_State:"UNAVAILABLE", 
	Affected_Fixed_Release:"UNAVAILABLE",
	Product_Release_Version:"UNAVAILABLE",
	Release_Package_Name:"UNAVAILABLE", 
	Release_Package_Version:"UNAVAILABLE", 
	Release_Number:"UNAVAILABLE", 
	Release_ARCH:"UNAVAILABLE", 
	Release_Size_Bytes:"UNAVAILABLE", 
	Release_Source_RPM:"UNAVAILABLE",
	Notes:"UNAVAILABLE"]

	for each CVE_Entry CVE_Number entry lookup by 'curl -s' out to “{API_HOST}/cve.json?ids={CVE_Number}&product={Architecture}&package={Package_Name}&include_package_state=true” this will return a .json file, 
		replacing "{CVE_Number}" with the specific CVE_Number provided in the CSV_file force uppercase, 
		replacing {Package_Name} with the corresponding Package_Name provided in the CSV_file, 
		replacing {Architecture} with ARCH, keep the .json file returned for later search and comparison, 
	update CVE_Entry CVE_Reported_Severity to .json severity value for CSV return
	compare each .json package_state name value of all instances where (product_name sub-name equal to ARCH AND package_name sub-name contains Package_Name), 
		if none found 
			update Package_State to "Architecture/Package Name not in RHEL CVE Database" 
			and update Notes to f"False Positive. Product not affected by Vulnerabilities, {CVE_Number} specific package or package version not install on our systems"
		else 
			then try join into CVE_Entry with the loaded releasepackages where ReleasePackageName like Package_Name
				if join fails break and add CVE_Entry Notes f"Unable to merge on Package Names from provided CSV and Release Package. The provided package name doesn't match the Product's installed package. Provided:{Package_Name} Release Package: {ReleasePackageName}",
				update Product_Release_Version to ReleaseVersion from passed values for CSV return,
				update CVE_Entry Release_Package_Name to ReleasePackageName,
				update CVE_Entry Release_Package_Version to ReleasePackageVersion,
				update CVE_Entry Release_Number to ReleaseNumber,
				update CVE_Entry Release_ARCH to ReleaseARCH,
				update CVE_Entry Release_Size_Bytes to ReleaseSizeBytes,
				update CVE_Entry Release_Source_RPM to ReleaseSourceRPM,
				
			update CVE_Entry Package_State to .json fix_state sub-name value,
			update CVE_Entry Notes to f"{CVE_Number} has noted the package {Package_Name} to be {Package_State}.",
			also check if any fix_state sub-name values in the found .json package_state name entries are equal to 'Affected' 
			then update Package_State to "AFFECTED" and search .json affected_packages name for all instances like Package_Name,
				extract as FixedVersion, 
				with all extracted FixedVersion using rpm python library to compare FixedVersion to Release_Source_RPM, 
					if (any FixedVersion is greater than Release_Source_RPM and (CVE_Reported_Severity is equal to lowercase "important" OR "critical")), append Notes with f"Package Affected and has not been patched in {Product_Release_Version}. Further investigation is needed, will engage the Surity Team and return with results of investigation."
					elif (any FixedVersion is greater than Release_Source_RPM and (CVE_Reported_Severity is equal to lowercase "moderate" OR "low")), append Notes with f"Package Affected and has not been patched in {Product_Release_Version}. Will be patched in a furture release of the Product." and update Package_State to "Affected"
					elif (any FixedVersion is greater than Release_Source_RPM and (CVE_Reported_Severity is equal to anything else)), append Notes with f"False Positive. Package is reporting as Affected and has not been patched in {Product_Release_Version} but {CVE_Number} is reporting a non-standard severity {CVE_Reported_Severity}. This means it is not of significant impact." and update Package_State to "Affected"
					elif any FixedVersion is less than or equal Release_Source_RPM, update Package_State to "Affected" and append Notes with f"Package Affected and has been patched in {Product_Release_Version}. Please update to the patched version of the Product."
		update Affected_Fixed_Release to FixedVersion most like Product_Release_Version for CSV return
	return processed CVE_Entry as CSV_file
"""