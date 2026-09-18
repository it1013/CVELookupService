# CVE Comparison NiceGUI Service

## Files

- `app.py` - NiceGUI web service on TCP port `3251`.
- `cve_processor.py` - separate child-process worker.
- `releasebuilds/` - place the platform RPM inventories here.
- `sample_input.csv` - example input format.
- `config/` - currently only holding `platform_versions.json`.

The supplied `sample.json` was inspected while implementing the JSON parser. Its
top-level CVE object contains `severity`, `affected_packages`, and
`package_state`; `package_state` entries contain `product_name`, `fix_state`,
and `package_name`. For example, the sample contains RHEL 8 and RHEL 9
package-state entries, including `python-pip`. See the supplied source:
`sample.json`.

## Input CSV

```csv
CVE Number,Severity,Package Name
CVE-2026-8643,important,python-pip
```

The web UI also accepts XLSX. XLSX is converted/handled by the child processor
without requiring the user to convert it manually.

## Release package inventory

Create one inventory per supported platform version:

```text
releasebuilds/releasepackages_1.1.13.csv
releasebuilds/releasepackages_1.2.4.csv
releasebuilds/releasepackages_2.1.o.csv
```

Required header:

```csv
ReleasePackageName,ReleasePackageVersion,ReleaseNumber,ReleaseARCH,ReleaseSizeBytes,ReleaseSourceRPM
```

The rows can be generated on a target system with:

```bash
rpm -qa --qf "%{name},%{version},%{release},%{arch},%{size},%{sourcerpm}\n"
```

That command's output does not have the exact `Release*` headers, so rename the
six columns when creating the inventory.

## Install

On RHEL/OL-like systems, the `rpm` Python module normally comes from the OS
package that provides `python3-rpm`. Install that package using the appropriate
system package manager.

Then install Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

```bash
python app.py
```

The service listens on:

```text
http://<server>:3251/
```

## Child process

The web process launches the worker approximately as:

```text
python cve_processor.py \
  --csv-file /path/to/input.csv \
  --name INC123456 \
  --architecture OL9 \
  --release-version 1.2.4 \
  --output /temporary/path/INC123456_OL9_1.2.4.csv
```

The resulting CSV is returned to the browser as a download.

## Important implementation notes

1. `ARCH` is set to `Red Hat Enterprise Linux 8` for `OL8` and
   `Red Hat Enterprise Linux 9` for `OL9`; an invalid value raises
   `Architecture has not been provided`.
2. CVE IDs are forced uppercase before the Red Hat API lookup.
3. The worker keeps each API JSON response in memory for the processing of that
   CVE, so package-state and affected-package comparisons use the same response.
4. Processing is unique by `(CVE_Number, Package_Name)` to avoid repeating the
   same API lookup for duplicate input rows.
5. RPM comparisons use the Python `rpm.labelCompare()` implementation rather
   than lexical string comparison.
6. API calls include retries and a 60-second timeout.
7. The UI executes the worker with `subprocess.run()` in a background thread so
   the NiceGUI event loop is not blocked by network/API processing.

## API behavior

The request endpoint is:

```text
https://access.redhat.com/hydra/rest/securitydata/cve.json?ids={CVE_Number}&product={Architecture}&package={Package_Name}&include_package_state=true
```

with `ids`, `product`, `package`, and `include_package_state=true`.

The worker intentionally keeps the requested API parameter behavior: the
`product` parameter receives the full `ARCH` value.

## Docker Build

To build docker image download repo, in terminal run the following command with admin right:
```commandline
docker build -t cve-tool-service .
```
It is assumed you have Docker installed and running. Tested on Docker Engine 29.8.0.

## Docker Run

Windows:
```commandline
docker run -d `
  --name cvetool `
  -p <local_port>:3251 `
  -v $(pwd)/config:/app/config `
  -v $(pwd)/releasebuilds:/app/releasebuilds `
  cve-tool-service
```

Linux:
```commandline
docker run -d \
  --name cvetool \
  -p <local_port>:3251 \
  -v <working_dir OR .>/config:/app/config \
  -v <working_dir OR .>/releasebuilds:/app/releasebuilds \
  cve-tool-service
```

Once run completes, you can access on `http://localhost:<local_port>`.