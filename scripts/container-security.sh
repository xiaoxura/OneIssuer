#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=${ONEISSUER_IMAGE:-oneissuer:v0.1.0-dev.4}
output_dir=${ONEISSUER_SUPPLY_CHAIN_DIR:-$root/.artifacts/supply-chain}

# Tool releases are deliberately pinned by immutable manifest-list digest. Update
# the version comment, digest, CI record, and release notes in the same review.
trivy_image='aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f' # 0.72.0
syft_image='anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026' # v1.50.0

usage() {
  echo "usage: scripts/container-security.sh {scan|sbom|all}" >&2
  exit 2
}

require_image() {
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "container security target image is missing: $image" >&2
    exit 1
  fi
  mkdir -p "$output_dir"
  chmod 700 "$output_dir"
}

write_sbom() {
  require_image
  destination=$output_dir/oneissuer.cdx.json
  temporary=$destination.tmp
  trap 'rm -f "$temporary"' EXIT HUP INT TERM

  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$syft_image" "$image" -q -o cyclonedx-json >"$temporary"

  python3 - "$temporary" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    document = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"SBOM is not valid UTF-8 CycloneDX JSON: {error}")

if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") is None:
    raise SystemExit("SBOM does not identify itself as CycloneDX")
components = document.get("components")
if not isinstance(components, list) or not components:
    raise SystemExit("SBOM has no components")

private_members = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

def inspect(value):
    if isinstance(value, dict):
        if value.get("kty") in {"RSA", "EC", "OKP", "oct"} and private_members.intersection(value):
            raise SystemExit("SBOM contains private JWK material")
        for child in value.values():
            inspect(child)
    elif isinstance(value, list):
        for child in value:
            inspect(child)
    elif isinstance(value, str):
        lowered = value.lower()
        if lowered.endswith((".jwk", ".jwks")) or "oneissuer-signing-key" in lowered:
            raise SystemExit("SBOM references a signing-key file")

inspect(document)
print(f"CycloneDX SBOM validated: {len(components)} components")
PY

  # The SBOM catalogs the image; independently prove that the runtime filesystem
  # contains no JWK/JWKS file. Private keys must only ever arrive as runtime mounts.
  docker run --rm --entrypoint /bin/sh "$image" -ec \
    'test -z "$(find / -type f \( -name "*.jwk" -o -name "*.jwks" \) -print -quit 2>/dev/null)"'

  mv "$temporary" "$destination"
  chmod 600 "$destination"
  sha256sum "$destination" >"$output_dir/SHA256SUMS"
  chmod 600 "$output_dir/SHA256SUMS"
  trap - EXIT HUP INT TERM
  echo "SBOM written to $destination"
}

scan_image() {
  require_image
  destination=$output_dir/trivy-high-critical.json
  temporary=$destination.tmp
  trap 'rm -f "$temporary"' EXIT HUP INT TERM

  # Trivy deliberately exits 1 when the configured vulnerability threshold is
  # met. Capture that status without letting `set -e` discard the JSON evidence;
  # CI must be able to upload the failing report for review.
  set +e
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v oneissuer-trivy-cache:/root/.cache/trivy \
    "$trivy_image" image \
    --scanners vuln \
    --format json \
    --exit-code 1 \
    --ignore-unfixed \
    --severity HIGH,CRITICAL \
    "$image" >"$temporary"
  scan_status=$?
  set -e

  if [ ! -s "$temporary" ]; then
    echo "Trivy did not produce a report (exit $scan_status)" >&2
    exit 1
  fi
  mv "$temporary" "$destination"
  chmod 600 "$destination"
  if [ -f "$output_dir/oneissuer.cdx.json" ]; then
    sha256sum "$output_dir/oneissuer.cdx.json" "$destination" >"$output_dir/SHA256SUMS"
  else
    sha256sum "$destination" >"$output_dir/SHA256SUMS"
  fi
  chmod 600 "$output_dir/SHA256SUMS"
  trap - EXIT HUP INT TERM

  python3 - "$destination" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    report = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Trivy report is not valid JSON: {error}")
findings = []
for result in report.get("Results") or []:
    findings.extend(result.get("Vulnerabilities") or [])
if findings:
    counts = {}
    for finding in findings:
        severity = finding.get("Severity", "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1
    raise SystemExit(f"Trivy returned fixable High/Critical findings: {counts}")
print("Trivy validated: no fixable High/Critical image vulnerabilities")
PY

  if [ "$scan_status" -ne 0 ]; then
    echo "Trivy scan failed with exit $scan_status; report retained at $destination" >&2
    exit "$scan_status"
  fi
  echo "Trivy report written to $destination"
}

case ${1:-} in
  scan)
    scan_image
    ;;
  sbom)
    write_sbom
    ;;
  all)
    write_sbom
    scan_image
    ;;
  *)
    usage
    ;;
esac
