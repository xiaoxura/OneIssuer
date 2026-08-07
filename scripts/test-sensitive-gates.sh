#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/oneissuer-sensitive-gates.XXXXXX")
cleanup() {
  rm -rf "$temporary_root"
}
trap cleanup 0 HUP INT TERM

canary='r1_abcdefghijklmnopqrstuvwxyz12345678901234567'
payload=${canary#r1_}
if [ "$(printf '%s' "$payload" | awk '{print length($0)}')" -ne 43 ]; then
  echo "internal test canary is not exactly 43 characters" >&2
  exit 1
fi

mkdir -p "$temporary_root/scripts" "$temporary_root/docs" "$temporary_root/examples" "$temporary_root/conformance"
cp "$root/scripts/check-sensitive-examples.sh" "$temporary_root/scripts/check-sensitive-examples.sh"
cp "$root/scripts/check-conformance-record.py" "$temporary_root/scripts/check-conformance-record.py"
cp -R "$root/conformance/phase-3" "$temporary_root/conformance/phase-3"
cp -R "$root/conformance/phase-4" "$temporary_root/conformance/phase-4"

printf '%s\n' 'public documentation fixture' > "$temporary_root/README.md"
printf '%s\n' 'security fixture' > "$temporary_root/SECURITY.md"
printf '%s\n' 'contribution fixture' > "$temporary_root/CONTRIBUTING.md"
printf '%s\n' 'minimal markdown fixture' > "$temporary_root/docs/public.md"

"$temporary_root/scripts/check-sensitive-examples.sh"
python3 "$temporary_root/scripts/check-conformance-record.py" >/dev/null

printf '\nsynthetic documentation value: %s\n' "$canary" >> "$temporary_root/docs/public.md"
public_log="$temporary_root/public-rejection.log"
if "$temporary_root/scripts/check-sensitive-examples.sh" >"$public_log" 2>&1; then
  echo "sensitive-example gate accepted a strict r1_ fixture" >&2
  exit 1
fi
if grep -F "$canary" "$public_log" >/dev/null 2>&1; then
  echo "sensitive-example diagnostic echoed the complete canary" >&2
  exit 1
fi

phase4_template="$temporary_root/conformance/phase-4/public-config.template.json"
phase4_copy="$temporary_root/conformance/phase-4/public-config.template.json.baseline"
cp "$phase4_template" "$phase4_copy"
sed "s/phase-four/phase-four $canary/" "$phase4_copy" > "$phase4_template"
conformance_log="$temporary_root/conformance-rejection.log"
if python3 "$temporary_root/scripts/check-conformance-record.py" >"$conformance_log" 2>&1; then
  echo "conformance-record gate accepted a strict r1_ fixture" >&2
  exit 1
fi
if grep -F "$canary" "$conformance_log" >/dev/null 2>&1; then
  echo "conformance-record diagnostic echoed the complete canary" >&2
  exit 1
fi

echo "sensitive gate self-test passed"
