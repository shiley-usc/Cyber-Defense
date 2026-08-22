#!/bin/sh
set -eu
URL=; SHA=; ID=; ROOT=/tmp/VelociraptorCollector; CLEANUP=0
while [ "$#" -gt 0 ]; do case "$1" in -CollectorUrl|--CollectorUrl) URL="$2"; shift 2;; -CollectorSha256|--CollectorSha256) SHA="$2"; shift 2;; -CollectionId|--CollectionId) ID="$2"; shift 2;; -DeployRoot|--DeployRoot) ROOT="$2"; shift 2;; -CleanupOnly|--CleanupOnly) CLEANUP=1; shift;; *) shift;; esac; done
if [ "$CLEANUP" -eq 1 ]; then rm -rf "$ROOT/$ID" "$ROOT/$ID.part"* "$ROOT/$ID.manifest.txt" "$ROOT/$ID.sha256"; exit 0; fi
[ -n "$URL" ] && [ -n "$SHA" ] && [ -n "$ID" ] || { echo 'CollectorUrl, CollectorSha256 and CollectionId are required.' >&2; exit 2; }
mkdir -p "$ROOT/$ID"
COLLECTOR="$ROOT/$ID/collector"
if command -v curl >/dev/null 2>&1; then curl -fsSL "$URL" -o "$COLLECTOR"; else wget -qO "$COLLECTOR" "$URL"; fi
ACTUAL="$(sha256sum "$COLLECTOR" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$COLLECTOR" | awk '{print $1}')"
[ "$ACTUAL" = "$SHA" ] || { echo 'Velociraptor collector SHA-256 mismatch.' >&2; exit 3; }
chmod 700 "$COLLECTOR"
cd "$ROOT/$ID"
./collector
ARCHIVE="$(ls -1t Collection-*.zip 2>/dev/null | head -n 1 || true)"
[ -n "$ARCHIVE" ] || { echo 'Velociraptor collector produced no collection ZIP.' >&2; exit 4; }
mv "$ARCHIVE" "$ID.zip"
split -b 8m "$ID.zip" "$ROOT/$ID.part"
rm -f "$ID.zip"
find "$ROOT" -maxdepth 1 -type f -name "$ID.part*" -print | sort > "$ROOT/$ID.manifest.txt"
rm -f "$COLLECTOR"
