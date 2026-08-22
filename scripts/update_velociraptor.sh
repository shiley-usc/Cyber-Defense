#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${VELOCIRAPTOR_LATEST_VERSION:?VELOCIRAPTOR_LATEST_VERSION is required}"
if [ ! -f .env ]; then
  echo ".env is required" >&2
  exit 2
fi
python3 - "$VERSION" <<'PY'
import sys
from pathlib import Path
version=sys.argv[1]
p=Path('.env')
lines=p.read_text().splitlines()
out=[]; found=False
for line in lines:
    if line.startswith('VELOCIRAPTOR_VERSION='):
        out.append('VELOCIRAPTOR_VERSION='+version); found=True
    else: out.append(line)
if not found: out.append('VELOCIRAPTOR_VERSION='+version)
p.write_text('\n'.join(out)+'\n')
PY
docker compose pull velociraptor-server velociraptor-builder
docker compose up -d velociraptor-server
"$ROOT/scripts/build_velociraptor_collectors.sh"
echo "Velociraptor updated to $VERSION and offline collectors rebuilt."
