#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
for spec in "$ROOT"/velociraptor/specs/*.yaml; do
  name="$(basename "$spec" .yaml)"
  echo "Building Velociraptor collector: $name"
  docker compose --profile build run --rm velociraptor-builder collector --datastore /datastore "$spec"
done
echo "Velociraptor collectors built under velociraptor/collectors/"
