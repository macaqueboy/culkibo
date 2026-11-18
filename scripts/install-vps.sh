#!/usr/bin/env bash
# Wrapper de compatibilidad: redirige al instalador endurecido `scripts/install.sh`.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/install.sh" "$@"
