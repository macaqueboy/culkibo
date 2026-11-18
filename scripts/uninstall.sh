#!/usr/bin/env bash
# =============================================================================
# Culkibo — desinstalador
#
#   sudo /opt/culkibo/scripts/uninstall.sh            # conserva los datos
#   sudo /opt/culkibo/scripts/uninstall.sh --purge    # borra también los datos
#
# Es un envoltorio sobre `install.sh --uninstall`. Existe como fichero aparte
# por una razón de producto, no técnica: quien quiere quitar tu software busca
# «uninstall», no una opción escondida del instalador. Que sea fácil de
# encontrar es parte de que sea fácil de instalar.
#
# La lógica vive en un solo sitio para que no puedan divergir.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SCRIPT_DIR/install.sh"

if [ ! -f "$INSTALLER" ]; then
  printf 'No se encuentra %s.\n' "$INSTALLER" >&2
  printf 'Desinstala con: curl -fsSL <url>/scripts/install.sh | sudo bash -s -- --uninstall\n' >&2
  exit 1
fi

exec bash "$INSTALLER" --uninstall "$@"
