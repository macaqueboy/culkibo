#!/usr/bin/env bash
# =============================================================================
# Banco de pruebas del instalador, contra un Debian 12 REAL con systemd.
#
#   ./scripts/test-install.sh
#
# Por qué un contenedor con systemd y no un `docker run debian bash install.sh`:
# la mitad de lo que hace el instalador ES systemd — crear la unidad,
# habilitarla, arrancarla, comprobar que sobrevive a un reinicio. Un contenedor
# sin PID 1 de systemd daría por buena una instalación que en un VPS no
# arrancaría nunca.
#
# Lo que este banco NO puede probar, y hay que decirlo: emisión de certificados
# por ACME (haría falta un dominio público apuntando aquí) y el comportamiento
# del cortafuegos del proveedor. Todo lo demás es real.
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="${CULKIBO_TEST_CONTAINER:-culkibo-install-test}"
IMAGE="${CULKIBO_TEST_IMAGE:-jrei/systemd-debian:12}"

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
PASS=0; FAIL=0

check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$label"; PASS=$((PASS + 1))
  else
    printf '  %s✗%s %s\n' "$RED" "$RESET" "$label"; FAIL=$((FAIL + 1))
  fi
}

dexec() { docker exec "$CONTAINER" "$@"; }
dsh()   { docker exec "$CONTAINER" bash -lc "$1"; }

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '\n%s%sBanco de pruebas del instalador de Culkibo%s\n' "$BOLD" "$GREEN" "$RESET"
printf '%sImagen: %s%s\n\n' "$DIM" "$IMAGE" "$RESET"

# --- Arranque del sistema de pruebas ----------------------------------------
cleanup
docker run -d --name "$CONTAINER" \
  --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock \
  -v "$REPO_ROOT":/src:ro \
  "$IMAGE" >/dev/null

# systemd tarda un momento en llegar a «running».
for _ in $(seq 1 30); do
  state=$(dexec systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
printf '%sSistema de pruebas: systemd %s%s\n\n' "$DIM" "$(dexec systemctl is-system-running 2>/dev/null || echo '?')" "$RESET"

# --- Instalación -------------------------------------------------------------
printf '%s1. Instalación desde cero%s\n' "$BOLD" "$RESET"
if dsh 'bash /src/scripts/install.sh --source /src --yes --no-caddy 2>&1 | tail -n 40'; then
  printf '  %s✓%s el instalador terminó con código 0\n' "$GREEN" "$RESET"; PASS=$((PASS + 1))
else
  printf '  %s✗%s el instalador falló\n' "$RED" "$RESET"; FAIL=$((FAIL + 1))
fi

printf '\n%s2. Estado del servicio%s\n' "$BOLD" "$RESET"
check "la unidad existe"                     dsh 'test -f /etc/systemd/system/culkibo.service'
check "el servicio está activo"              dsh 'systemctl is-active --quiet culkibo'
check "está habilitado para el arranque"     dsh 'systemctl is-enabled --quiet culkibo'
check "responde en /api/health"              dsh 'curl -fsS --max-time 5 http://127.0.0.1:3030/api/health'
check "NO corre como root"                   dsh '[ "$(systemctl show -p User --value culkibo)" = "culkibo" ]'
check "el usuario de sistema existe"         dsh 'id culkibo'
check "escucha sólo en 127.0.0.1"            dsh 'ss -ltn | grep -q "127.0.0.1:3030"'
check "NO escucha en 0.0.0.0"                dsh '! ss -ltn | grep -qE "0\.0\.0\.0:3030|\*:3030"'

printf '\n%s3. Secretos%s\n' "$BOLD" "$RESET"
# El token se extrae UNA vez a /tmp/tok y las comprobaciones siguientes buscan
# ese texto exacto donde no debería aparecer nunca.
dsh 'node -e "process.stdout.write(require(\"/opt/culkibo/data/auth.json\").token)" > /tmp/tok' >/dev/null 2>&1 || true
check "auth.json existe"                     dsh 'test -s /opt/culkibo/data/auth.json'
check "el token se puede leer"               dsh '[ "$(wc -c < /tmp/tok)" -ge 32 ]'
check "auth.json tiene permisos 600"         dsh '[ "$(stat -c %a /opt/culkibo/data/auth.json)" = "600" ]'
check "auth.json pertenece a culkibo"        dsh '[ "$(stat -c %U /opt/culkibo/data/auth.json)" = "culkibo" ]'
check "data/ tiene permisos 750"             dsh '[ "$(stat -c %a /opt/culkibo/data)" = "750" ]'
check "el token NO está en journalctl"       dsh 'journalctl -u culkibo --no-pager > /tmp/j.log; ! grep -qFf /tmp/tok /tmp/j.log'
check "el token NO está en el .env"          dsh '! grep -qFf /tmp/tok /opt/culkibo/.env'
check "la unidad NO lleva el token"          dsh '! grep -qFf /tmp/tok /etc/systemd/system/culkibo.service'
check "el token NO está en el entorno del servicio" dsh '! tr "\0" "\n" < /proc/$(systemctl show -p MainPID --value culkibo)/environ | grep -qFf /tmp/tok'

printf '\n%s4. La API exige el token desde fuera de bucle local%s\n' "$BOLD" "$RESET"
check "sin token, /api/projects responde"    dsh 'curl -fsS --max-time 5 http://127.0.0.1:3030/api/projects'
check "con token, /api/projects responde"    dsh 'curl -fsS --max-time 5 -H "Authorization: Bearer $(cat /tmp/tok)" http://127.0.0.1:3030/api/projects'
check "un token falso es rechazado"          dsh '[ "$(curl -s -o /dev/null -w %{http_code} -H "Authorization: Bearer noesestetoken" http://127.0.0.1:3030/api/projects)" = "401" ]'

printf '\n%s5. Catálogo servido por el daemon%s\n' "$BOLD" "$RESET"
check "/api/catalog/check dice ok"           dsh 'curl -fsS http://127.0.0.1:3030/api/catalog/check | grep -q "\"ok\":true"'
check "hay 13 plantillas"                    dsh '[ "$(curl -fsS http://127.0.0.1:3030/api/catalog/templates | node -e "let s=\"\";process.stdin.on(\"data\",d=>s+=d).on(\"end\",()=>console.log(JSON.parse(s).templates.length))")" = "13" ]'

printf '\n%s6. Idempotencia: segunda ejecución%s\n' "$BOLD" "$RESET"
TOKEN_BEFORE=$(dsh 'cat /tmp/tok')
if dsh 'bash /src/scripts/install.sh --source /src --yes --no-caddy >/tmp/second.log 2>&1'; then
  printf '  %s✓%s la segunda ejecución terminó con código 0\n' "$GREEN" "$RESET"; PASS=$((PASS + 1))
else
  printf '  %s✗%s la segunda ejecución falló\n' "$RED" "$RESET"; FAIL=$((FAIL + 1))
  dsh 'tail -n 30 /tmp/second.log' || true
fi
TOKEN_AFTER=$(dsh 'node -e "process.stdout.write(require(\"/opt/culkibo/data/auth.json\").token)"')
check "el token NO ha cambiado"              test "$TOKEN_BEFORE" = "$TOKEN_AFTER"
check "el servicio sigue activo"             dsh 'systemctl is-active --quiet culkibo'
check "no se ha duplicado el usuario"        dsh '[ "$(grep -c "^culkibo:" /etc/passwd)" = "1" ]'

printf '\n%s7. Supervivencia al reinicio%s\n' "$BOLD" "$RESET"
# Reiniciar el contenedor reinicia PID 1, que es systemd: es lo más parecido a
# un reinicio de servidor que se puede hacer aquí.
docker restart "$CONTAINER" >/dev/null
for _ in $(seq 1 45); do
  if dsh 'curl -fsS --max-time 2 http://127.0.0.1:3030/api/health' >/dev/null 2>&1; then break; fi
  sleep 1
done
check "el servicio arrancó solo tras reiniciar" dsh 'systemctl is-active --quiet culkibo'
check "y vuelve a responder"                 dsh 'curl -fsS --max-time 5 http://127.0.0.1:3030/api/health'

printf '\n%s8. Desinstalación conservando datos%s\n' "$BOLD" "$RESET"
dsh 'bash /src/scripts/install.sh --uninstall --yes >/tmp/uninstall.log 2>&1' || true
check "el servicio ya no está activo"        dsh '! systemctl is-active --quiet culkibo'
check "la unidad ha desaparecido"            dsh '! test -f /etc/systemd/system/culkibo.service'
check "systemd ya no la conoce"              dsh '! systemctl list-unit-files | grep -q "^culkibo.service"'
check "los datos se conservan"               dsh 'test -f /opt/culkibo/data/auth.json'
check "el código se ha ido"                  dsh '! test -f /opt/culkibo/server/index.js'

printf '\n%s9. Desinstalación con --purge%s\n' "$BOLD" "$RESET"
dsh 'bash /src/scripts/install.sh --uninstall --purge --yes >/tmp/purge.log 2>&1' || true
check "el directorio ha desaparecido"        dsh '! test -d /opt/culkibo'
check "el usuario de sistema se ha ido"      dsh '! id culkibo'

printf '\n%s──────────────────────────────────────────────%s\n' "$DIM" "$RESET"
if [ "$FAIL" -eq 0 ]; then
  printf '%s%s%d comprobaciones superadas, 0 fallos%s\n\n' "$BOLD" "$GREEN" "$PASS" "$RESET"
  exit 0
fi
printf '%s%s%d superadas, %d fallos%s\n\n' "$BOLD" "$RED" "$PASS" "$FAIL" "$RESET"
exit 1
