#!/usr/bin/env bash
# =============================================================================
# Culkibo — instalador para servidores Debian y Ubuntu
#
#   curl -fsSL https://raw.githubusercontent.com/<repo>/main/scripts/install.sh | bash
#
# Compatible con Debian 11/12/13 y Ubuntu 20.04/22.04/24.04.
#
# -----------------------------------------------------------------------------
# DECISIONES QUE NO SON OBVIAS
# -----------------------------------------------------------------------------
#
# 1. EL DAEMON ESCUCHA EN 127.0.0.1, NO EN 0.0.0.0.
#
#    Es lo contrario de lo que hace casi todo instalador de este tipo, y es
#    deliberado. El puerto 3030 es el plano de CONTROL: quien lo alcance
#    despliega, borra proyectos y lee credenciales. Dejarlo abierto a internet
#    y confiar en que el usuario configure un cortafuegos es trasladarle un
#    riesgo que no ha pedido.
#
#    Al panel se llega por un túnel SSH (`ssh -L`), que no necesita abrir nada.
#    Quien quiera exponerlo pasa `--bind 0.0.0.0`, y entonces el instalador
#    fuerza CULKIBO_REQUIRE_TOKEN=1 para que ni una sola petición pase sin
#    credencial.
#
# 2. EL SERVICIO NO CORRE COMO ROOT.
#
#    Se crea un usuario de sistema `culkibo` y se le mete en el grupo `docker`.
#    Hay que decirlo con todas las letras: pertenecer al grupo `docker` equivale
#    a root, porque se puede montar `/` dentro de un contenedor. Aun así la
#    diferencia importa — el proceso no puede escribir en `/etc`, ni en los
#    binarios del sistema, ni leer `/root`, y la unidad systemd añade
#    ProtectSystem, PrivateTmp y NoNewPrivileges.
#
# 3. EL TOKEN NO PASA POR NINGÚN REGISTRO.
#
#    Lo genera el propio daemon en `data/auth.json` con permisos 0600. Este
#    script lo LEE y lo imprime en la terminal (`/dev/tty` cuando existe), y no
#    lo pone en la unidad de systemd, ni en una variable de entorno del
#    servicio, ni en `journalctl`. `set -x` está prohibido en este fichero por
#    ese motivo.
#
# 4. IDEMPOTENTE.
#
#    Ejecutarlo dos veces actualiza el código y reinicia el servicio. No toca
#    `data/`, no regenera el token, no duplica reglas de cortafuegos y no vuelve
#    a crear el usuario. Cada paso comprueba antes de actuar.
# =============================================================================

set -euo pipefail

# Nunca `set -x`: dejaría el token en el registro del terminal y en cualquier
# transcripción que alguien pegue en un foro pidiendo ayuda.

# -----------------------------------------------------------------------------
# Constantes
# -----------------------------------------------------------------------------

readonly CULKIBO_VERSION="1.0.0"
readonly DEFAULT_REPO="https://github.com/macaqueboy/culkibo.git"
readonly DEFAULT_BRANCH="main"
readonly DEFAULT_DIR="/opt/culkibo"
readonly DEFAULT_PORT="3030"
readonly DEFAULT_USER="culkibo"
readonly SERVICE_NAME="culkibo"
readonly UNIT_PATH="/etc/systemd/system/culkibo.service"
readonly MIN_NODE_MAJOR=20
readonly NODE_MAJOR_TO_INSTALL=22

# -----------------------------------------------------------------------------
# Salida
# -----------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi

STEP_CURRENT=0
STEP_TOTAL=9
WARNINGS=()

step()  { STEP_CURRENT=$((STEP_CURRENT + 1)); printf '\n%s[%d/%d]%s %s%s%s\n' "$C_DIM" "$STEP_CURRENT" "$STEP_TOTAL" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
info()  { printf '      %s\n' "$1"; }
ok()    { printf '   %s✓%s  %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn()  { printf '   %s!%s  %s%s%s\n' "$C_YELLOW" "$C_RESET" "$C_YELLOW" "$1" "$C_RESET"; WARNINGS+=("$1"); }
die()   { printf '\n   %s✗  %s%s\n\n' "$C_RED" "$1" "$C_RESET" >&2; exit 1; }

# ¿Hay una terminal de verdad detrás de /dev/tty?
#
# No basta con `[ -r /dev/tty ]`: el nodo de dispositivo existe y tiene los
# permisos puestos aunque el proceso no tenga terminal de control, y abrirlo
# falla entonces con ENXIO. Se descubrió probando el instalador con
# `docker exec` sin `-t`, que es exactamente la forma en que lo ejecuta un
# script de automatización. La única comprobación que no miente es intentar
# abrirlo.
has_tty() { { true > /dev/tty; } 2>/dev/null; }

# Pregunta sí/no. Con `curl | bash`, la entrada estándar es el propio script:
# preguntar por stdin leería el resto del código como respuesta. Por eso se lee
# siempre de /dev/tty, y sin terminal se toma el valor por defecto seguro.
confirm() {
  local prompt="$1" default="${2:-n}"
  if [ "$ASSUME_YES" = "1" ]; then return 0; fi
  if ! has_tty; then
    [ "$default" = "y" ] && return 0 || return 1
  fi
  local reply=""
  printf '   %s?%s  %s [s/N] ' "$C_CYAN" "$C_RESET" "$prompt" > /dev/tty
  read -r reply < /dev/tty || true
  case "$reply" in [sSyY]*) return 0 ;; *) return 1 ;; esac
}

# -----------------------------------------------------------------------------
# Argumentos
# -----------------------------------------------------------------------------

INSTALL_DIR="${CULKIBO_INSTALL_DIR:-$DEFAULT_DIR}"
PORT="${CULKIBO_PORT:-$DEFAULT_PORT}"
RUN_USER="${CULKIBO_USER:-$DEFAULT_USER}"
REPO_URL="${CULKIBO_REPO:-$DEFAULT_REPO}"
BRANCH="${CULKIBO_BRANCH:-$DEFAULT_BRANCH}"
BIND_ADDR="127.0.0.1"
WITH_CADDY=1
ASSUME_YES=0
ALLOW_ROOT_SERVICE=0
ACTION="install"
PURGE=0
SOURCE_DIR=""

usage() {
  cat <<'EOF'
Culkibo — instalador para servidores Debian y Ubuntu

  curl -fsSL <url>/scripts/install.sh | bash
  curl -fsSL <url>/scripts/install.sh | bash -s -- --bind 0.0.0.0

Opciones:
  --dir <ruta>          Directorio de instalación        (por defecto /opt/culkibo)
  --port <puerto>       Puerto del plano de control      (por defecto 3030)
  --user <usuario>      Usuario de sistema del servicio  (por defecto culkibo)
  --bind <direccion>    Dirección de escucha             (por defecto 127.0.0.1)
                        Con 0.0.0.0 se exige token en todas las peticiones.
  --repo <url>          Repositorio de origen
  --branch <rama>       Rama a instalar                  (por defecto main)
  --source <ruta>       Instalar desde una copia local en lugar de clonar
  --no-caddy            No levantar el plano de datos (Caddy)
  --allow-root-service  Ejecutar el servicio como root. Desaconsejado.
  --yes                 No preguntar nada
  --uninstall           Desinstalar, conservando los datos
  --purge               Con --uninstall, borrar también los datos. Irreversible.
  --help                Esta ayuda

Desinstalación:
  curl -fsSL <url>/scripts/install.sh | bash -s -- --uninstall
  sudo /opt/culkibo/scripts/uninstall.sh
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)        INSTALL_DIR="${2:?--dir necesita una ruta}"; shift 2 ;;
    --port)       PORT="${2:?--port necesita un número}"; shift 2 ;;
    --user)       RUN_USER="${2:?--user necesita un nombre}"; shift 2 ;;
    --bind)       BIND_ADDR="${2:?--bind necesita una dirección}"; shift 2 ;;
    --repo)       REPO_URL="${2:?--repo necesita una URL}"; shift 2 ;;
    --branch)     BRANCH="${2:?--branch necesita una rama}"; shift 2 ;;
    --source)     SOURCE_DIR="${2:?--source necesita una ruta}"; shift 2 ;;
    --no-caddy)   WITH_CADDY=0; shift ;;
    --allow-root-service) ALLOW_ROOT_SERVICE=1; shift ;;
    --yes|-y)     ASSUME_YES=1; shift ;;
    --uninstall)  ACTION="uninstall"; shift ;;
    --purge)      PURGE=1; shift ;;
    --help|-h)    usage; exit 0 ;;
    *)            printf 'Opción desconocida: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

# Validación de los valores que van a acabar en rutas, unidades de systemd y
# nombres de usuario. Lista blanca estricta: si no encaja, se rechaza. Nada de
# lo que llega por argumento se interpola en un comando sin pasar por aquí.
case "$PORT" in ''|*[!0-9]*) die "Puerto inválido: «$PORT»" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "Puerto fuera de rango: $PORT"
printf '%s' "$RUN_USER" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "Nombre de usuario inválido: «$RUN_USER»"
printf '%s' "$INSTALL_DIR" | grep -Eq '^/[A-Za-z0-9._/-]+$' || die "Directorio de instalación inválido: «$INSTALL_DIR»"
printf '%s' "$BIND_ADDR" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || die "Dirección de escucha inválida: «$BIND_ADDR»"

readonly ENV_FILE="$INSTALL_DIR/.env"
readonly DATA_DIR="$INSTALL_DIR/data"

# -----------------------------------------------------------------------------
# Utilidades
# -----------------------------------------------------------------------------

has() { command -v "$1" >/dev/null 2>&1; }

# ¿Está ocupado un puerto TCP? Se prueban tres herramientas porque ninguna está
# garantizada en una imagen mínima de Debian: `ss` (iproute2), `netstat`
# (net-tools, ya no va por defecto) y, como último recurso, /proc/net/tcp.
port_in_use() {
  local port="$1"
  if has ss; then
    ss -H -ltn "sport = :$port" 2>/dev/null | grep -q . && return 0 || return 1
  fi
  if has netstat; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$port$" && return 0 || return 1
  fi
  local hex
  hex=$(printf '%04X' "$port")
  grep -qiE "^ *[0-9]+: [0-9A-F]{8}:$hex " /proc/net/tcp /proc/net/tcp6 2>/dev/null && return 0 || return 1
}

# Quién ocupa un puerto, cuando se puede averiguar. Informativo.
port_owner() {
  local port="$1"
  if has ss; then
    ss -H -ltnp "sport = :$port" 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -n1
  fi
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >/dev/null
}

# Ejecuta algo como el usuario del servicio. `runuser` no pide contraseña y no
# arrastra el entorno de PAM de `su -`, que en algunos Debian rompe npm.
as_service_user() {
  if [ "$RUN_USER" = "root" ]; then
    "$@"
  else
    runuser -u "$RUN_USER" -- "$@"
  fi
}

# -----------------------------------------------------------------------------
# Desinstalación
# -----------------------------------------------------------------------------
#
# Está aquí, en el mismo fichero y en la misma ejecución, por una razón de
# producto: quien no puede quitar tu software limpiamente no lo instala. Y por
# una razón práctica: una desinstalación que hay que descargar aparte es una
# desinstalación que nadie encuentra el día que la necesita.

do_uninstall() {
  printf '\n%s%sDesinstalando Culkibo%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
  [ "$(id -u)" -eq 0 ] || die "La desinstalación necesita privilegios de root. Usa sudo."

  if [ "$PURGE" = "1" ]; then
    warn "--purge borrará $DATA_DIR: proyectos, dominios, certificados y el token."
    if ! confirm "¿Seguro que quieres borrar también todos los datos?"; then
      die "Cancelado. Sin --purge se desinstala conservando los datos."
    fi
  fi

  if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}.service"; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    ok "Servicio detenido y deshabilitado"
  else
    info "No había ningún servicio systemd instalado"
  fi

  if [ -f "$UNIT_PATH" ]; then
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
    ok "Unidad de systemd eliminada"
  fi

  # Los contenedores de Culkibo llevan la etiqueta `culkibo.managed=true` desde
  # que se crean, precisamente para poder encontrarlos ahora sin adivinar
  # nombres. Los volúmenes NO se tocan salvo con --purge.
  if has docker && docker info >/dev/null 2>&1; then
    local managed
    managed=$(docker ps -aq --filter "label=culkibo.managed=true" 2>/dev/null || true)
    if [ -n "$managed" ]; then
      # shellcheck disable=SC2086
      docker rm -f $managed >/dev/null 2>&1 || true
      ok "Contenedores gestionados eliminados"
    fi
    if docker ps -aq --filter "name=^culkibo-caddy$" | grep -q .; then
      docker rm -f culkibo-caddy >/dev/null 2>&1 || true
      ok "Plano de datos (Caddy) eliminado"
    fi
    if [ "$PURGE" = "1" ]; then
      local vols
      vols=$(docker volume ls -q --filter "name=^culkibo_" 2>/dev/null || true)
      if [ -n "$vols" ]; then
        # shellcheck disable=SC2086
        docker volume rm $vols >/dev/null 2>&1 || true
        ok "Volúmenes de Culkibo eliminados"
      fi
      docker network ls -q --filter "label=culkibo.managed=true" | while read -r netid; do
        [ -n "$netid" ] && docker network rm "$netid" >/dev/null 2>&1 || true
      done
    else
      info "Los volúmenes de Docker se conservan (usa --purge para borrarlos)"
    fi
  fi

  # Reglas de cortafuegos que pusimos nosotros (solo si llevan el comentario 'culkibo' para no romper otros servicios).
  if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ufw status 2>/dev/null | grep -q "# culkibo"; then
      ufw --force delete allow 80/tcp  comment 'culkibo' >/dev/null 2>&1 || true
      ufw --force delete allow 443/tcp comment 'culkibo' >/dev/null 2>&1 || true
      ufw --force delete allow 443/udp comment 'culkibo' >/dev/null 2>&1 || true
      ok "Reglas de cortafuegos de Culkibo retiradas"
    fi
  fi

  if [ "$PURGE" = "1" ]; then
    rm -rf "$INSTALL_DIR"
    ok "Directorio $INSTALL_DIR eliminado por completo"
    if id "$RUN_USER" >/dev/null 2>&1 && [ "$RUN_USER" != "root" ]; then
      userdel "$RUN_USER" 2>/dev/null || true
      ok "Usuario de sistema «$RUN_USER» eliminado"
    fi
  else
    # Se borra el código y se conservan los datos. Así «desinstalar y volver a
    # instalar» recupera los proyectos, que es lo que la gente espera.
    if [ -d "$INSTALL_DIR" ]; then
      find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name data ! -name projects ! -name .env -exec rm -rf {} + 2>/dev/null || true
      ok "Código eliminado. Se conservan $DATA_DIR, $INSTALL_DIR/projects y .env"
    fi
  fi

  printf '\n%s%sCulkibo desinstalado.%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  if [ "$PURGE" != "1" ]; then
    printf '   Los datos siguen en %s. Para borrarlos: %s--uninstall --purge%s\n\n' "$DATA_DIR" "$C_BOLD" "$C_RESET"
  else
    printf '\n'
  fi
  exit 0
}

# -----------------------------------------------------------------------------
# 1. Comprobaciones previas
# -----------------------------------------------------------------------------

preflight() {
  step "Comprobando el sistema"

  [ "$(id -u)" -eq 0 ] || die "Este instalador necesita root para instalar paquetes y crear el servicio. Usa: curl ... | sudo bash"

  [ "$(uname -s)" = "Linux" ] || die "Este instalador es para Linux. En Windows y macOS usa 'npm install && npm start'."

  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ok "Arquitectura $(uname -m)" ;;
    *) die "Arquitectura no soportada: $(uname -m). Culkibo necesita x86_64 o arm64." ;;
  esac

  has apt-get || die "No hay apt-get: este instalador cubre Debian y Ubuntu. En otra distribución, instala Node 20+ y Docker a mano y ejecuta 'npm install && npm run build'."

  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    ok "Sistema ${PRETTY_NAME:-desconocido}"
    case "${ID:-}${ID_LIKE:-}" in
      *debian*|*ubuntu*) : ;;
      *) warn "Distribución no probada («${ID:-?}»). El instalador seguirá, pero puede fallar." ;;
    esac
  fi

  # systemd es un requisito duro: sin él no hay «sobrevive al reinicio», que es
  # la mitad del valor de instalar esto en un servidor.
  [ -d /run/systemd/system ] || die "Este servidor no usa systemd. Culkibo no puede instalarse como servicio aquí."

  local mem_mb
  mem_mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$mem_mb" -lt 900 ]; then
    warn "Sólo hay ${mem_mb} MB de memoria. Culkibo arranca, pero compilar el panel necesita ~1 GB y los servicios del catálogo bastante más."
  else
    ok "Memoria: ${mem_mb} MB"
  fi

  local free_mb
  free_mb=$(df -Pm "$(dirname "$INSTALL_DIR")" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
  if [ "${free_mb:-0}" -lt 3000 ]; then
    warn "Quedan ${free_mb:-?} MB libres en $(dirname "$INSTALL_DIR"). Las imágenes de Docker ocupan varios GB."
  else
    ok "Espacio libre: ${free_mb} MB"
  fi

  # --- Puertos -------------------------------------------------------------
  if port_in_use "$PORT"; then
    if [ -f "$UNIT_PATH" ] && systemctl is-active --quiet "$SERVICE_NAME"; then
      ok "El puerto $PORT lo tiene el propio Culkibo (se reinstalará encima)"
    else
      die "El puerto $PORT ya está ocupado$( [ -n "$(port_owner "$PORT")" ] && printf ' por %s' "$(port_owner "$PORT")" ). Usa --port para elegir otro."
    fi
  else
    ok "Puerto $PORT libre"
  fi

  if [ "$WITH_CADDY" = "1" ]; then
    local blocked=""
    port_in_use 80  && blocked="80"
    port_in_use 443 && blocked="${blocked:+$blocked y }443"
    if [ -n "$blocked" ]; then
      if has docker && docker ps --filter "name=^culkibo-caddy$" --filter "status=running" -q 2>/dev/null | grep -q .; then
        ok "Puertos 80 y 443 gestionados por nuestro propio culkibo-caddy (reinstalación idempotente)"
      else
        local owner80 owner443
        owner80=$(port_owner 80); owner443=$(port_owner 443)
        warn "El puerto $blocked ya está en uso${owner80:+ (80: $owner80)}${owner443:+ (443: $owner443)}."
        warn "No se levantará Caddy: pararía lo que ya está sirviendo ahí. Culkibo se instalará sin plano de datos."
        WITH_CADDY=0
      fi
    else
      ok "Puertos 80 y 443 libres"
    fi
  fi

  # --- Exposición del plano de control -------------------------------------
  if [ "$BIND_ADDR" = "0.0.0.0" ]; then
    warn "Has pedido --bind 0.0.0.0: el plano de control quedará accesible desde la red."
    warn "Se activará CULKIBO_REQUIRE_TOKEN=1 para que ninguna petición pase sin credencial."
    if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
      if ufw status 2>/dev/null | grep -qE "^${PORT}(/tcp)?[[:space:]]+ALLOW"; then
        warn "UFW ya permite el puerto $PORT desde cualquier origen. Restríngelo a tu IP: ufw allow from <tu-ip> to any port $PORT"
      fi
    else
      warn "No hay cortafuegos UFW activo. El puerto $PORT quedará abierto a internet: restringe el acceso en el panel de tu proveedor."
    fi
    if ! confirm "¿Continuar exponiendo el plano de control?"; then
      die "Cancelado. Sin --bind, Culkibo escucha sólo en 127.0.0.1 y se accede por túnel SSH."
    fi
  else
    ok "El plano de control escuchará sólo en $BIND_ADDR (acceso por túnel SSH)"
  fi

  # --- Usuario del servicio -------------------------------------------------
  if [ "$RUN_USER" = "root" ] && [ "$ALLOW_ROOT_SERVICE" != "1" ]; then
    die "Negarse a instalar un servicio que corre como root es deliberado. Culkibo crea el usuario «culkibo» por ti; si de verdad quieres root, pasa --allow-root-service."
  fi
  if [ "$RUN_USER" = "root" ]; then
    warn "El servicio correrá como root. Un fallo en cualquier dependencia de npm será root en este servidor."
  fi
}

# -----------------------------------------------------------------------------
# 2. Paquetes base
# -----------------------------------------------------------------------------

install_base_packages() {
  step "Instalando dependencias del sistema"
  local missing=()
  for pkg in curl git ca-certificates gnupg openssl; do
    has "$pkg" || missing+=("$pkg")
  done
  # `ss` viene en iproute2 y se usa para comprobar puertos; `runuser` en
  # util-linux, que siempre está.
  has ss || missing+=("iproute2")

  if [ ${#missing[@]} -eq 0 ]; then
    ok "Todo lo necesario ya estaba instalado"
    return
  fi

  info "Faltan: ${missing[*]}"
  apt-get update -qq >/dev/null
  apt_install "${missing[@]}"
  ok "Instalados: ${missing[*]}"
}

# -----------------------------------------------------------------------------
# 3. Node.js
# -----------------------------------------------------------------------------

install_node() {
  step "Comprobando Node.js"

  local current=0
  if has node; then
    current=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)
    current=${current:-0}
  fi

  if [ "$current" -ge "$MIN_NODE_MAJOR" ]; then
    ok "Node.js $(node -v) cumple el mínimo (>= $MIN_NODE_MAJOR)"
    return
  fi

  if [ "$current" -gt 0 ]; then
    info "Node.js v$current es anterior al mínimo v$MIN_NODE_MAJOR; se instalará v$NODE_MAJOR_TO_INSTALL"
  else
    info "Node.js no está instalado; se instalará v$NODE_MAJOR_TO_INSTALL desde NodeSource"
  fi

  install -d -m 0755 /etc/apt/keyrings
  # `--yes` en gpg para que reejecutar el instalador no se quede esperando a que
  # alguien confirme que sí, que sobrescriba el llavero.
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  chmod 0644 /etc/apt/keyrings/nodesource.gpg
  printf 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_%s.x nodistro main\n' \
    "$NODE_MAJOR_TO_INSTALL" > /etc/apt/sources.list.d/nodesource.list
  apt-get update -qq >/dev/null
  apt_install nodejs
  has node || die "La instalación de Node.js falló. Instálalo a mano y vuelve a ejecutar."
  ok "Node.js $(node -v) instalado"
}

# -----------------------------------------------------------------------------
# 4. Docker
# -----------------------------------------------------------------------------

install_docker() {
  step "Comprobando Docker"

  if has docker && docker info >/dev/null 2>&1; then
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo activo) operativo"
    return
  fi

  if has docker; then
    info "El cliente de Docker existe pero el daemon no responde; se intentará arrancarlo"
    systemctl enable --now docker >/dev/null 2>&1 || true
    if docker info >/dev/null 2>&1; then
      ok "Daemon de Docker arrancado"
      return
    fi
  fi

  # El repositorio oficial de Docker, no el `docker.io` de Debian: la versión
  # empaquetada por la distribución suele ir uno o dos años por detrás y sin
  # `docker compose` v2.
  info "Instalando Docker Engine desde el repositorio oficial"
  install -d -m 0755 /etc/apt/keyrings
  local distro_id distro_codename
  distro_id=$(. /etc/os-release && case "${ID:-} ${ID_LIKE:-}" in *ubuntu*) echo ubuntu ;; *) echo debian ;; esac)
  distro_codename=$(. /etc/os-release && if [ "$distro_id" = "ubuntu" ]; then echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-noble}}"; else echo "${DEBIAN_CODENAME:-${VERSION_CODENAME:-bookworm}}"; fi)

  curl -fsSL "https://download.docker.com/linux/$distro_id/gpg" \
    | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  chmod 0644 /etc/apt/keyrings/docker.gpg
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$distro_id" "$distro_codename" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq >/dev/null
  apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker >/dev/null 2>&1 || true

  if docker info >/dev/null 2>&1; then
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) instalado y en marcha"
  else
    warn "Docker quedó instalado pero el daemon no responde. Culkibo arrancará en modo degradado (sin contenedores ni catálogo)."
  fi
}

# -----------------------------------------------------------------------------
# 5. Usuario del servicio
# -----------------------------------------------------------------------------

create_service_user() {
  step "Preparando el usuario del servicio"

  if [ "$RUN_USER" = "root" ]; then
    warn "Saltando la creación de usuario: el servicio correrá como root"
    return
  fi

  if id "$RUN_USER" >/dev/null 2>&1; then
    ok "El usuario «$RUN_USER» ya existe"
  else
    # `--system` para que no tenga caducidad de contraseña ni aparezca en la
    # pantalla de inicio de sesión. Con shell real porque npm y los scripts de
    # build la necesitan.
    useradd --system --create-home --home-dir "/home/$RUN_USER" --shell /bin/bash "$RUN_USER"
    ok "Usuario de sistema «$RUN_USER» creado"
  fi

  if getent group docker >/dev/null 2>&1; then
    if id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx docker; then
      ok "«$RUN_USER» ya pertenece al grupo docker"
    else
      usermod -aG docker "$RUN_USER"
      ok "«$RUN_USER» añadido al grupo docker"
    fi
    # Decirlo, no esconderlo: es la concesión de seguridad real de este diseño.
    info "Pertenecer al grupo docker equivale a root en la práctica: quien controle"
    info "ese proceso puede montar / dentro de un contenedor. Es el precio de que"
    info "Culkibo orqueste contenedores sin ser root."
  else
    warn "No existe el grupo docker: Culkibo funcionará sin contenedores hasta que Docker esté disponible."
  fi
}

# -----------------------------------------------------------------------------
# 6. Código
# -----------------------------------------------------------------------------

fetch_source() {
  step "Obteniendo el código de Culkibo"

  install -d -m 0755 "$INSTALL_DIR"

  if [ -n "$SOURCE_DIR" ]; then
    [ -f "$SOURCE_DIR/server/index.js" ] || die "«$SOURCE_DIR» no parece una copia de Culkibo (falta server/index.js)"
    # `--exclude` para no pisar los datos de una instalación previa con los del
    # árbol de origen, que es exactamente lo que rompería la idempotencia.
    if has rsync; then
      rsync -a --delete \
        --exclude 'data' --exclude 'projects' --exclude 'node_modules' \
        --exclude 'web/node_modules' --exclude '.git' --exclude '.env' \
        "$SOURCE_DIR"/ "$INSTALL_DIR"/
    else
      # Sin rsync: copia sin borrar, suficiente para una instalación nueva.
      ( cd "$SOURCE_DIR" && tar --exclude=./data --exclude=./projects \
          --exclude=./node_modules --exclude=./web/node_modules \
          --exclude=./.git --exclude=./.env -cf - . ) | ( cd "$INSTALL_DIR" && tar -xf - )
    fi
    ok "Código copiado desde $SOURCE_DIR"
  elif [ -d "$INSTALL_DIR/.git" ]; then
    # Reinstalación sobre un clon existente: actualizar sin perder nada que no
    # esté versionado (los datos no lo están).
    if ! git config --global --get-all safe.directory 2>/dev/null | grep -Fxq "$INSTALL_DIR"; then
      git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
    fi
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$BRANCH" >/dev/null 2>&1 \
      || die "No se pudo actualizar desde $REPO_URL (rama $BRANCH)"
    git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH" >/dev/null
    ok "Código actualizado a origin/$BRANCH ($(git -C "$INSTALL_DIR" rev-parse --short HEAD))"
  else
    if [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null | grep -v '^data$' | grep -v '^projects$' || true)" ]; then
      die "$INSTALL_DIR ya tiene contenido que no es un clon de git. Vacíalo o usa --dir."
    fi
    # `--depth 1`: nadie necesita el historial en un servidor, y clonarlo entero
    # en un VPS con disco pequeño es tirar espacio.
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR.clone" >/dev/null 2>&1 \
      || die "No se pudo clonar $REPO_URL (rama $BRANCH)"
    # Mover el contenido del clon sin tocar data/ si ya existía.
    ( cd "$INSTALL_DIR.clone" && tar -cf - . ) | ( cd "$INSTALL_DIR" && tar -xf - )
    rm -rf "$INSTALL_DIR.clone"
    ok "Código clonado desde $REPO_URL"
  fi

  # Permisos 0700 estrictos en directorios de datos/config (cierra Dokploy CVE-2026-129315 / CWE-732)
  install -d -m 0700 "$DATA_DIR" "$DATA_DIR/certs" "$DATA_DIR/backups"
  install -d -m 0750 "$INSTALL_DIR/projects"
  chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR"
  # 0700 en los datos: ahí viven auth.json, las claves de cifrado y los
  # certificados. Ningún otro usuario del sistema tiene acceso de lectura o escritura.
  chmod 0700 "$DATA_DIR" "$DATA_DIR/certs" "$DATA_DIR/backups"
  ok "Permisos aplicados ($RUN_USER, datos en 0700)"
}

# -----------------------------------------------------------------------------
# 7. Dependencias y compilación
# -----------------------------------------------------------------------------

build_app() {
  step "Instalando dependencias y compilando el panel"

  # `npm ci` cuando hay lockfile: reproducible y bastante más rápido que
  # `npm install`, que reescribe el lockfile en el servidor.
  local npm_cmd="install"
  [ -f "$INSTALL_DIR/package-lock.json" ] && npm_cmd="ci"

  info "Dependencias del servidor (npm $npm_cmd)…"
  as_service_user env -C "$INSTALL_DIR" npm "$npm_cmd" --omit=dev --no-audit --no-fund >/dev/null 2>&1 \
    || as_service_user env -C "$INSTALL_DIR" npm install --omit=dev --no-audit --no-fund >/dev/null \
    || die "Falló la instalación de dependencias del servidor"
  ok "Dependencias del servidor listas"

  if [ -d "$INSTALL_DIR/web" ]; then
    info "Compilando el panel (esto tarda un par de minutos)…"
    local web_npm="install"
    [ -f "$INSTALL_DIR/web/package-lock.json" ] && web_npm="ci"
    # El panel necesita sus devDependencies para compilar: vite, tailwind y
    # typescript están ahí. Por eso se pasa `--include=dev` explícitamente (ignora NODE_ENV=production del host).
    as_service_user env -C "$INSTALL_DIR/web" npm "$web_npm" --include=dev --no-audit --no-fund >/dev/null 2>&1 \
      || as_service_user env -C "$INSTALL_DIR/web" npm install --include=dev --no-audit --no-fund >/dev/null \
      || die "Falló la instalación de dependencias del panel"
    if as_service_user env -C "$INSTALL_DIR" npm run build >/dev/null 2>&1; then
      ok "Panel compilado en web/dist"
      rm -rf "$INSTALL_DIR/web/node_modules" 2>/dev/null || true
    else
      warn "El panel no compiló. El daemon y la API funcionarán; la interfaz no se servirá."
      warn "Reintenta con: sudo -u $RUN_USER npm --prefix $INSTALL_DIR run build"
    fi
  fi
}

# -----------------------------------------------------------------------------
# 8. Configuración y servicio
# -----------------------------------------------------------------------------

write_env_file() {
  # El .env sólo lleva configuración, NUNCA el token. El token vive en
  # data/auth.json con permisos 0600 y lo gestiona el propio daemon: si
  # estuviera aquí, cualquier `cat .env` en una sesión compartida lo filtraría.
  if [ -f "$ENV_FILE" ]; then
    ok "Se conserva la configuración existente en .env"
    return
  fi
  cat > "$ENV_FILE" <<EOF
# Generado por scripts/install.sh el $(date -u +%Y-%m-%dT%H:%M:%SZ)
# El token de acceso NO está aquí: vive en data/auth.json con permisos 0600.
PORT=$PORT
CULKIBO_BIND=$BIND_ADDR
NODE_ENV=production
EOF
  if [ "$BIND_ADDR" = "0.0.0.0" ]; then
    # Con el plano de control expuesto, la exención de loopback del middleware
    # de autenticación deja de ser aceptable.
    printf 'CULKIBO_REQUIRE_TOKEN=1\n' >> "$ENV_FILE"
  fi
  chown "$RUN_USER":"$RUN_USER" "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  ok "Configuración escrita en .env (0600)"
}

install_systemd_unit() {
  step "Instalando el servicio de systemd"

  write_env_file

  # `WantedBy=multi-user.target` es lo que hace que sobreviva al reinicio.
  # `After=docker.service` y no sólo `Wants`: arrancar antes que Docker deja el
  # daemon en modo degradado hasta que alguien lo reinicia a mano.
  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Culkibo — orquestador cloud autohospedado
Documentation=https://github.com/macaqueboy/culkibo
After=network-online.target docker.service
Wants=network-online.target docker.service
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
Environment=NPM_CONFIG_CACHE=$INSTALL_DIR/data/.npm-cache
Environment=DOCKER_CONFIG=$INSTALL_DIR/data/.docker
ExecStart=/usr/bin/env node $INSTALL_DIR/server/index.js
Restart=always
RestartSec=5
TimeoutStopSec=30
UMask=0077

# El daemon supervisa procesos hijo y sockets: el límite por defecto de 1024
# descriptores se agota con una veintena de proyectos vigilados.
LimitNOFILE=65536

# Endurecimiento del servicio systemd
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$INSTALL_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true

# El token no aparece en el registro del sistema, así que el registro se puede
# compartir sin limpiar nada.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=culkibo

[Install]
WantedBy=multi-user.target
EOF

  chmod 0644 "$UNIT_PATH"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  ok "Unidad instalada y habilitada para arrancar en cada reinicio"

  # `restart` y no `start`: en una reinstalación el servicio ya está corriendo
  # con el código viejo.
  systemctl restart "$SERVICE_NAME"

  local waited=0
  while [ "$waited" -lt 45 ]; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
      ok "El daemon responde en http://127.0.0.1:$PORT"
      return 0
    fi
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
      printf '\n%s' "$C_DIM"; journalctl -u "$SERVICE_NAME" -n 25 --no-pager 2>/dev/null || true; printf '%s\n' "$C_RESET"
      die "El servicio se detuvo al arrancar. El registro de arriba dice por qué."
    fi
    sleep 1
    waited=$((waited + 1))
  done

  warn "El daemon no respondió en 45 s. Revisa: journalctl -u $SERVICE_NAME -n 50"
}

# -----------------------------------------------------------------------------
# 9. Plano de datos y cortafuegos
# -----------------------------------------------------------------------------

start_data_plane() {
  step "Levantando el plano de datos (Caddy)"

  if [ "$WITH_CADDY" != "1" ]; then
    info "Omitido. Culkibo no terminará TLS ni enrutará dominios hasta que haya un Caddy."
    info "Para levantarlo después: curl -X POST http://127.0.0.1:$PORT/api/ingress/start"
    return
  fi

  if ! docker info >/dev/null 2>&1; then
    warn "Sin Docker no hay plano de datos. Culkibo servirá el panel, pero no dominios con HTTPS."
    return
  fi

  if docker ps --filter "name=^culkibo-caddy$" --filter "status=running" -q | grep -q .; then
    ok "Caddy ya estaba en marcha"
  else
    docker rm -f culkibo-caddy >/dev/null 2>&1 || true
    # Se delega en la API del daemon en lugar de invocar `docker run` aquí: así
    # hay UNA sola definición de cómo se arranca el plano de datos
    # (caddyManager.startWithDocker), y el instalador no puede quedarse
    # desincronizado con el producto. En Linux se usa red de host, que es lo
    # único que permite a Caddy alcanzar los destinos en 127.0.0.1.
    local auth_hdr=""
    local tok=""
    tok="$(read_token 2>/dev/null || true)"
    if [ -n "$tok" ]; then
      auth_hdr="Authorization: Bearer $tok"
    fi
    if curl -fsS --max-time 60 -X POST \
         -H 'Content-Type: application/json' \
         ${auth_hdr:+-H "$auth_hdr"} \
         -d '{"network":"host"}' \
         "http://127.0.0.1:$PORT/api/ingress/start" >/dev/null 2>&1; then
      ok "Caddy levantado con red de host (puertos 80 y 443)"
    else
      warn "No se pudo levantar Caddy. Compruébalo con: docker logs culkibo-caddy"
    fi
  fi

  # --- Cortafuegos ---------------------------------------------------------
  if has ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 80/tcp  comment 'culkibo' >/dev/null 2>&1 || true
    ufw allow 443/tcp comment 'culkibo' >/dev/null 2>&1 || true
    ufw allow 443/udp comment 'culkibo' >/dev/null 2>&1 || true
    ok "UFW: abiertos 80/tcp, 443/tcp y 443/udp (HTTP, HTTPS y HTTP/3 QUIC)"
    if [ "$BIND_ADDR" != "0.0.0.0" ]; then
      info "El puerto $PORT NO se ha abierto a propósito: el plano de control no debe estar en internet."
    fi
  elif has ufw; then
    info "UFW está instalado pero inactivo. Si lo activas, abre 80 y 443."
  else
    info "No hay UFW. Abre 80 y 443 en el cortafuegos de tu proveedor."
  fi
}

# -----------------------------------------------------------------------------
# Token y resumen
# -----------------------------------------------------------------------------

# Lee el token que el daemon ha generado en data/auth.json.
#
# Se usa `node` y no `grep`/`sed` porque es JSON y ya hay un Node instalado; un
# parseo con expresiones regulares se rompe el día que el fichero cambie de
# forma, y aquí romperse significa no enseñar la credencial.
read_token() {
  local auth="$DATA_DIR/auth.json"
  [ -f "$auth" ] || return 1
  node -e '
    const fs = require("fs");
    try {
      const t = JSON.parse(fs.readFileSync(process.argv[1], "utf8")).token;
      if (t) process.stdout.write(t);
    } catch (e) {}
  ' "$auth" 2>/dev/null
}

print_summary() {
  local token public_ip
  token=$(read_token || true)
  public_ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "<ip-del-servidor>")

  # Toda la salida final va a la terminal directamente cuando la hay. Con
  # `curl | bash` eso ya es la terminal; el redireccionamiento explícito evita
  # que el token acabe en un fichero si alguien canaliza la salida a `tee`.
  # Sin terminal —automatización, CI— se cae a la salida estándar, que es lo
  # único que queda, y se avisa de ello.
  local out=/dev/stdout
  has_tty && out=/dev/tty

  {
    printf '\n%s%s' "$C_BOLD" "$C_GREEN"
    printf '════════════════════════════════════════════════════════════════\n'
    printf '  Culkibo %s instalado\n' "$CULKIBO_VERSION"
    printf '════════════════════════════════════════════════════════════════%s\n' "$C_RESET"

    if [ "$BIND_ADDR" = "0.0.0.0" ]; then
      printf '\n  %sPanel:%s      http://%s:%s\n' "$C_BOLD" "$C_RESET" "$public_ip" "$PORT"
    else
      printf '\n  %sPanel:%s      http://127.0.0.1:%s  (sólo desde el servidor)\n' "$C_BOLD" "$C_RESET" "$PORT"
      printf '\n  Para abrirlo desde tu portátil, haz un túnel SSH y entra en\n'
      printf '  http://localhost:%s:\n\n' "$PORT"
      printf '      %sssh -N -L %s:127.0.0.1:%s %s@%s%s\n' "$C_CYAN" "$PORT" "$PORT" "${SUDO_USER:-root}" "$public_ip" "$C_RESET"
    fi

    if [ -n "$token" ]; then
      printf '\n  %sToken de acceso%s — cópialo ahora, no vuelve a mostrarse:\n\n' "$C_BOLD" "$C_RESET"
      printf '      %s%s%s\n' "$C_CYAN" "$token" "$C_RESET"
      printf '\n  %sNo está en el registro del sistema.%s Vive en %s (0600).\n' "$C_DIM" "$C_RESET" "$DATA_DIR/auth.json"
      printf '  Para usarlo desde la API o desde un agente MCP:\n\n'
      printf '      curl -H "Authorization: Bearer <token>" http://127.0.0.1:%s/api/projects\n' "$PORT"
    else
      printf '\n  %sNo se pudo leer el token.%s Búscalo en %s\n' "$C_YELLOW" "$C_RESET" "$DATA_DIR/auth.json"
    fi

    printf '\n  %sQué hacer ahora%s\n' "$C_BOLD" "$C_RESET"
    printf '    1. Abre el panel con el túnel de arriba.\n'
    printf '    2. Ve a «Catálogo» e instala un servicio: n8n, Ghost, Uptime Kuma…\n'
    if [ "$WITH_CADDY" = "1" ]; then
      printf '    3. Apunta un dominio (registro A) a %s y añádelo al instalar.\n' "$public_ip"
      printf '       El certificado se emite solo en el primer acceso HTTPS.\n'
    else
      printf '    3. Levanta el plano de datos cuando los puertos 80 y 443 estén libres:\n'
      printf '       curl -X POST http://127.0.0.1:%s/api/ingress/start\n' "$PORT"
    fi

    printf '\n  %sComandos%s\n' "$C_BOLD" "$C_RESET"
    printf '    Estado        systemctl status %s\n' "$SERVICE_NAME"
    printf '    Registro      journalctl -u %s -f\n' "$SERVICE_NAME"
    printf '    Reiniciar     systemctl restart %s\n' "$SERVICE_NAME"
    printf '    Diagnóstico   sudo -u %s node %s/bin/culkibo.js doctor\n' "$RUN_USER" "$INSTALL_DIR"
    printf '    Desinstalar   sudo %s/scripts/uninstall.sh\n' "$INSTALL_DIR"

    if [ ${#WARNINGS[@]} -gt 0 ]; then
      printf '\n  %s%d aviso(s) durante la instalación:%s\n' "$C_YELLOW" "${#WARNINGS[@]}" "$C_RESET"
      for w in "${WARNINGS[@]}"; do printf '    · %s\n' "$w"; done
    fi
    printf '\n'
  } > "$out"
}

# -----------------------------------------------------------------------------
# Principal
# -----------------------------------------------------------------------------

main() {
  printf '\n%s%s  Culkibo %s — instalador para Debian y Ubuntu%s\n' "$C_BOLD" "$C_CYAN" "$CULKIBO_VERSION" "$C_RESET"
  printf '%s  Orquestador cloud autohospedado, Apache-2.0%s\n' "$C_DIM" "$C_RESET"

  [ "$ACTION" = "uninstall" ] && do_uninstall

  preflight
  install_base_packages
  install_node
  install_docker
  create_service_user
  fetch_source
  build_app
  install_systemd_unit
  start_data_plane
  print_summary
}

main "$@"
