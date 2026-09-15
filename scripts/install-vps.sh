#!/usr/bin/env bash
# ==============================================================================
# Culkibo v1.0.0 — Script de Instalación Automatizada para Servidores Linux VPS
# Compatible con Ubuntu 20.04/22.04/24.04 y Debian 11/12
# ==============================================================================

set -e

COLOR_CYAN='\033[0;36m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${COLOR_CYAN}================================================================${NC}"
echo -e "${COLOR_CYAN}🚀 Instalador de Culkibo Orchestrator v1.0.0 para Servidores VPS${NC}"
echo -e "${COLOR_CYAN}================================================================${NC}\n"

# 1. Comprobar permisos de root
if [ "$EUID" -ne 0 ]; then
  echo -e "${COLOR_RED}❌ Error: Por favor, ejecuta este instalador como root (sudo).${NC}"
  exit 1
fi

INSTALL_DIR="/opt/culkibo"
PORT=3030

echo -e "${COLOR_YELLOW}[1/6] Actualizando paquetes del sistema y dependencias base...${NC}"
apt-get update -y
apt-get install -y curl git ufw jq openssl ca-certificates gnupg

# 2. Instalar Node.js 22 LTS si no está presente o versión antigua
echo -e "${COLOR_YELLOW}[2/6] Verificando instalación de Node.js...${NC}"
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d'.' -f1 | tr -d 'v')" -lt 20 ]; then
  echo -e "Instalando Node.js v22 LTS..."
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg --yes
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
  apt-get update -y
  apt-get install -y nodejs
fi
echo -e "${COLOR_GREEN}✓ Node.js detectado: $(node -v)${NC}"

# 3. Comprobar Docker
echo -e "${COLOR_YELLOW}[3/6] Verificando motor Docker...${NC}"
if ! command -v docker >/dev/null 2>&1; then
  echo "Instalando Docker Engine..."
  apt-get install -y docker.io docker-compose
  systemctl enable --now docker
fi
echo -e "${COLOR_GREEN}✓ Docker listo: $(docker --version)${NC}"

# 4. Clonar o actualizar Culkibo en /opt/culkibo
echo -e "${COLOR_YELLOW}[4/6] Preparando Culkibo en ${INSTALL_DIR}...${NC}"
if [ -d "$INSTALL_DIR" ]; then
  echo "Directorio existente, actualizando..."
  cd "$INSTALL_DIR"
  if [ -d ".git" ]; then
    git pull origin main || true
  fi
else
  mkdir -p "$INSTALL_DIR"
  # Si se ejecuta desde el repositorio local clonado, copiamos archivos
  if [ -f "./server/index.js" ]; then
    cp -r ./* "$INSTALL_DIR/"
  else
    echo "Descargando Culkibo desde GitHub..."
    git clone https://github.com/pablo-developer/culkibo.git "$INSTALL_DIR" || true
  fi
fi

cd "$INSTALL_DIR"
mkdir -p data data/certs data/backups projects

# 5. Instalar dependencias npm y compilar frontend
echo -e "${COLOR_YELLOW}[5/6] Instalando dependencias de Node.js y compilando frontend...${NC}"
npm install --production=false
if [ -d "web" ]; then
  npm --prefix web install
  npm --prefix web run build
fi

# 6. Configurar servicio Systemd
echo -e "${COLOR_YELLOW}[6/6] Creando servicio systemd para ejecución 24/7...${NC}"
cat << EOF > /etc/systemd/system/culkibo.service
[Unit]
Description=Culkibo Cloud Orchestrator Daemon
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/node ${INSTALL_DIR}/bin/culkibo.js start --port ${PORT}
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=${PORT}

# Límites de recursos recomendados
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable culkibo
systemctl restart culkibo

# Abrir puertos en cortafuegos si UFW está activo
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "Habilitando puerto ${PORT} en UFW..."
  ufw allow ${PORT}/tcp comment 'Culkibo Dashboard & API'
  ufw allow 80/tcp comment 'Culkibo HTTP Ingress'
  ufw allow 443/tcp comment 'Culkibo HTTPS Ingress'
fi

# Obtener IP pública del servidor
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || hostname -I | awk '{print $1}')

echo -e "\n${COLOR_GREEN}================================================================${NC}"
echo -e "${COLOR_GREEN}🎉 ¡Instalación de Culkibo completada con éxito!${NC}"
echo -e "${COLOR_GREEN}================================================================${NC}"
echo -e "Panel de Control Web:  ${COLOR_CYAN}http://${PUBLIC_IP}:${PORT}${NC}"
echo -e "Comprobar Estado:      ${COLOR_CYAN}systemctl status culkibo${NC}"
echo -e "Ver Logs en Vivo:      ${COLOR_CYAN}journalctl -u culkibo -f${NC}"
echo -e "CLI de Administración: ${COLOR_CYAN}node ${INSTALL_DIR}/bin/culkibo.js doctor${NC}"
echo -e "================================================================\n"
