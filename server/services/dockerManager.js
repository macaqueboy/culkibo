const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class DockerManager {
  constructor() {
    this.isDockerAvailable = false;
    this.dockerVersion = null;
    this.lastCheckTime = 0;
    this.checkIntervalMs = 15000;
    this.cachedStatus = null;
  }

  /**
   * Comprueba si el daemon de Docker está disponible y accesible.
   * Si no está disponible, no bloquea ni falla: activa modo proceso ligero.
   */
  async checkDockerStatus(forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh && this.cachedStatus && (now - this.lastCheckTime < this.checkIntervalMs)) {
      return this.cachedStatus;
    }

    try {
      // Intento rápido de consultar docker version
      const { stdout: versionOut } = await execPromise('docker version --format "{{json .}}"', { timeout: 3500 });
      let versionData = {};
      try {
        versionData = JSON.parse(versionOut.trim());
      } catch (e) {
        versionData = { raw: versionOut.trim() };
      }

      // Comprobar si el server/daemon responde
      const { stdout: infoOut } = await execPromise('docker info --format "{{json .}}"', { timeout: 4000 });
      let infoData = {};
      try {
        infoData = JSON.parse(infoOut.trim());
      } catch (e) {
        infoData = { raw: infoOut.trim() };
      }

      this.isDockerAvailable = true;
      this.dockerVersion = versionData.Client?.Version || 'Activo';
      this.cachedStatus = {
        available: true,
        serverRunning: true,
        mode: 'docker_native',
        clientVersion: versionData.Client?.Version || 'Desconocido',
        serverVersion: versionData.Server?.Version || 'Activo',
        os: infoData.OperatingSystem || process.platform,
        containersRunning: infoData.ContainersRunning || 0,
        containersTotal: infoData.Containers || 0,
        imagesCount: infoData.Images || 0,
        memoryLimit: infoData.MemTotal ? Math.round(infoData.MemTotal / 1024 / 1024) + ' MB' : 'Ilimitado',
        message: 'Motor Docker nativo conectado y operativo'
      };
    } catch (err) {
      this.isDockerAvailable = false;
      this.cachedStatus = {
        available: false,
        serverRunning: false,
        mode: 'sandbox_simulation',
        clientVersion: this.dockerVersion || 'No detectado',
        serverVersion: null,
        error: err.message,
        message: 'Daemon de Docker no detectado en este host. Operando en modo sandbox de procesos.'
      };
    }

    this.lastCheckTime = now;
    return this.cachedStatus;
  }

  /**
   * Lista contenedores activos o todos los contenedores.
   */
  async listContainers({ all = true, projectId = null } = {}) {
    const status = await this.checkDockerStatus();

    if (!status.available) {
      // Retornar contenedores simulados según el proyecto o entorno
      return [
        {
          id: 'culkibo-forge-dev',
          names: ['/culkibo_dev_forge'],
          image: 'node:22-alpine',
          status: 'Up (Hot-Reloading activo)',
          state: 'running',
          ports: '0.0.0.0:3001->3001/tcp',
          mode: 'sandbox',
          created: new Date().toISOString()
        },
        {
          id: 'culkibo-citadel-prod',
          names: ['/culkibo_prod_citadel'],
          image: 'culkibo/citadel:v1.0.0',
          status: 'Up (Inmutable)',
          state: 'running',
          ports: '0.0.0.0:8080->8080/tcp',
          mode: 'sandbox',
          created: new Date().toISOString()
        }
      ];
    }

    try {
      const allFlag = all ? '-a' : '';
      const { stdout } = await execPromise(`docker ps ${allFlag} --format "{{json .}}"`, { timeout: 5000 });
      const lines = stdout.trim().split('\n').filter(Boolean);
      return lines.map(line => {
        try {
          const item = JSON.parse(line);
          return {
            id: item.ID,
            names: item.Names ? [item.Names] : [],
            image: item.Image,
            command: item.Command,
            created: item.CreatedAt,
            status: item.Status,
            state: item.State,
            ports: item.Ports,
            mode: 'docker_native'
          };
        } catch (e) {
          return { raw: line };
        }
      });
    } catch (err) {
      return [{ error: err.message, mode: 'fallback' }];
    }
  }

  /**
   * Obtiene métricas en vivo de un contenedor específico.
   */
  async getContainerStats(containerId) {
    const status = await this.checkDockerStatus();
    if (!status.available) {
      return {
        id: containerId,
        cpuPercent: '1.2%',
        memoryUsage: '142MiB / 2GiB',
        memoryPercent: '6.9%',
        netIO: '12.4kB / 8.2kB',
        mode: 'sandbox_simulation'
      };
    }

    try {
      const { stdout } = await execPromise(`docker stats ${containerId} --no-stream --format "{{json .}}"`, { timeout: 6000 });
      return JSON.parse(stdout.trim());
    } catch (err) {
      return { id: containerId, error: err.message };
    }
  }

  /**
   * Inicia un contenedor.
   */
  async startContainer(containerId) {
    const status = await this.checkDockerStatus();
    if (!status.available) {
      return { success: true, message: `Contenedor ${containerId} iniciado en sandbox.`, mode: 'sandbox' };
    }
    const { stdout } = await execPromise(`docker start ${containerId}`);
    return { success: true, stdout: stdout.trim(), mode: 'docker_native' };
  }

  /**
   * Detiene un contenedor.
   */
  async stopContainer(containerId) {
    const status = await this.checkDockerStatus();
    if (!status.available) {
      return { success: true, message: `Contenedor ${containerId} detenido en sandbox.`, mode: 'sandbox' };
    }
    const { stdout } = await execPromise(`docker stop ${containerId}`);
    return { success: true, stdout: stdout.trim(), mode: 'docker_native' };
  }

  /**
   * Reinicia un contenedor.
   */
  async restartContainer(containerId) {
    const status = await this.checkDockerStatus();
    if (!status.available) {
      return { success: true, message: `Contenedor ${containerId} reiniciado en sandbox.`, mode: 'sandbox' };
    }
    const { stdout } = await execPromise(`docker restart ${containerId}`);
    return { success: true, stdout: stdout.trim(), mode: 'docker_native' };
  }

  /**
   * Lee logs del contenedor.
   */
  async getLogs(containerId, lines = 100) {
    const status = await this.checkDockerStatus();
    if (!status.available) {
      return {
        containerId,
        lines: [
          `[Sandbox] Contenedor ${containerId} operando en modo simulación de alta velocidad.`,
          `[Sandbox] Tráfico HTTP enrutado a través del proxy Ingress interno.`,
          `[Sandbox] Estado: Saludable.`
        ]
      };
    }
    try {
      const { stdout, stderr } = await execPromise(`docker logs --tail ${lines} ${containerId}`, { timeout: 5000 });
      return {
        containerId,
        output: stdout || stderr
      };
    } catch (err) {
      return { containerId, error: err.message };
    }
  }
}

module.exports = new DockerManager();
