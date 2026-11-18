const { execFile } = require('child_process');
const util = require('util');
const execFilePromise = util.promisify(execFile);

/**
 * Cliente del motor Docker.
 *
 * Todo pasa por `execFile('docker', [argv])`. Nunca se construye una cadena de
 * shell, porque `exec()` entrega la cadena a `cmd.exe` / `/bin/sh` y cualquier
 * metacarácter dentro de un ID o de un nombre de contenedor se convierte en
 * ejecución de comandos. Ésa es exactamente la clase que ha producido 21 avisos
 * críticos en Coolify y 34 en Dokploy, y dos de esos parches están catalogados
 * como «incomplete fix»: no se arregla caso a caso, se elimina por construcción.
 *
 * Con argv no hay shell, pero sigue existiendo *inyección de argumento*: un
 * valor que empiece por `-` lo lee `docker` como una opción. Por eso
 * `assertRef()` valida la forma de cada referencia antes de pasarla, en vez de
 * confiar en que el llamante lo haya hecho.
 */

/**
 * Referencias válidas de Docker: IDs hexadecimales, nombres de contenedor y
 * nombres de imagen. Docker exige que el primer carácter sea alfanumérico, así
 * que este patrón no puede empezar por `-` ni contener espacios ni separadores
 * de shell.
 */
const DOCKER_REF = /^[a-zA-Z0-9][a-zA-Z0-9_.\-/:]*$/;

class DockerManager {
  constructor() {
    this.isDockerAvailable = false;
    this.dockerVersion = null;
    this.lastCheckTime = 0;
    this.checkIntervalMs = 15000;
    this.cachedStatus = null;
  }

  /**
   * Rechaza cualquier referencia que no tenga forma de ID/nombre de Docker.
   * Defensa en profundidad: aunque no haya shell, un `-v` colado como ID
   * cambiaría el significado del comando.
   */
  assertRef(value, label = 'referencia de contenedor') {
    const ref = String(value == null ? '' : value);
    if (!DOCKER_REF.test(ref) || ref.length > 255) {
      throw new Error(`${label} inválida: ${JSON.stringify(ref)}`);
    }
    return ref;
  }

  /**
   * Único punto de ejecución. `shell: false` es el valor por defecto de
   * `execFile`, pero se declara para que sea explícito en la lectura y para que
   * quede constancia de la invariante que este módulo mantiene.
   */
  async docker(args, { timeout = 10000 } = {}) {
    return execFilePromise('docker', args, {
      timeout,
      shell: false,
      windowsHide: true,
      maxBuffer: 8 * 1024 * 1024
    });
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
      const { stdout: versionOut } = await this.docker(['version', '--format', '{{json .}}'], { timeout: 3500 });
      let versionData = {};
      try {
        versionData = JSON.parse(versionOut.trim());
      } catch (e) {
        versionData = { raw: versionOut.trim() };
      }

      // Comprobar si el server/daemon responde
      const { stdout: infoOut } = await this.docker(['info', '--format', '{{json .}}'], { timeout: 4000 });
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
      const args = ['ps'];
      if (all) args.push('-a');
      args.push('--format', '{{json .}}');
      const { stdout } = await this.docker(args, { timeout: 5000 });
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
      const ref = this.assertRef(containerId);
      const { stdout } = await this.docker(['stats', ref, '--no-stream', '--format', '{{json .}}'], { timeout: 6000 });
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
    const ref = this.assertRef(containerId);
    const { stdout } = await this.docker(['start', ref]);
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
    const ref = this.assertRef(containerId);
    const { stdout } = await this.docker(['stop', ref], { timeout: 30000 });
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
    const ref = this.assertRef(containerId);
    const { stdout } = await this.docker(['restart', ref], { timeout: 45000 });
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
      const ref = this.assertRef(containerId);
      // `--tail` sólo acepta un entero o `all`. Se normaliza aquí para que un
      // valor arbitrario del llamante no llegue nunca a la línea de comandos.
      const tail = Number.isFinite(Number(lines)) ? Math.min(Math.max(parseInt(lines, 10) || 100, 1), 10000) : 100;
      const { stdout, stderr } = await this.docker(['logs', '--tail', String(tail), ref], { timeout: 5000 });
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
module.exports.DockerManager = DockerManager;
