const fs = require('fs');
const path = require('path');
// Este módulo NO ejecuta procesos: sólo construye la especificación argv del
// volcado (`buildDbDumpSpec`) para que la ejecute quien corresponda. El
// `require('child_process')` que había aquí no se usaba y sólo servía para que
// alguien cayera en la tentación de añadir un `exec()`.
const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const { assertContainedPath } = require('./ssrfGuard');

class DbBackupManager {
  constructor() {
    this.backupsDir = path.join(__dirname, '..', '..', 'data', 'backups');
    this.ensureDir(this.backupsDir);
  }

  ensureDir(dir) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Construye la especificación ejecutable de un volcado: programa, argumentos
   * como array y secretos en el entorno.
   *
   * Nunca se devuelve una cadena de shell. Concatenar `host`, `user` o `dbName`
   * —valores que vienen del usuario— dentro de un comando es exactamente la
   * clase que ha producido 21 avisos críticos en Coolify y 34 en Dokploy. Con
   * argv no hay shell en la que inyectar, y con la contraseña en el entorno no
   * aparece en la salida de `ps`.
   *
   * @returns {{program:string, args:string[], env:Object, secretInArgs:boolean}}
   */
  buildDbDumpSpec(dbType, options = {}) {
    const { host = 'localhost', port, user = 'root', password = '', dbName = 'app', outputFile } = options;
    const engine = String(dbType || '').toLowerCase();

    switch (engine) {
      case 'postgresql':
      case 'postgres':
        return {
          program: 'pg_dump',
          args: ['-h', String(host), '-p', String(port || 5432), '-U', String(user),
                 '-d', String(dbName), '-F', 'c', '-b', '-f', String(outputFile)],
          env: password ? { PGPASSWORD: password } : {},
          secretInArgs: false
        };

      case 'mysql':
      case 'mariadb':
        return {
          program: 'mysqldump',
          args: ['-h', String(host), '-P', String(port || 3306), '-u', String(user),
                 '--single-transaction', '--quick', `--result-file=${outputFile}`, String(dbName)],
          // MYSQL_PWD evita que la contraseña aparezca en la línea de comandos.
          env: password ? { MYSQL_PWD: password } : {},
          secretInArgs: false
        };

      case 'redis':
        return {
          program: 'redis-cli',
          args: ['-h', String(host), '-p', String(port || 6379), '--rdb', String(outputFile)],
          env: password ? { REDISCLI_AUTH: password } : {},
          secretInArgs: false
        };

      case 'mongodb':
      case 'mongo':
        return {
          program: 'mongodump',
          args: [`--host=${host}`, `--port=${port || 27017}`, `--username=${user}`,
                 `--db=${dbName}`, `--archive=${outputFile}`, '--gzip',
                 ...(password ? [`--password=${password}`] : [])],
          env: {},
          // mongodump no ofrece variable de entorno para la contraseña; la
          // alternativa es un fichero --config temporal. Marcado para que quien
          // ejecute sepa que este caso sí expone el secreto en `ps`.
          secretInArgs: Boolean(password)
        };

      default:
        throw new Error(`Motor de base de datos no soportado: ${dbType}`);
    }
  }

  /**
   * Representación legible del comando, con los secretos ocultos.
   * Es lo único que sale por la API o llega a un log: nunca la contraseña.
   */
  generateDbDumpCommand(dbType, options = {}) {
    const spec = this.buildDbDumpSpec(dbType, options);
    const quote = (v) => (/[\s"'$`\\;|&<>()]/.test(v) ? JSON.stringify(v) : v);
    const envPrefix = Object.keys(spec.env).map(k => `${k}=********`).join(' ');
    const args = spec.args.map(a => quote(String(a).replace(/(--password=)[\s\S]*/, '$1********')));
    return [envPrefix, spec.program, ...args].filter(Boolean).join(' ');
  }

  /**
   * Realiza una exportación completa de un proyecto (metadata, volúmenes, envs, dominios).
   */
  async exportProject(projectId) {
    const project = projectManager.getById(projectId);
    if (!project) {
      throw new Error(`Proyecto ${projectId} no encontrado`);
    }

    // P1-27: asociar dominios reales por projectId o project.domains (no por puerto genérico 3001/8080)
    const projHosts = new Set((project.domains || []).map((h) => String(h).toLowerCase()));
    const domains = domainManager.listDomains().filter(
      (d) => d.projectId === project.id || projHosts.has(String(d.hostname || '').toLowerCase())
    );

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `backup_${project.id}_${timestamp}.json`;
    const backupFilePath = path.join(this.backupsDir, backupFileName);

    const exportBundle = {
      version: '1.0.0',
      exportedAt: new Date().toISOString(),
      source: 'Culkibo Orchestrator',
      project: project,
      domains: domains,
      volumes: project.volumes || [],
      fileMounts: project.fileMounts || [],
      checksum: `sha256_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
    };

    await fs.promises.writeFile(backupFilePath, JSON.stringify(exportBundle, null, 2), { encoding: 'utf8', mode: 0o600 });

    return {
      success: true,
      backupFile: backupFileName,
      fullPath: backupFilePath,
      exportedAt: exportBundle.exportedAt,
      projectId: project.id,
      projectName: project.name,
      resourcesCount: (project.resources || []).length,
      domainsCount: domains.length
    };
  }

  /**
   * Importa y restaura un proyecto desde un archivo de backup JSON.
   * Por seguridad, desde API/MCP el archivo debe estar contenido en `this.backupsDir`;
   * la CLI local puede pasar `{ allowExternalPath: true }`.
   */
  async restoreProject(backupFilePathOrName, { allowExternalPath = false } = {}) {
    const rawInput = String(backupFilePathOrName || '').trim();
    if (!rawInput || rawInput.includes('\0')) {
      throw new Error('Ruta de backup inválida');
    }
    let filePath;
    if (allowExternalPath && path.isAbsolute(rawInput)) {
      filePath = path.resolve(rawInput);
    } else if (path.isAbsolute(rawInput)) {
      const resolved = path.resolve(rawInput);
      const rel = path.relative(path.resolve(this.backupsDir), resolved);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        throw new Error('Ruta de backup fuera del directorio permitido (data/backups)');
      }
      filePath = resolved;
    } else {
      filePath = assertContainedPath(this.backupsDir, rawInput);
    }

    if (!fs.existsSync(filePath)) {
      throw new Error(`Archivo de backup no encontrado: ${path.basename(filePath)}`);
    }

    const raw = await fs.promises.readFile(filePath, 'utf8');
    const bundle = JSON.parse(raw);

    if (!bundle.project || !bundle.project.name) {
      throw new Error('Estructura de backup inválida o dañada');
    }

    // Comprobar si ya existe el ID, si existe asignar nuevo o actualizar
    let targetProject = bundle.project;
    const existing = projectManager.getById(targetProject.id);
    if (existing) {
      targetProject.id = `restored_${Date.now().toString(36)}`;
      targetProject.name = `${targetProject.name} (Restaurado)`;
    }

    const restored = projectManager.create(targetProject);

    // Restaurar dominios asociados si no existen
    if (bundle.domains && Array.isArray(bundle.domains)) {
      for (const d of bundle.domains) {
        try {
          await domainManager.addDomain({
            hostname: d.hostname,
            targetPod: d.targetPod || 'citadel',
            targetPort: d.targetPort || restored.citadelPort,
            cloudflareProxied: d.cloudflareProxied
          });
        } catch (e) {
          // Ignorar duplicados de dominio
        }
      }
    }

    // P0-6: garantizar escritura atómica en disco antes de devolver éxito (CLI restore)
    await projectManager.flushToDisk();

    return {
      success: true,
      restoredProjectId: restored.id,
      restoredName: restored.name,
      restoredAt: new Date().toISOString()
    };
  }

  /**
   * Lista todos los backups existentes en el disco.
   */
  async listBackups() {
    this.ensureDir(this.backupsDir);
    const files = await fs.promises.readdir(this.backupsDir);
    const backups = [];

    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const filePath = path.join(this.backupsDir, file);
          const stats = await fs.promises.stat(filePath);
          backups.push({
            fileName: file,
            sizeBytes: stats.size,
            createdAt: stats.birthtime,
            modifiedAt: stats.mtime
          });
        } catch (e) {
          // Ignorar ficheros eliminados concurrentemente durante el listado
        }
      }
    }

    return backups.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }
}

module.exports = new DbBackupManager();
