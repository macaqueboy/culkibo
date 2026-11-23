const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// Este módulo NO ejecuta procesos: sólo construye la especificación argv del
// volcado (`buildDbDumpSpec`) para que la ejecute quien corresponda.
const projectManager = require('./projectManager');
const domainManager = require('./domainManager');
const { assertContainedPath, atomicWriteJsonSync } = require('./ssrfGuard');

/** Rechaza valores con guion inicial para impedir inyección de flags en CLI (p. ej. `-o`, `--eval`). */
function assertSafeCliArg(value, field) {
  const s = String(value == null ? '' : value);
  if (s.startsWith('-')) {
    throw new Error(`${field} inválido: no puede empezar por guion (-)`);
  }
  if (/[\0\r\n]/.test(s)) {
    throw new Error(`${field} inválido: contiene caracteres de control`);
  }
  return s;
}

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
    const safeHost = assertSafeCliArg(host, 'host');
    const safeUser = assertSafeCliArg(user, 'user');
    const safeDb = assertSafeCliArg(dbName, 'dbName');
    const safeOut = assertSafeCliArg(outputFile || '', 'outputFile');

    switch (engine) {
      case 'postgresql':
      case 'postgres':
        return {
          program: 'pg_dump',
          args: ['-h', safeHost, '-p', String(port || 5432), '-U', safeUser,
                 '-d', safeDb, '-F', 'c', '-b', '-f', safeOut],
          env: password ? { PGPASSWORD: password } : {},
          secretInArgs: false
        };

      case 'mysql':
      case 'mariadb':
        return {
          program: 'mysqldump',
          args: ['-h', safeHost, '-P', String(port || 3306), '-u', safeUser,
                 '--single-transaction', '--quick', `--result-file=${safeOut}`, safeDb],
          // MYSQL_PWD evita que la contraseña aparezca en la línea de comandos.
          env: password ? { MYSQL_PWD: password } : {},
          secretInArgs: false
        };

      case 'redis':
      case 'valkey':
        return {
          program: engine === 'valkey' ? 'valkey-cli' : 'redis-cli',
          args: ['-h', safeHost, '-p', String(port || 6379), '--rdb', safeOut],
          env: password ? { REDISCLI_AUTH: password, ...(engine === 'valkey' ? { VALKEYCLI_AUTH: password } : {}) } : {},
          secretInArgs: false
        };

      case 'mongodb':
      case 'mongo':
        return {
          program: 'mongodump',
          args: [`--host=${safeHost}`, `--port=${port || 27017}`, `--username=${safeUser}`,
                 `--db=${safeDb}`, `--archive=${safeOut}`, '--gzip',
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

    const bundleBody = {
      version: '1.0.0',
      exportedAt: new Date().toISOString(),
      source: 'Culkibo Orchestrator',
      project: project,
      domains: domains,
      volumes: project.volumes || [],
      fileMounts: project.fileMounts || []
    };
    const sha256 = crypto.createHash('sha256').update(JSON.stringify(bundleBody)).digest('hex');
    const exportBundle = { ...bundleBody, checksum: `sha256:${sha256}` };

    atomicWriteJsonSync(backupFilePath, exportBundle, 0o600);

    return {
      success: true,
      backupFile: backupFileName,
      fullPath: backupFilePath,
      exportedAt: exportBundle.exportedAt,
      checksum: exportBundle.checksum,
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

    // Impedir escapes por symlink fuera de data/backups cuando no se permite ruta externa
    if (!allowExternalPath) {
      const realRoot = fs.realpathSync(this.backupsDir);
      const realFile = fs.realpathSync(filePath);
      const relReal = path.relative(realRoot, realFile);
      if (relReal.startsWith('..') || path.isAbsolute(relReal)) {
        throw new Error('Ruta de backup fuera del directorio permitido (symlink bloqueado)');
      }
    }

    const raw = await fs.promises.readFile(filePath, 'utf8');
    const bundle = JSON.parse(raw);

    if (!bundle.project || !bundle.project.name) {
      throw new Error('Estructura de backup inválida o dañada');
    }

    // Verificar checksum real sha256 si el backup lo trae en el nuevo formato `sha256:<hex>`
    if (typeof bundle.checksum === 'string' && /^sha256:[a-f0-9]{64}$/.test(bundle.checksum)) {
      const { checksum, ...bodyWithoutChecksum } = bundle;
      const expected = `sha256:${crypto.createHash('sha256').update(JSON.stringify(bodyWithoutChecksum)).digest('hex')}`;
      if (checksum !== expected) {
        throw new Error('El checksum SHA-256 del archivo de backup no coincide (archivo modificado o corrupto)');
      }
    }

    // Comprobar si ya existe el ID, si existe asignar nuevo o actualizar
    let targetProject = { ...bundle.project };
    const existing = projectManager.getById(targetProject.id);
    if (existing) {
      targetProject.id = `restored_${Date.now().toString(36)}`;
      targetProject.name = `${targetProject.name} (Restaurado)`;
    }

    const restored = projectManager.create(targetProject);

    // Restaurar dominios asociados vinculados explícitamente a `restored.id`
    if (bundle.domains && Array.isArray(bundle.domains)) {
      for (const d of bundle.domains) {
        try {
          await domainManager.addDomain({
            hostname: d.hostname,
            projectId: restored.id,
            targetPod: d.targetPod || 'citadel',
            targetPort: d.targetPort || restored.citadelPort,
            cloudflareProxied: d.cloudflareProxied,
            canonicalRedirect: d.canonicalRedirect || 'none'
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
