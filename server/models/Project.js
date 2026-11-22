const crypto = require('crypto');

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;

class Project {
  constructor(data) {
    // `proj_${Date.now()}` collides when several projects are created inside the
    // same millisecond (bulk Coolify import), silently overwriting each other in
    // the Map. Suffix with entropy while keeping the id filesystem/URL safe.
    if (data.id !== undefined && data.id !== null && data.id !== '') {
      const rawId = String(data.id);
      if (!PROJECT_ID_RE.test(rawId)) {
        throw new Error(`Invalid project ID: ${rawId.slice(0, 40)}`);
      }
      this.id = rawId;
    } else {
      this.id = `proj_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    }
    this.name = data.name || 'Nuevo Proyecto';
    this.description = data.description || '';
    this.icon = data.icon || '🚀';
    this.status = data.status || 'active'; // active | hibernated | stopped
    this.forgePort = data.forgePort || 3001;
    this.citadelPort = data.citadelPort || 8080;
    this.trafficSplit = data.trafficSplit || { forge: 0, citadel: 100 };
    this.domains = data.domains || [];
    this.envVars = data.envVars || {};
    this.gitRepo = data.gitRepo || '';
    this.createdAt = data.createdAt || new Date().toISOString();
    this.updatedAt = data.updatedAt || new Date().toISOString();
    this.source = data.source || 'manual'; // manual | coolify-import | github
    this.resources = data.resources || [];
    this.gitBranch = data.gitBranch || 'main';
    this.buildCommand = data.buildCommand || '';
    this.startCommand = data.startCommand || '';
    this.baseDirectory = data.baseDirectory || '/';
    this.watchPaths = data.watchPaths || [];
    this.volumes = data.volumes || [];
    this.fileMounts = data.fileMounts || [];
    this.webhookSecret = data.webhookSecret || crypto.randomBytes(16).toString('hex');
    this.autoDeploy = data.autoDeploy !== undefined ? data.autoDeploy : true;
    this.lastDeployedAt = data.lastDeployedAt || null;
    this.lastCommit = data.lastCommit || null;
    this.githubOwner = data.githubOwner || '';
    this.githubRepo = data.githubRepo || '';
    this.localRunning = data.localRunning !== undefined ? data.localRunning : false;
    this.localPort = data.localPort || null;
    // Ajustes del despliegue a producción (deployManager). Sin estos campos en
    // el modelo, cualquier valor que el usuario configurase se perdía en el
    // siguiente `update()`, porque el constructor reconstruye el objeto entero.
    // Todos se vuelven a validar en deployManager antes de tocar un argv.
    this.containerPort = data.containerPort || null;
    this.healthPath = data.healthPath || '/';
    this.memoryMb = data.memoryMb || null;
    this.cpus = data.cpus || null;
    this.buildArgs = data.buildArgs || {};
  }
}

module.exports = Project;
