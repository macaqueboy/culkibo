import React, { useState, useMemo } from 'react';
import { Download, Link as LinkIcon, Server, Database, CheckCircle, AlertCircle, Box, ChevronDown, ChevronRight, FolderKanban, Check, Minus, Globe, Loader2, Cloud } from 'lucide-react';
import { api, type DomainItem } from '../lib/api';

interface CoolifyProject {
  uuid: string;
  id?: number;
  name: string;
  description?: string;
}

interface CoolifyResource {
  uuid: string;
  name: string;
  fqdn?: string;
  database_type?: string;
  status?: string;
  environment?: { project?: { uuid?: string; name?: string; id?: number } };
  project_id?: number;
  local_persistent_volumes?: any[];
  persistent_volumes?: any[];
  volumes?: any[];
  local_file_volumes?: any[];
  file_volumes?: any[];
  environment_variables?: any[];
  _resourceType: 'app' | 'database' | 'service';
}

interface ProjectGroup {
  project: CoolifyProject;
  resources: CoolifyResource[];
}

export const CoolifyImport: React.FC<{ onComplete: () => void, onCancel: () => void, onNotify: (msg: string) => void }> = ({ onComplete, onCancel, onNotify }) => {
  const [step, setStep] = useState(1);
  const [apiUrl, setApiUrl] = useState('https://coolify.example.com');
  const [apiToken, setApiToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [allResources, setAllResources] = useState<CoolifyResource[]>([]);
  const [projects, setProjects] = useState<CoolifyProject[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [results, setResults] = useState<any>(null);

  const [importedDomains, setImportedDomains] = useState<DomainItem[]>([]);
  const [serverIp, setServerIp] = useState('');
  const [hasCloudflare, setHasCloudflare] = useState(false);
  const [migratingDomains, setMigratingDomains] = useState<Set<string>>(new Set());

  const handleConnect = async () => {
    setLoading(true);
    try {
      const res = await api.previewCoolify(apiUrl, apiToken);
      const apps: CoolifyResource[] = (res.apps || []).map((a: any) => ({ ...a, _resourceType: 'app' as const }));
      const dbs: CoolifyResource[] = (res.databases || []).map((d: any) => ({ ...d, _resourceType: 'database' as const }));
      const svcs: CoolifyResource[] = (res.services || []).map((s: any) => ({ ...s, _resourceType: 'service' as const }));
      const all = [...apps, ...dbs, ...svcs];
      setAllResources(all);
      setProjects(res.projects || []);
      setSelected(new Set(all.map(r => r.uuid)));
      setStep(2);
    } catch (e: any) {
      onNotify(e.message || 'Error al conectar');
    }
    setLoading(false);
  };

  const projectGroups: ProjectGroup[] = useMemo(() => {
    const groups = new Map<string, ProjectGroup>();
    const fallbackProject: CoolifyProject = { uuid: '_unassigned', name: 'Sin Proyecto Asignado', description: 'Recursos sin proyecto en Coolify' };

    for (const resource of allResources) {
      let projectKey = '_unassigned';
      let project: CoolifyProject = fallbackProject;

      if (resource.environment?.project?.uuid) {
        projectKey = resource.environment.project.uuid;
        const match = projects.find(p => p.uuid === projectKey);
        project = match || { uuid: projectKey, name: resource.environment.project.name || 'Proyecto Coolify', description: '' };
      } else if (resource.project_id && projects.length) {
        const match = projects.find(p => p.id === resource.project_id || p.uuid === String(resource.project_id));
        if (match) {
          projectKey = match.uuid || String(match.id);
          project = match;
        }
      }

      if (!groups.has(projectKey)) {
        groups.set(projectKey, { project, resources: [] });
      }
      groups.get(projectKey)!.resources.push(resource);
    }

    return Array.from(groups.values()).sort((a, b) => {
      if (a.project.uuid === '_unassigned') return 1;
      if (b.project.uuid === '_unassigned') return -1;
      return a.project.name.localeCompare(b.project.name);
    });
  }, [allResources, projects]);

  const toggleResource = (uuid: string) => setSelected(prev => { const next = new Set(prev); if (next.has(uuid)) next.delete(uuid); else next.add(uuid); return next; });
  const toggleProject = (group: ProjectGroup) => {
    const uuids = group.resources.map(r => r.uuid);
    const allSelected = uuids.every(id => selected.has(id));
    setSelected(prev => {
      const next = new Set(prev);
      if (allSelected) uuids.forEach(id => next.delete(id));
      else uuids.forEach(id => next.add(id));
      return next;
    });
  };
  const toggleCollapse = (key: string) => setCollapsed(prev => { const next = new Set(prev); if (next.has(key)) next.delete(key); else next.add(key); return next; });
  const selectAll = () => setSelected(new Set(allResources.map(r => r.uuid)));
  const deselectAll = () => setSelected(new Set());

  const selectedApps = allResources.filter(r => r._resourceType === 'app' && selected.has(r.uuid)).map(r => r.uuid);
  const selectedDbs = allResources.filter(r => r._resourceType === 'database' && selected.has(r.uuid)).map(r => r.uuid);
  const selectedServices = allResources.filter(r => r._resourceType === 'service' && selected.has(r.uuid)).map(r => r.uuid);
  const totalApps = allResources.filter(r => r._resourceType === 'app').length;
  const totalDbs = allResources.filter(r => r._resourceType === 'database').length;
  const totalSvcs = allResources.filter(r => r._resourceType === 'service').length;

  const handleImport = async () => {
    setLoading(true);
    try {
      const res = await api.importCoolify(apiUrl, apiToken, selectedApps, selectedDbs, selectedServices);
      setResults(res);
      
      const domainsRes = await api.getDomains();
      const coolifyDomains = domainsRes.domains.filter(d => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify');
      setImportedDomains(coolifyDomains);
      
      const ipRes = await api.getServerIp();
      if (ipRes.ip) setServerIp(ipRes.ip);
      
      const cfRes = await api.getCloudflareConfig();
      setHasCloudflare(cfRes.isConfigured);
      
      setStep(3);
    } catch (e: any) {
      onNotify(e.message || 'Error al importar');
    }
    setLoading(false);
  };

  const typeConfig = {
    app: { icon: Server, label: 'App', checkboxClass: 'text-blue-600 focus:ring-blue-500', iconClass: 'text-blue-500', bgHover: 'hover:bg-blue-50', badge: 'bg-blue-100 text-blue-700' },
    database: { icon: Database, label: 'BD', checkboxClass: 'text-emerald-600 focus:ring-emerald-500', iconClass: 'text-emerald-500', bgHover: 'hover:bg-emerald-50', badge: 'bg-emerald-100 text-emerald-700' },
    service: { icon: Box, label: 'Servicio', checkboxClass: 'text-purple-600 focus:ring-purple-500', iconClass: 'text-purple-500', bgHover: 'hover:bg-purple-50', badge: 'bg-purple-100 text-purple-700' },
  };

  const getVolCount = (r: CoolifyResource) => r.local_persistent_volumes?.length || r.persistent_volumes?.length || r.volumes?.length || 0;
  const getMountCount = (r: CoolifyResource) => r.local_file_volumes?.length || r.file_volumes?.length || 0;
  const getEnvCount = (r: CoolifyResource) => r.environment_variables?.length || 0;

  const renderResourceRow = (resource: CoolifyResource) => {
    const cfg = typeConfig[resource._resourceType];
    const Icon = cfg.icon;
    const isChecked = selected.has(resource.uuid);
    const vols = getVolCount(resource);
    const mounts = getMountCount(resource);
    const envs = getEnvCount(resource);
    const statusRunning = resource.status === 'running';

    return (
      <label key={resource.uuid} className={`flex items-center gap-3 p-3 bg-white border border-slate-200 rounded-lg cursor-pointer ${cfg.bgHover} transition-colors`}>
        <input type="checkbox" checked={isChecked} onChange={() => toggleResource(resource.uuid)} className={`w-4 h-4 rounded border-slate-300 ${cfg.checkboxClass}`} />
        <Icon className={`w-4 h-4 ${cfg.iconClass} flex-shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-900 truncate">{resource.name}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${cfg.badge}`}>{cfg.label}</span>
            {statusRunning && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 flex-shrink-0" title="Running" />}
          </div>
          <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
            {resource.fqdn && <span className="text-xs text-slate-500 truncate max-w-[200px]">{resource.fqdn}</span>}
            {resource.database_type && <span className="text-xs text-slate-500">{resource.database_type}</span>}
            {resource._resourceType === 'service' && <span className="text-xs text-slate-500">Docker Compose</span>}
          </div>
          <div className="flex gap-1.5 mt-1">
            {vols > 0 && <span className="text-[10px] px-1.5 py-0.5 bg-slate-100 rounded text-slate-600">{vols} Vol</span>}
            {mounts > 0 && <span className="text-[10px] px-1.5 py-0.5 bg-slate-100 rounded text-slate-600">{mounts} Mount</span>}
            {envs > 0 && <span className="text-[10px] px-1.5 py-0.5 bg-amber-50 rounded text-amber-700">{envs} Env</span>}
          </div>
        </div>
      </label>
    );
  };

  return (
    <div className="max-w-2xl mx-auto bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
      <div className="p-6 border-b border-slate-200 bg-slate-50 flex items-center gap-3">
        <Download className="w-6 h-6 text-blue-600" />
        <div>
          <h2 className="font-bold text-lg text-slate-900">Importación Total de Coolify</h2>
          <p className="text-sm text-slate-500">Migra apps, bases de datos y servicios con su configuración completa.</p>
        </div>
      </div>

      <div className="p-6">
        {/* ─── STEP 1: Connection ─── */}
        {step === 1 && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">URL de Coolify</label>
              <div className="relative">
                <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input type="text" value={apiUrl} onChange={e => setApiUrl(e.target.value)} className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500" />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">API Token (Bearer)</label>
              <div className="relative">
                <AlertCircle className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input type="password" value={apiToken} onChange={e => setApiToken(e.target.value)} placeholder="v4_..." className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500" />
              </div>
            </div>
            <div className="flex gap-3 pt-4">
              <button onClick={onCancel} className="px-4 py-2 text-slate-600 font-medium hover:bg-slate-100 rounded-xl text-sm">Cancelar</button>
              <button onClick={handleConnect} disabled={loading || !apiUrl || !apiToken} className="flex-1 bg-blue-600 text-white py-2 rounded-xl text-sm font-medium hover:bg-blue-700 flex justify-center items-center">
                {loading ? 'Conectando...' : 'Conectar y Previsualizar'}
              </button>
            </div>
          </div>
        )}

        {/* ─── STEP 2: Preview grouped by Project ─── */}
        {step === 2 && (
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3 text-sm">
                <span className="flex items-center gap-1.5 text-blue-700 font-medium"><Server className="w-3.5 h-3.5" /> {selectedApps.length}/{totalApps} Apps</span>
                <span className="flex items-center gap-1.5 text-emerald-700 font-medium"><Database className="w-3.5 h-3.5" /> {selectedDbs.length}/{totalDbs} BDs</span>
                <span className="flex items-center gap-1.5 text-purple-700 font-medium"><Box className="w-3.5 h-3.5" /> {selectedServices.length}/{totalSvcs} Servicios</span>
              </div>
              <div className="flex gap-2">
                <button onClick={selectAll} className="text-xs text-blue-600 hover:text-blue-800 font-medium">Seleccionar Todo</button>
                <span className="text-slate-300">|</span>
                <button onClick={deselectAll} className="text-xs text-slate-500 hover:text-slate-700 font-medium">Quitar Todo</button>
              </div>
            </div>

            <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
              {projectGroups.map(group => {
                const key = group.project.uuid;
                const isCollapsed = collapsed.has(key);
                const groupUuids = group.resources.map(r => r.uuid);
                const selectedInGroup = groupUuids.filter(id => selected.has(id)).length;
                const allInGroupSelected = selectedInGroup === groupUuids.length;
                const someSelected = selectedInGroup > 0 && !allInGroupSelected;
                const groupApps = group.resources.filter(r => r._resourceType === 'app').length;
                const groupDbs = group.resources.filter(r => r._resourceType === 'database').length;
                const groupSvcs = group.resources.filter(r => r._resourceType === 'service').length;

                return (
                  <div key={key} className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                    <div className="flex items-center gap-3 px-4 py-3 bg-slate-50/80 border-b border-slate-100 cursor-pointer select-none" onClick={() => toggleCollapse(key)}>
                      <button onClick={e => { e.stopPropagation(); toggleProject(group); }} className={`w-5 h-5 flex items-center justify-center rounded border transition-colors flex-shrink-0 ${allInGroupSelected ? 'bg-blue-600 border-blue-600 text-white' : someSelected ? 'bg-blue-100 border-blue-400 text-blue-600' : 'border-slate-300 text-transparent hover:border-slate-400'}`} title={allInGroupSelected ? 'Quitar selección' : 'Seleccionar todo el proyecto'}>
                        {allInGroupSelected ? <Check className="w-3 h-3" /> : someSelected ? <Minus className="w-3 h-3" /> : null}
                      </button>
                      <FolderKanban className="w-4 h-4 text-slate-500 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-slate-900 truncate">{group.project.name}</span>
                          <span className="text-xs text-slate-400">{selectedInGroup}/{group.resources.length}</span>
                        </div>
                        <div className="flex gap-2 mt-0.5">
                          {groupApps > 0 && <span className="text-[10px] text-blue-600">{groupApps} app{groupApps > 1 ? 's' : ''}</span>}
                          {groupDbs > 0 && <span className="text-[10px] text-emerald-600">{groupDbs} bd{groupDbs > 1 ? 's' : ''}</span>}
                          {groupSvcs > 0 && <span className="text-[10px] text-purple-600">{groupSvcs} servicio{groupSvcs > 1 ? 's' : ''}</span>}
                        </div>
                      </div>
                      {isCollapsed ? <ChevronRight className="w-4 h-4 text-slate-400 flex-shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0" />}
                    </div>
                    {!isCollapsed && (
                      <div className="p-3 space-y-2">
                        {group.resources.map(r => renderResourceRow(r))}
                      </div>
                    )}
                  </div>
                );
              })}
              {projectGroups.length === 0 && (
                <div className="text-center py-8 text-slate-500">
                  <FolderKanban className="w-10 h-10 mx-auto mb-2 text-slate-300" />
                  <p className="text-sm">No se encontraron recursos en Coolify.</p>
                </div>
              )}
            </div>

            <div className="flex gap-3 pt-4 border-t border-slate-200">
              <button onClick={() => setStep(1)} className="px-4 py-2 text-slate-600 font-medium hover:bg-slate-100 rounded-xl text-sm transition-colors">Atrás</button>
              <button onClick={handleImport} disabled={loading || selected.size === 0} className="flex-1 bg-blue-600 text-white py-2 rounded-xl text-sm font-medium hover:bg-blue-700 transition-colors flex justify-center items-center disabled:opacity-50 disabled:cursor-not-allowed">
                {loading ? 'Importando...' : `Importar ${selected.size} Recurso${selected.size !== 1 ? 's' : ''} Seleccionados`}
              </button>
            </div>
          </div>
        )}

        {/* ─── STEP 3: Results ─── */}
        {step === 3 && results && (
          <div className="space-y-6 text-center py-6">
            <CheckCircle className="w-16 h-16 text-emerald-500 mx-auto" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Migración Completada Exitosamente</h2>
              <p className="text-sm text-slate-500 mt-2">
                Se han importado {results.importedApps} aplicaciones, {results.importedDbs} bases de datos y {results.importedServices} servicios.
              </p>
            </div>
            {results.errors?.length > 0 && (
              <div className="bg-red-50 text-red-700 p-4 rounded-lg text-sm text-left border border-red-200">
                <p className="font-bold mb-2">Hubo algunos avisos durante la migración:</p>
                <ul className="list-disc pl-4 space-y-1">
                  {results.errors.map((e: string, i: number) => <li key={i}>{e}</li>)}
                </ul>
              </div>
            )}
            
            {importedDomains.length > 0 ? (
              <button onClick={() => setStep(4)} className="w-full bg-blue-600 text-white py-2 rounded-xl text-sm font-medium hover:bg-blue-700 transition-colors">
                Siguiente: Configurar Dominios ({importedDomains.length})
              </button>
            ) : (
              <button onClick={onComplete} className="w-full bg-slate-900 text-white py-2 rounded-xl text-sm font-medium hover:bg-slate-800 transition-colors">
                Ir a mis Proyectos
              </button>
            )}
          </div>
        )}

        {/* ─── STEP 4: Domain Wizard ─── */}
        {step === 4 && (
          <div className="space-y-6">
            <div className="flex items-center gap-3 border-b border-slate-200 pb-4">
              <Globe className="w-6 h-6 text-blue-600" />
              <div>
                <h2 className="font-bold text-lg text-slate-900">Configuración de Dominios</h2>
                <p className="text-sm text-slate-500">Tus apps se han importado correctamente. Ahora configura los dominios para que apunten a tu servidor Culkibo.</p>
              </div>
            </div>

            <div className="bg-blue-50 border border-blue-100 rounded-xl p-4">
              <label className="block text-sm font-medium text-blue-900 mb-1">IP del servidor Culkibo</label>
              <div className="flex items-center gap-3">
                <input 
                  type="text" 
                  value={serverIp} 
                  onChange={e => setServerIp(e.target.value)} 
                  placeholder="Ej: 142.250.180.206"
                  className="flex-1 px-3 py-2 bg-white border border-blue-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500" 
                />
                <label className="flex items-center gap-2 text-sm text-blue-800 bg-blue-100/50 px-3 py-2 rounded-lg cursor-pointer">
                  <input type="checkbox" checked={hasCloudflare} onChange={e => setHasCloudflare(e.target.checked)} className="rounded border-blue-300 text-blue-600" />
                  <Cloud className="w-4 h-4" /> Tengo Cloudflare conectado
                </label>
              </div>
            </div>

            {!hasCloudflare && (
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 text-sm">
                <p className="font-medium text-slate-800 mb-2">Crea un registro A en tu proveedor DNS para cada dominio:</p>
                <code className="block bg-white border border-slate-200 text-slate-800 font-mono text-xs p-2.5 rounded-lg">Tipo: A | Host: @ | Valor: {serverIp || '{serverIp}'} | TTL: 300</code>
              </div>
            )}

            <div className="space-y-3 max-h-[300px] overflow-y-auto">
              {importedDomains.map(domain => {
                const isMigrating = migratingDomains.has(domain.hostname);
                return (
                  <div key={domain.id} className="flex items-center justify-between p-3 bg-white border border-slate-200 rounded-lg">
                    <div>
                      <div className="font-medium text-slate-900 text-sm flex items-center gap-2">
                        {domain.hostname}
                        {domain.sslStatus === 'pending_migration' ? (
                          <span className="text-[10px] bg-yellow-100 text-yellow-800 px-2 py-0.5 rounded-full flex items-center gap-1">
                            <AlertCircle className="w-3 h-3" /> Pendiente
                          </span>
                        ) : (
                          <span className="text-[10px] bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full flex items-center gap-1">
                            <CheckCircle className="w-3 h-3" /> Certificado activo
                          </span>
                        )}
                      </div>
                    </div>
                    <button 
                      onClick={async () => {
                        setMigratingDomains(prev => new Set([...prev, domain.hostname]));
                        try {
                          await api.migrateDomain(domain.hostname, serverIp, hasCloudflare);
                          const domainsRes = await api.getDomains();
                          setImportedDomains(domainsRes.domains.filter(d => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify'));
                        } catch (e: any) {
                          onNotify(e.message || 'Error al migrar dominio');
                        }
                        setMigratingDomains(prev => { const n = new Set(prev); n.delete(domain.hostname); return n; });
                      }}
                      disabled={isMigrating || domain.sslStatus !== 'pending_migration'}
                      className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-100 text-slate-700 hover:bg-slate-200 disabled:opacity-50"
                    >
                      {isMigrating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : domain.sslStatus === 'pending_migration' ? 'Migrar DNS' : 'Completado'}
                    </button>
                  </div>
                );
              })}
            </div>

            <div className="flex gap-3 pt-4 border-t border-slate-200">
              <button onClick={onComplete} className="px-4 py-2 text-slate-600 font-medium hover:bg-slate-100 rounded-xl text-sm transition-colors">
                Saltar y configurar después
              </button>
              <button 
                onClick={async () => {
                  setLoading(true);
                  const hostnames = importedDomains.filter(d => d.sslStatus === 'pending_migration').map(d => d.hostname);
                  setMigratingDomains(new Set(hostnames));
                  try {
                    await api.migrateDomainsBatch(hostnames, serverIp, hasCloudflare);
                    const domainsRes = await api.getDomains();
                    setImportedDomains(domainsRes.domains.filter(d => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify'));
                    onNotify('Migración de dominios completada');
                  } catch (e: any) {
                    onNotify(e.message || 'Error en batch');
                  }
                  setMigratingDomains(new Set());
                  setLoading(false);
                }}
                disabled={loading || importedDomains.every(d => d.sslStatus !== 'pending_migration')}
                className="flex-1 bg-blue-600 text-white py-2 rounded-xl text-sm font-medium hover:bg-blue-700 transition-colors flex justify-center items-center disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Migrar Todos los Dominios a Culkibo'}
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
