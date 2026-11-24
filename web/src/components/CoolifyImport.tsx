import React, { useState, useMemo } from 'react';
import {
  Download,
  Link as LinkIcon,
  Server,
  Database,
  CheckCircle2,
  AlertCircle,
  Box,
  ChevronDown,
  ChevronRight,
  FolderKanban,
  Check,
  Minus,
  Globe,
  Loader2,
  Cloud,
} from 'lucide-react';
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

export const CoolifyImport: React.FC<{
  onComplete: () => void;
  onCancel: () => void;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}> = ({ onComplete, onCancel, onNotify }) => {
  const [step, setStep] = useState(1);
  const [apiUrl, setApiUrl] = useState('');
  const [apiToken, setApiToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [allResources, setAllResources] = useState<CoolifyResource[]>([]);
  const [projects, setProjects] = useState<CoolifyProject[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [results, setResults] = useState<any>(null);

  const [importedDomains, setImportedDomains] = useState<DomainItem[]>([]);
  const [serverIp, setServerIp] = useState('');
  const [cfAvailable, setCfAvailable] = useState(false);
  const [useCloudflare, setUseCloudflare] = useState(false);
  const [migratingDomains, setMigratingDomains] = useState<Set<string>>(new Set());

  const handleConnect = async () => {
    setLoading(true);
    try {
      const res = await api.previewCoolify(apiUrl.trim(), apiToken.trim());
      const apps: CoolifyResource[] = (res.apps || []).map((a: any) => ({ ...a, _resourceType: 'app' as const }));
      const dbs: CoolifyResource[] = (res.databases || []).map((d: any) => ({ ...d, _resourceType: 'database' as const }));
      const svcs: CoolifyResource[] = (res.services || []).map((s: any) => ({ ...s, _resourceType: 'service' as const }));
      const all = [...apps, ...dbs, ...svcs];
      setAllResources(all);
      setProjects(res.projects || []);
      setSelected(new Set(all.map((r) => r.uuid)));
      setStep(2);
    } catch (e: any) {
      onNotify(e?.message || 'Error al conectar con Coolify', 'error');
    } finally {
      setLoading(false);
    }
  };

  const projectGroups: ProjectGroup[] = useMemo(() => {
    const groups = new Map<string, ProjectGroup>();
    const fallbackProject: CoolifyProject = {
      uuid: '_unassigned',
      name: 'Sin proyecto asignado',
      description: 'Recursos sin proyecto en Coolify',
    };

    for (const resource of allResources) {
      let projectKey = '_unassigned';
      let project: CoolifyProject = fallbackProject;

      if (resource.environment?.project?.uuid) {
        projectKey = resource.environment.project.uuid;
        const match = projects.find((p) => p.uuid === projectKey);
        project = match || { uuid: projectKey, name: resource.environment.project.name || 'Proyecto Coolify', description: '' };
      } else if (resource.project_id && projects.length) {
        const match = projects.find((p) => p.id === resource.project_id || p.uuid === String(resource.project_id));
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

  const toggleResource = (uuid: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(uuid)) next.delete(uuid);
      else next.add(uuid);
      return next;
    });

  const toggleProject = (group: ProjectGroup) => {
    const uuids = group.resources.map((r) => r.uuid);
    const allSelected = uuids.every((id) => selected.has(id));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) uuids.forEach((id) => next.delete(id));
      else uuids.forEach((id) => next.add(id));
      return next;
    });
  };

  const toggleCollapse = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const selectAll = () => setSelected(new Set(allResources.map((r) => r.uuid)));
  const deselectAll = () => setSelected(new Set());

  const selectedApps = allResources.filter((r) => r._resourceType === 'app' && selected.has(r.uuid)).map((r) => r.uuid);
  const selectedDbs = allResources.filter((r) => r._resourceType === 'database' && selected.has(r.uuid)).map((r) => r.uuid);
  const selectedServices = allResources.filter((r) => r._resourceType === 'service' && selected.has(r.uuid)).map((r) => r.uuid);
  const totalApps = allResources.filter((r) => r._resourceType === 'app').length;
  const totalDbs = allResources.filter((r) => r._resourceType === 'database').length;
  const totalSvcs = allResources.filter((r) => r._resourceType === 'service').length;

  const handleImport = async () => {
    setLoading(true);
    try {
      const res = await api.importCoolify(apiUrl.trim(), apiToken.trim(), selectedApps, selectedDbs, selectedServices);
      setResults(res);

      const [domainsRes, ipRes, cfRes] = await Promise.all([
        api.getDomains().catch(() => ({ domains: [] as DomainItem[] })),
        api.getServerIp().catch(() => ({ ip: null })),
        api.getCloudflareConfig().catch(() => ({ isConfigured: false })),
      ]);

      const coolifyDomains = (domainsRes.domains || []).filter(
        (d) => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify'
      );
      setImportedDomains(coolifyDomains);
      if (ipRes.ip) setServerIp(ipRes.ip);
      const cfOk = Boolean(cfRes?.isConfigured);
      setCfAvailable(cfOk);
      setUseCloudflare(cfOk);

      setStep(3);
    } catch (e: any) {
      onNotify(e?.message || 'Error al importar desde Coolify', 'error');
    } finally {
      setLoading(false);
    }
  };

  const typeConfig = {
    app: { icon: Server, label: 'Aplicación' },
    database: { icon: Database, label: 'Base de datos' },
    service: { icon: Box, label: 'Servicio' },
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
      <label key={resource.uuid} className="flex items-center gap-3 p-3 bg-white border border-slate-200 rounded-lg cursor-pointer hover:bg-slate-50 transition-colors">
        <input
          type="checkbox"
          checked={isChecked}
          onChange={() => toggleResource(resource.uuid)}
          className="w-4 h-4 rounded border-slate-300 accent-slate-900"
        />
        <Icon className="w-4 h-4 text-slate-500 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-slate-900 truncate">{resource.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200 font-medium">
              {cfg.label}
            </span>
            {statusRunning && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" title="En ejecución" />}
          </div>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap text-[11px] text-slate-500">
            {resource.fqdn && <span className="font-mono truncate max-w-[220px]">{resource.fqdn}</span>}
            {resource.database_type && <span>{resource.database_type}</span>}
            {resource._resourceType === 'service' && <span>Docker Compose</span>}
          </div>
          {(vols > 0 || mounts > 0 || envs > 0) && (
            <div className="flex gap-1.5 mt-1 text-[10px] text-slate-500 tabular-nums">
              {vols > 0 && <span className="px-1.5 py-0.5 bg-slate-100 rounded">{vols} {vols === 1 ? 'volumen' : 'volúmenes'}</span>}
              {mounts > 0 && <span className="px-1.5 py-0.5 bg-slate-100 rounded">{mounts} {mounts === 1 ? 'archivo' : 'archivos'}</span>}
              {envs > 0 && <span className="px-1.5 py-0.5 bg-slate-100 rounded">{envs} {envs === 1 ? 'variable' : 'variables'}</span>}
            </div>
          )}
        </div>
      </label>
    );
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      <div className="p-5 border-b border-slate-200 bg-slate-50 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
          <Download className="w-4 h-4" />
        </div>
        <div>
          <h2 className="font-semibold text-base text-slate-900">Importación desde Coolify v4</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Migra aplicaciones, bases de datos, variables y dominios con su configuración completa.
          </p>
        </div>
      </div>

      <div className="p-5">
        {/* PASO 1 */}
        {step === 1 && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void handleConnect();
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">URL de tu instancia Coolify</label>
              <div className="relative">
                <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="url"
                  required
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="https://coolify.tudominio.com"
                  className="w-full pl-9 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Token de API (Bearer)</label>
              <div className="relative">
                <AlertCircle className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="password"
                  required
                  value={apiToken}
                  onChange={(e) => setApiToken(e.target.value)}
                  placeholder="1|xxxxxxxxxxxxxxxxxxxx"
                  className="w-full pl-9 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={onCancel} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                Cancelar
              </button>
              <button
                type="submit"
                disabled={loading || !apiUrl.trim() || !apiToken.trim()}
                className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
              >
                {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {loading ? 'Conectando…' : 'Conectar y previsualizar'}
              </button>
            </div>
          </form>
        )}

        {/* PASO 2 */}
        {step === 2 && (
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3 text-xs text-slate-600 tabular-nums">
                <span className="flex items-center gap-1"><Server className="w-3.5 h-3.5 text-slate-400" /> {selectedApps.length}/{totalApps} apps</span>
                <span className="flex items-center gap-1"><Database className="w-3.5 h-3.5 text-slate-400" /> {selectedDbs.length}/{totalDbs} BDs</span>
                <span className="flex items-center gap-1"><Box className="w-3.5 h-3.5 text-slate-400" /> {selectedServices.length}/{totalSvcs} servicios</span>
              </div>
              <div className="flex gap-2 text-xs">
                <button type="button" onClick={selectAll} className="text-slate-700 hover:text-slate-900 font-medium underline cursor-pointer">
                  Seleccionar todo
                </button>
                <span className="text-slate-300">·</span>
                <button type="button" onClick={deselectAll} className="text-slate-500 hover:text-slate-800 font-medium cursor-pointer">
                  Quitar todo
                </button>
              </div>
            </div>

            <div className="space-y-3 max-h-[400px] overflow-y-auto pr-1">
              {projectGroups.map((group) => {
                const key = group.project.uuid;
                const isCollapsed = collapsed.has(key);
                const groupUuids = group.resources.map((r) => r.uuid);
                const selectedInGroup = groupUuids.filter((id) => selected.has(id)).length;
                const allInGroupSelected = selectedInGroup === groupUuids.length;
                const someSelected = selectedInGroup > 0 && !allInGroupSelected;

                return (
                  <div key={key} className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                    <div className="flex items-center gap-3 px-4 py-3 bg-slate-50 border-b border-slate-200 select-none">
                      <button
                        type="button"
                        aria-label={allInGroupSelected ? `Quitar selección de ${group.project.name}` : `Seleccionar todo ${group.project.name}`}
                        onClick={() => toggleProject(group)}
                        className={`w-4 h-4 flex items-center justify-center rounded border transition-colors shrink-0 cursor-pointer ${
                          allInGroupSelected
                            ? 'bg-slate-900 border-slate-900 text-white'
                            : someSelected
                              ? 'bg-slate-200 border-slate-400 text-slate-900'
                              : 'border-slate-300 text-transparent bg-white'
                        }`}
                        title={allInGroupSelected ? 'Quitar selección' : 'Seleccionar todo el proyecto'}
                      >
                        {allInGroupSelected ? <Check className="w-3 h-3" /> : someSelected ? <Minus className="w-3 h-3" /> : null}
                      </button>
                      <button
                        type="button"
                        aria-expanded={!isCollapsed}
                        onClick={() => toggleCollapse(key)}
                        className="flex-1 min-w-0 flex items-center justify-between gap-2 text-left cursor-pointer"
                      >
                        <span className="flex items-center gap-2 min-w-0">
                          <FolderKanban className="w-4 h-4 text-slate-500 shrink-0" />
                          <span className="text-xs font-semibold text-slate-900 truncate">{group.project.name}</span>
                          <span className="text-[11px] text-slate-400 tabular-nums">
                            {selectedInGroup}/{group.resources.length}
                          </span>
                        </span>
                        {isCollapsed ? <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />}
                      </button>
                    </div>
                    {!isCollapsed && (
                      <div className="p-3 space-y-2">{group.resources.map((r) => renderResourceRow(r))}</div>
                    )}
                  </div>
                );
              })}
              {projectGroups.length === 0 && (
                <div className="text-center py-8 text-slate-500 text-xs">
                  No se encontraron recursos en esa instancia de Coolify.
                </div>
              )}
            </div>

            <div className="flex justify-between gap-2 pt-3 border-t border-slate-200">
              <button type="button" onClick={() => setStep(1)} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                Atrás
              </button>
              <button
                type="button"
                onClick={() => void handleImport()}
                disabled={loading || selected.size === 0}
                className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer tabular-nums"
              >
                {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {loading
                  ? 'Importando…'
                  : `Importar ${selected.size} ${selected.size === 1 ? 'recurso seleccionado' : 'recursos seleccionados'}`}
              </button>
            </div>
          </div>
        )}

        {/* PASO 3 */}
        {step === 3 && results && (
          <div className="space-y-5 text-center py-4">
            <CheckCircle2 className="w-12 h-12 text-emerald-600 mx-auto" />
            <div>
              <h3 className="text-base font-semibold text-slate-900">Migración completada</h3>
              <p className="text-xs text-slate-500 mt-1 tabular-nums">
                Se importaron {results.importedApps} aplicaciones, {results.importedDbs} bases de datos y {results.importedServices} servicios.
              </p>
            </div>
            {results.errors?.length > 0 && (
              <div className="bg-red-50 text-red-800 p-4 rounded-xl text-xs text-left border border-red-200">
                <p className="font-semibold mb-1.5">Avisos durante la migración:</p>
                <ul className="list-disc pl-4 space-y-1">
                  {results.errors.map((e: string, i: number) => <li key={i}>{e}</li>)}
                </ul>
              </div>
            )}

            {importedDomains.length > 0 ? (
              <button
                type="button"
                onClick={() => setStep(4)}
                className="px-5 py-2.5 bg-slate-900 text-white rounded-lg text-xs font-medium hover:bg-slate-800 cursor-pointer tabular-nums"
              >
                Siguiente: configurar dominios ({importedDomains.length})
              </button>
            ) : (
              <button
                type="button"
                onClick={onComplete}
                className="px-5 py-2.5 bg-slate-900 text-white rounded-lg text-xs font-medium hover:bg-slate-800 cursor-pointer"
              >
                Ir a proyectos
              </button>
            )}
          </div>
        )}

        {/* PASO 4 */}
        {step === 4 && (
          <div className="space-y-5">
            <div className="flex items-center gap-2.5 border-b border-slate-200 pb-3.5">
              <Globe className="w-4 h-4 text-slate-600" />
              <div>
                <h3 className="font-semibold text-sm text-slate-900">Migración de dominios</h3>
                <p className="text-xs text-slate-500">Apunta los dominios importados a la IP de este servidor.</p>
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2.5">
              <label className="block text-xs font-medium text-slate-700">IP del servidor Culkibo</label>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                <input
                  type="text"
                  value={serverIp}
                  onChange={(e) => setServerIp(e.target.value)}
                  placeholder="203.0.113.10"
                  className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                />
                <label className="flex items-center gap-2 text-xs text-slate-700 bg-white border border-slate-200 px-3 py-2 rounded-lg cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useCloudflare}
                    onChange={(e) => setUseCloudflare(e.target.checked)}
                    className="rounded border-slate-300 accent-slate-900"
                  />
                  <Cloud className="w-3.5 h-3.5 text-slate-500" />
                  <span>Actualizar DNS vía Cloudflare</span>
                </label>
              </div>
              {useCloudflare && !cfAvailable && (
                <p className="text-[11px] text-amber-800">
                  Cloudflare no está configurado todavía en Ajustes → Integraciones; configura tu API Token para que el cambio sea automático.
                </p>
              )}
            </div>

            {!useCloudflare && (
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 text-xs">
                <p className="font-medium text-slate-800 mb-1.5">Crea un registro A en tu proveedor DNS:</p>
                <code className="block bg-white border border-slate-200 text-slate-800 font-mono text-[11px] p-2.5 rounded-lg">
                  Tipo: A · Host: @ · Valor: {serverIp || '<IP_DEL_SERVIDOR>'} · TTL: 300
                </code>
              </div>
            )}

            <div className="space-y-2 max-h-[280px] overflow-y-auto">
              {importedDomains.map((domain) => {
                const isMigrating = migratingDomains.has(domain.hostname);
                const isPending = domain.sslStatus === 'pending_migration';
                const isActive = domain.sslStatus === 'active';
                return (
                  <div key={domain.id} className="flex items-center justify-between p-3 bg-white border border-slate-200 rounded-lg gap-3">
                    <div className="flex items-center gap-2 min-w-0 flex-wrap">
                      <span className="font-mono font-medium text-slate-900 text-xs truncate">{domain.hostname}</span>
                      {isPending ? (
                        <span className="text-[10px] bg-amber-50 text-amber-800 border border-amber-200 px-2 py-0.5 rounded-full">
                          Pendiente DNS
                        </span>
                      ) : isActive ? (
                        <span className="text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded-full">
                          Certificado activo
                        </span>
                      ) : (
                        <span className="text-[10px] bg-amber-50 text-amber-800 border border-amber-200 px-2 py-0.5 rounded-full">
                          SSL pendiente
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={async () => {
                        setMigratingDomains((prev) => new Set([...prev, domain.hostname]));
                        try {
                          await api.migrateDomain(domain.hostname, serverIp, useCloudflare);
                          const domainsRes = await api.getDomains();
                          setImportedDomains(
                            domainsRes.domains.filter((d) => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify')
                          );
                          onNotify(`Dominio ${domain.hostname} actualizado`, 'success');
                        } catch (e: any) {
                          onNotify(e?.message || 'Error al migrar dominio', 'error');
                        } finally {
                          setMigratingDomains((prev) => {
                            const n = new Set(prev);
                            n.delete(domain.hostname);
                            return n;
                          });
                        }
                      }}
                      disabled={isMigrating || !isPending}
                      className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-50 cursor-pointer shrink-0"
                    >
                      {isMigrating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : isPending ? 'Migrar DNS' : 'Registrado'}
                    </button>
                  </div>
                );
              })}
            </div>

            <div className="flex justify-between gap-2 pt-3 border-t border-slate-200">
              <button type="button" onClick={onComplete} className="px-3.5 py-2 text-slate-600 font-medium border border-slate-200 hover:bg-slate-50 rounded-lg text-xs cursor-pointer">
                Configurar después
              </button>
              <button
                type="button"
                onClick={async () => {
                  setLoading(true);
                  const hostnames = importedDomains.filter((d) => d.sslStatus === 'pending_migration').map((d) => d.hostname);
                  setMigratingDomains(new Set(hostnames));
                  try {
                    await api.migrateDomainsBatch(hostnames, serverIp, useCloudflare);
                    const domainsRes = await api.getDomains();
                    setImportedDomains(
                      domainsRes.domains.filter((d) => d.sslStatus === 'pending_migration' || d.migrationSource === 'coolify')
                    );
                    onNotify('Migración de dominios completada', 'success');
                  } catch (e: any) {
                    onNotify(e?.message || 'Error al migrar los dominios', 'error');
                  } finally {
                    setMigratingDomains(new Set());
                    setLoading(false);
                  }
                }}
                disabled={loading || importedDomains.every((d) => d.sslStatus !== 'pending_migration')}
                className="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-medium hover:bg-slate-800 inline-flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
              >
                {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                <span>Migrar todos los dominios</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
