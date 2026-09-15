import React, { useState, useEffect } from 'react';
import { Settings, Activity, Globe, Variable, Play, Square, Moon, Trash2, ShieldAlert, Database, Server, Copy, Eye, EyeOff, Plus, Search, Upload, Save, CheckCircle2, Box, Cpu, Webhook, GitBranch, Check, RefreshCw, Zap, Power } from 'lucide-react';
import { api, type Project } from '../lib/api';
import { LiveLogs } from './LiveLogs';
import { DomainManager } from './DomainManager';
import { DatabasesPanel } from './DatabasesPanel';

interface ProjectDetailProps {
  projectId: string;
  onBack: () => void;
  onNotify: (msg: string) => void;
  onProjectUpdate?: () => void;
  incomingLog?: any;
}

export const ProjectDetail: React.FC<ProjectDetailProps> = ({ projectId, onBack, onNotify, onProjectUpdate, incomingLog }) => {
  const [project, setProject] = useState<Project | null>(null);
  const [activeTab, setActiveTab] = useState<'general' | 'logs' | 'domains' | 'databases' | 'storage' | 'vars' | 'config'>('general');
  const [loading, setLoading] = useState(false);
  const [simulatingWebhook, setSimulatingWebhook] = useState(false);

  // Webhook state
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [showSecret, setShowSecret] = useState(false);

  // Vars state
  const [envMode, setEnvMode] = useState<'table' | 'raw'>('table');
  const [envText, setEnvText] = useState('');
  const [envRows, setEnvRows] = useState<{ key: string, value: string, id: string }[]>([]);
  const [showValues, setShowValues] = useState<Record<string, boolean>>({});
  const [searchVar, setSearchVar] = useState('');

  const [showAddService, setShowAddService] = useState(false);
  const [newService, setNewService] = useState({ name: '', type: 'Aplicación Web', port: '', image: '' });

  const handleAddService = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!project) return;
    try {
      const updatedResources = [...(project.resources || []), {
        id: `res_${Date.now()}`,
        name: newService.name,
        type: newService.type.toLowerCase().includes('database') || newService.type.toLowerCase().includes('redis') || newService.type.toLowerCase().includes('mongo') ? 'database' : 'app',
        port: newService.port,
        image: newService.image,
        ports: [newService.port]
      }];
      await api.updateProject(projectId, { resources: updatedResources });
      onNotify('Servicio añadido correctamente');
      setShowAddService(false);
      setNewService({ name: '', type: 'Aplicación Web', port: '', image: '' });
      fetchProject();
    } catch (error) {
      onNotify('Error al añadir servicio');
    }
  };

  const fetchProject = async () => {
    try {
      const found = await api.getProject(projectId);
      if (found) {
        setProject(found);
        const text = Object.entries(found.envVars || {}).map(([k,v]) => `${k}=${v}`).join('\n');
        setEnvText(text);
        setEnvRows(Object.entries(found.envVars || {}).map(([k,v], i) => ({ key: k, value: v as string, id: `row_${i}_${Date.now()}` })));
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchProject();
  }, [projectId]);

  useEffect(() => {
    if (incomingLog) {
      const msg = incomingLog.message || '';
      if (
        incomingLog.projectId === projectId ||
        msg.includes(projectId) ||
        (project && msg.includes(project.name)) ||
        msg.includes('GitHub:Webhook') ||
        msg.includes('Despliegue completado')
      ) {
        fetchProject();
      }
    }
  }, [incomingLog]);

  const handleSimulatePush = async () => {
    if (!project) return;
    setSimulatingWebhook(true);
    try {
      const shortSha = Math.random().toString(36).substring(2, 9);
      const res = await fetch(`/api/webhooks/github?projectId=${project.id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-github-event': 'push'
        },
        body: JSON.stringify({
          ref: `refs/heads/${project.gitBranch || 'main'}`,
          after: `${shortSha}1234567890`,
          head_commit: {
            id: `${shortSha}1234567890`,
            message: `test: actualización en tiempo real (${shortSha})`,
            author: { name: 'Pablo Developer' }
          },
          repository: {
            full_name: project.gitRepo || `${project.githubOwner || 'user'}/${project.githubRepo || project.name}`,
            html_url: project.gitRepo || 'https://github.com/user/repo'
          }
        })
      });
      const data = await res.json();
      if (res.ok && data.deployed) {
        onNotify(`🚀 Despliegue simulado con éxito (${shortSha})`);
        fetchProject();
      } else {
        onNotify(`Webhook recibido: ${data.reason || data.error || 'OK'}`);
      }
    } catch (e: any) {
      onNotify(`Error al simular webhook: ${e.message}`);
    } finally {
      setSimulatingWebhook(false);
    }
  };

  if (!project) return <div className="p-8 text-center text-slate-500">Cargando proyecto...</div>;

  const handleStop = async () => {
    setLoading(true);
    try {
      setProject(prev => prev ? { ...prev, status: 'stopped', localRunning: false } : null);
      await api.stopProject(projectId);
      await fetchProject();
      onNotify('Proyecto detenido: procesos finalizados y puerto liberado');
      onProjectUpdate?.();
    } catch (e: any) {
      console.error(e);
      onNotify('Error al detener proyecto: ' + (e.message || ''));
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleHibernate = async () => {
    setLoading(true);
    try {
      setProject(prev => prev ? { ...prev, status: 'hibernated', localRunning: false } : null);
      await api.hibernateProject(projectId);
      await fetchProject();
      onNotify('Proyecto hibernado correctamente');
      onProjectUpdate?.();
    } catch (e: any) {
      console.error(e);
      onNotify('Error al hibernar proyecto');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleStart = async () => {
    setLoading(true);
    try {
      setProject(prev => prev ? { ...prev, status: 'active', localRunning: true } : null);
      await api.startLocal(projectId);
      await fetchProject();
      onNotify('Proyecto iniciado en local');
      onProjectUpdate?.();
    } catch (e: any) {
      console.error(e);
      onNotify('Error al iniciar en local');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (action: 'activate' | 'hibernate') => {
    setLoading(true);
    try {
      if (action === 'activate') {
        setProject(prev => prev ? { ...prev, status: 'active' } : null);
        await api.activateProject(projectId);
        onNotify('Entorno activado');
      }
      if (action === 'hibernate') {
        setProject(prev => prev ? { ...prev, status: 'hibernated', localRunning: false } : null);
        await api.hibernateProject(projectId);
        onNotify('Proyecto hibernado');
      }
      await fetchProject();
      onProjectUpdate?.();
    } catch (e) {
      console.error(e);
      onNotify('Error al ejecutar acción');
      await fetchProject();
    } finally {
      setLoading(false);
    }
  };

  const handleSaveEnvRaw = async () => {
    const newVars: Record<string, string> = {};
    let currentKey: string | null = null;
    let currentValue: string[] = [];

    envText.split('\n').forEach(line => {
      const match = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)=(.*)$/);
      if (match) {
        if (currentKey) {
          newVars[currentKey] = currentValue.join('\n');
        }
        currentKey = match[1];
        currentValue = [match[2]];
      } else if (currentKey) {
        currentValue.push(line);
      }
    });
    if (currentKey) {
      newVars[currentKey] = currentValue.join('\n');
    }

    try {
      await api.updateProject(projectId, { envVars: newVars });
      onNotify('Variables actualizadas correctamente');
      fetchProject();
    } catch (e) {
      onNotify('Error al guardar variables');
    }
  };

  const handleSaveEnvTable = async () => {
    const newVars: Record<string, string> = {};
    for (const r of envRows) {
      if (r.key.trim()) {
        newVars[r.key.trim()] = r.value;
      }
    }
    try {
      await api.updateProject(projectId, { envVars: newVars });
      onNotify('Variables actualizadas correctamente');
      fetchProject();
    } catch (e) {
      onNotify('Error al guardar variables');
    }
  };

  const handleDelete = async () => {
    if (confirm('¿Estás seguro de eliminar este proyecto? Esta acción es irreversible.')) {
      await api.deleteProject(projectId);
      onNotify('Proyecto eliminado');
      onBack();
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    onNotify('Copiado al portapapeles');
  };

  const tabs = [
    { id: 'general', label: 'General', icon: Activity },
    { id: 'logs', label: 'Logs', icon: Activity },
    { id: 'domains', label: 'Dominios', icon: Globe },
    { id: 'databases', label: 'Bases de datos', icon: Database },
    { id: 'storage', label: 'Almacenamiento', icon: Box },
    { id: 'vars', label: 'Variables', icon: Variable },
    { id: 'config', label: 'Configuración', icon: Settings }
  ];

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
      <div className="flex flex-col md:flex-row md:items-center gap-4 bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
        <div className="flex items-center gap-4">
          <button onClick={onBack} className="text-slate-400 hover:text-slate-900 transition-colors p-2 -ml-2 rounded-xl hover:bg-slate-50">&larr; Volver</button>
          <div className="text-4xl bg-slate-50 w-16 h-16 rounded-2xl flex items-center justify-center border border-slate-100 shadow-sm">{project.icon}</div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-2xl font-bold text-slate-900">{project.name}</h2>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                  project.status === 'active'
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200/80'
                    : project.status === 'hibernated'
                    ? 'bg-sky-50 text-sky-700 border border-sky-200/80'
                    : 'bg-slate-100 text-slate-600 border border-slate-200'
                }`}
              >
                {project.status === 'active' ? (
                  <>
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                    </span>
                    Activo
                  </>
                ) : project.status === 'hibernated' ? (
                  <>
                    <span className="w-2 h-2 rounded-full bg-sky-400" />
                    Hibernado
                  </>
                ) : (
                  <>
                    <span className="w-2 h-2 rounded-full bg-slate-400" />
                    Detenido
                  </>
                )}
              </span>

              {project.localRunning && (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-amber-50 text-amber-700 border border-amber-200/80 shadow-2xs">
                  <Zap className="w-3.5 h-3.5 fill-amber-500 text-amber-600" />
                  <span>Local :{project.localPort}</span>
                </span>
              )}

              <button onClick={() => setActiveTab('config')} className="text-slate-400 hover:text-slate-900 transition-colors">
                <Settings className="w-5 h-5" />
              </button>
            </div>
            <p className="text-sm text-slate-500 mt-0.5">{project.description || 'Sin descripción'}</p>
          </div>
        </div>

        <div className="md:ml-auto flex items-center gap-2.5 flex-wrap">
          {project.status === 'active' || project.localRunning ? (
            <>
              {!project.localRunning && (
                <button
                  onClick={handleStart}
                  disabled={loading}
                  className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-4 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-sm active:scale-[0.98] cursor-pointer disabled:opacity-50"
                  title="Iniciar en entorno local"
                >
                  <Play className="w-4 h-4 fill-current" /> Iniciar en Local
                </button>
              )}

              {project.localRunning && project.localPort && (
                <a
                  href={`http://localhost:${project.localPort}`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-2 bg-amber-50 hover:bg-amber-100 text-amber-800 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all border border-amber-200/80 shadow-2xs cursor-pointer"
                  title={`Abrir entorno local en http://localhost:${project.localPort}`}
                >
                  <Globe className="w-4 h-4 text-amber-600" /> Abrir Local (:{project.localPort})
                </a>
              )}

              <button
                onClick={handleStop}
                disabled={loading}
                className="flex items-center gap-2 bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-2xs active:scale-[0.98] cursor-pointer disabled:opacity-50"
                title="Detener proyecto y liberar puertos"
              >
                <Square className="w-4 h-4 fill-rose-600 text-rose-600" /> Detener
              </button>

              <button
                onClick={handleHibernate}
                disabled={loading}
                className="flex items-center gap-2 bg-slate-100 hover:bg-slate-200 text-slate-700 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer disabled:opacity-50"
                title="Hibernar proyecto (reposo completo)"
              >
                <Moon className="w-4 h-4 text-slate-600" /> Hibernar
              </button>
            </>
          ) : (
            <>
              <button
                onClick={handleStart}
                disabled={loading}
                className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-5 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-sm active:scale-[0.98] cursor-pointer disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-current" /> Iniciar en Local
              </button>
              <button
                onClick={() => handleAction('activate')}
                disabled={loading}
                className="flex items-center gap-2 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200/80 px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all cursor-pointer disabled:opacity-50"
                title="Activar en producción"
              >
                <Power className="w-4 h-4 text-emerald-600" /> Activar
              </button>
            </>
          )}

          {project.domains && project.domains.length > 0 && (
            <a
              href={`https://${project.domains[0]}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 bg-blue-50 hover:bg-blue-100 text-blue-700 px-4 py-2.5 rounded-xl text-sm font-medium transition-all"
            >
              <Globe className="w-4 h-4" /> Ver Web
            </a>
          )}
        </div>
      </div>
      
      {/* Status Indicator Banner */}
      {project.status === 'active' ? (
        project.localRunning ? (
          <div className="bg-emerald-50 border border-emerald-200 text-emerald-900 px-4 py-3 rounded-xl flex items-center justify-between shadow-2xs">
            <span className="text-xs sm:text-sm font-medium flex items-center gap-2.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span>Ejecutándose en local — <strong>http://localhost:{project.localPort}</strong> y activo en producción</span>
            </span>
            <a
              href={`http://localhost:${project.localPort}`}
              target="_blank"
              rel="noreferrer"
              className="text-xs font-semibold text-emerald-700 hover:text-emerald-900 underline ml-2"
            >
              Abrir aplicación &rarr;
            </a>
          </div>
        ) : (
          <div className="bg-emerald-50/70 border border-emerald-200 text-emerald-900 px-4 py-3 rounded-xl flex items-center justify-between shadow-2xs">
            <span className="text-xs sm:text-sm font-medium flex items-center gap-2.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span>Producción activa — Enrutado por Citadel (:8080) / Ingress Edge</span>
            </span>
            {project.localPort ? (
              <span className="text-xs font-mono text-slate-500 bg-white/80 border border-emerald-200 px-2 py-0.5 rounded">
                Puerto local :{project.localPort} (inactivo)
              </span>
            ) : null}
          </div>
        )
      ) : project.status === 'hibernated' ? (
        <div className="bg-sky-50/80 border border-sky-200 text-sky-900 px-4 py-3 rounded-xl flex items-center justify-between shadow-2xs">
          <span className="text-xs sm:text-sm font-medium flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <span>Proyecto en estado hibernado — Recursos en reposo y puertos liberados.</span>
          </span>
          {project.localPort && (
            <span className="text-xs font-mono text-sky-600 bg-white/80 border border-sky-200 px-2 py-0.5 rounded">
              Puerto :{project.localPort} (liberado)
            </span>
          )}
        </div>
      ) : (
        <div className="bg-slate-100/90 border border-slate-200 text-slate-700 px-4 py-3 rounded-xl flex items-center justify-between shadow-2xs">
          <span className="text-xs sm:text-sm font-medium flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-400" />
            <span>Proyecto detenido — Sin procesos locales en ejecución ni puertos en uso.</span>
          </span>
          {project.localPort && (
            <span className="text-xs font-mono text-slate-400 bg-white border border-slate-200 px-2 py-0.5 rounded">
              Puerto :{project.localPort} (inactivo)
            </span>
          )}
        </div>
      )}

      <div className="flex border-b border-slate-200 gap-8 px-2">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id as any)} className={`flex items-center gap-2 pb-4 text-sm font-medium border-b-2 transition-all ${activeTab === t.id ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-500 hover:text-slate-800'}`}>
            <t.icon className={`w-4 h-4 ${activeTab === t.id ? 'text-slate-900' : 'text-slate-400'}`} />
            {t.label}
          </button>
        ))}
      </div>

      <div className="py-2">
        {activeTab === 'general' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              {/* Resources Section */}
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                  <h3 className="font-semibold text-slate-900 flex items-center gap-2">
                    <Box className="w-5 h-5 text-indigo-500" />
                    Recursos y Contenedores
                  </h3>
                  <button onClick={() => setShowAddService(true)} className="text-sm font-medium text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-sm flex items-center gap-1">
                    <Plus className="w-4 h-4" /> Añadir Servicio
                  </button>
                </div>
                <div className="p-6">
                  {project.resources && project.resources.length > 0 ? (
                    <div className="space-y-4">
                      {project.resources.map((res: any) => {
                        const isResActive = project.status === 'active' && (project.localRunning || res.status === 'running' || res.status === 'active');
                        const isResHibernated = project.status === 'hibernated' || res.status === 'hibernated';
                        return (
                          <div key={res.id} className="flex items-center justify-between p-4 rounded-xl border border-slate-200 hover:border-slate-300 transition-colors bg-white">
                            <div className="flex items-center gap-4">
                              <div className="w-10 h-10 rounded-lg bg-indigo-50 flex items-center justify-center text-indigo-600">
                                {res.type === 'database' ? <Database className="w-5 h-5" /> : <Server className="w-5 h-5" />}
                              </div>
                              <div>
                                <div className="font-medium text-slate-900">{res.name}</div>
                                <div className="text-xs text-slate-500 flex items-center gap-2">
                                  <span className="uppercase tracking-wider">{res.type}</span> &bull; {res.image || 'sandbox-isolated'}
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-4 text-sm">
                              {project.localRunning && res.localPort && (
                                <a href={`http://localhost:${res.localPort}`} target="_blank" rel="noreferrer" className="flex items-center gap-1.5 bg-blue-50 text-blue-700 hover:bg-blue-100 px-2.5 py-1 rounded-md text-xs font-medium border border-blue-200 transition-colors">
                                  <Globe className="w-3 h-3" /> Abrir (:{res.localPort})
                                </a>
                              )}
                              <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${
                                isResActive
                                  ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
                                  : isResHibernated
                                  ? 'bg-sky-50 text-sky-700 border-sky-100'
                                  : 'bg-slate-100 text-slate-600 border-slate-200'
                              }`}>
                                <span className={`w-1.5 h-1.5 rounded-full ${
                                  isResActive
                                    ? 'bg-emerald-500 animate-pulse'
                                    : isResHibernated
                                    ? 'bg-sky-400'
                                    : 'bg-slate-400'
                                }`} />
                                {isResActive ? 'Activo' : isResHibernated ? 'Hibernado' : 'Detenido'}
                              </span>
                              <span className="text-slate-400 font-mono text-xs">{Array.isArray(res.ports) ? res.ports.join(', ') : (res.ports || res.port || '-')}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Default Pods */}
                      <div className="flex items-center justify-between p-4 rounded-xl border border-slate-200 hover:border-slate-300 transition-colors bg-white">
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center text-blue-600">
                            <Cpu className="w-5 h-5" />
                          </div>
                          <div>
                            <div className="font-medium text-slate-900">Entorno de Desarrollo</div>
                            <div className="text-xs text-slate-500">Node.js / Hot Reloading</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-4 text-sm">
                          <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${
                            project.status === 'active' && project.localRunning
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
                              : project.status === 'hibernated'
                              ? 'bg-sky-50 text-sky-700 border-sky-100'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              project.status === 'active' && project.localRunning
                                ? 'bg-emerald-500 animate-pulse'
                                : project.status === 'hibernated'
                                ? 'bg-sky-400'
                                : 'bg-slate-400'
                            }`} />
                            {project.status === 'active' && project.localRunning ? 'Activo' : project.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                          </span>
                          <span className="text-slate-400 font-mono text-xs">:{project.forgePort}</span>
                        </div>
                      </div>
                      <div className="flex items-center justify-between p-4 rounded-xl border border-slate-200 hover:border-slate-300 transition-colors bg-white">
                        <div className="flex items-center gap-4">
                          <div className="w-10 h-10 rounded-lg bg-emerald-50 flex items-center justify-center text-emerald-600">
                            <Server className="w-5 h-5" />
                          </div>
                          <div>
                            <div className="font-medium text-slate-900">Entorno de Producción</div>
                            <div className="text-xs text-slate-500">Dockerizado / Optimizado</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-4 text-sm">
                          <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${
                            project.status === 'active'
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-100'
                              : project.status === 'hibernated'
                              ? 'bg-sky-50 text-sky-700 border-sky-100'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              project.status === 'active'
                                ? 'bg-emerald-500'
                                : project.status === 'hibernated'
                                ? 'bg-sky-400'
                                : 'bg-slate-400'
                            }`} />
                            {project.status === 'active' ? 'Activo' : project.status === 'hibernated' ? 'Hibernado' : 'Detenido'}
                          </span>
                          <span className="text-slate-400 font-mono text-xs">:{project.citadelPort}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-6">
              {/* Traffic Split */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 className="font-semibold text-slate-900 mb-6 flex items-center gap-2">
                  <Activity className="w-5 h-5 text-blue-500" /> Control de Tráfico
                </h3>
                <div className="space-y-5">
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span className="text-slate-600 font-medium">Entorno de Desarrollo</span>
                      <span className="font-bold text-slate-900">{project.trafficSplit?.forge || 0}%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-blue-500 h-2.5 rounded-full" style={{ width: `${project.trafficSplit?.forge || 0}%` }}></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span className="text-slate-600 font-medium">Entorno de Producción</span>
                      <span className="font-bold text-slate-900">{project.trafficSplit?.citadel || 0}%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-emerald-500 h-2.5 rounded-full" style={{ width: `${project.trafficSplit?.citadel || 0}%` }}></div>
                    </div>
                  </div>
                  <div className="pt-4 border-t border-slate-100">
                    <button className="w-full py-2 bg-slate-900 text-white rounded-xl text-sm font-medium hover:bg-slate-800 transition-colors shadow-sm">
                      Publicar a Producción
                    </button>
                  </div>
                </div>
              </div>

              {/* Quick Access */}
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <h3 className="font-semibold text-slate-900 mb-4 flex items-center gap-2">
                  <Globe className="w-5 h-5 text-slate-400" /> Dominios y Acceso
                </h3>
                <div className="space-y-3">
                  {project.domains && project.domains.length > 0 ? (
                    project.domains.map((d: any) => (
                      <div key={d} className="flex items-center justify-between p-3 bg-slate-50 border border-slate-200 rounded-xl">
                        <span className="text-sm font-medium text-slate-700 truncate">{d}</span>
                        <div className="flex items-center gap-1">
                          <button onClick={() => copyToClipboard(d)} className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-white rounded-md transition-colors"><Copy className="w-4 h-4" /></button>
                          <a href={`https://${d}`} target="_blank" rel="noreferrer" className="p-1.5 text-blue-500 hover:text-blue-700 hover:bg-blue-50 rounded-md transition-colors"><Globe className="w-4 h-4" /></a>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-slate-500 p-4 bg-slate-50 border border-slate-100 rounded-xl text-center">
                      No hay dominios configurados.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="h-[650px]">
            <LiveLogs incomingLog={incomingLog} projectId={project.id} />
          </div>
        )}

        {activeTab === 'domains' && (
          <DomainManager 
            onNotify={onNotify} 
            projectId={project.id} 
            projectDomains={project.domains || []}
            // Vincular y desvincular ya son una sola llamada al servidor
            // (registro del dominio + ruta en Caddy), así que aquí solo queda
            // refrescar. Antes el panel escribía `project.domains` por su
            // cuenta y nadie publicaba la ruta.
            onDomainAddedToProject={() => fetchProject()}
            onDomainRemovedFromProject={() => fetchProject()}
          />
        )}

        {activeTab === 'databases' && (
          <DatabasesPanel projectId={project.id} onNotify={onNotify} />
        )}

        {activeTab === 'vars' && (
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-6 border-b border-slate-100 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-50/50">
              <div>
                <h3 className="font-semibold text-slate-900 text-lg flex items-center gap-2">
                  <Variable className="w-5 h-5 text-indigo-500" /> Variables de Entorno
                </h3>
                <p className="text-sm text-slate-500 mt-1">Configura las variables secretas y de entorno para tus contenedores.</p>
              </div>
              <div className="flex items-center bg-slate-200/50 p-1 rounded-xl">
                <button onClick={() => setEnvMode('table')} className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${envMode === 'table' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}>Tabla Visual</button>
                <button onClick={() => setEnvMode('raw')} className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${envMode === 'raw' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}>.env Crudo</button>
              </div>
            </div>

            <div className="p-6">
              {envMode === 'table' ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="relative flex-1">
                      <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        placeholder="Buscar variable..."
                        value={searchVar}
                        onChange={e => setSearchVar(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                      />
                    </div>
                    <button onClick={() => setEnvRows([{ key: '', value: '', id: `new_${Date.now()}` }, ...envRows])} className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-xl text-sm font-medium shadow-sm transition-all">
                      <Plus className="w-4 h-4" /> Añadir Variable
                    </button>
                  </div>
                  
                  <div className="border border-slate-200 rounded-xl overflow-hidden">
 <div className="grid grid-cols-[1fr_2fr_auto] gap-4 bg-slate-50 p-3 border-b border-slate-200 text-xs font-semibold text-slate-500">
                      <div>Clave (KEY)</div>
                      <div>Valor (VALUE)</div>
                      <div className="w-24 text-center">Acciones</div>
                    </div>
                    <div className="divide-y divide-slate-100 max-h-[500px] overflow-y-auto">
                      {envRows.filter(r => r.key.toLowerCase().includes(searchVar.toLowerCase()) || searchVar === '').length === 0 && (
                        <div className="p-8 text-center text-slate-500 text-sm">No se encontraron variables.</div>
                      )}
                      {envRows.filter(r => r.key.toLowerCase().includes(searchVar.toLowerCase()) || searchVar === '').map((row) => (
                        <div key={row.id} className="grid grid-cols-[1fr_2fr_auto] gap-4 p-3 items-center hover:bg-slate-50/50 transition-colors group">
                          <input
                            type="text"
                            value={row.key}
                            onChange={e => {
                              const newRows = [...envRows];
                              const idx = newRows.findIndex(r => r.id === row.id);
                              newRows[idx].key = e.target.value;
                              setEnvRows(newRows);
                            }}
                            placeholder="API_KEY"
                            className="w-full px-3 py-1.5 border border-transparent hover:border-slate-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 rounded-lg text-sm font-mono transition-all bg-transparent focus:bg-white"
                          />
                          <div className="relative flex items-center">
                            <input
                              type={showValues[row.id] ? 'text' : 'password'}
                              value={row.value}
                              onChange={e => {
                                const newRows = [...envRows];
                                const idx = newRows.findIndex(r => r.id === row.id);
                                newRows[idx].value = e.target.value;
                                setEnvRows(newRows);
                              }}
                              placeholder="valor_secreto_123"
                              className="w-full pl-3 pr-10 py-1.5 border border-transparent hover:border-slate-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 rounded-lg text-sm font-mono transition-all bg-transparent focus:bg-white"
                            />
                            <button
                              onClick={() => setShowValues(prev => ({ ...prev, [row.id]: !prev[row.id] }))}
                              className="absolute right-2 p-1 text-slate-400 hover:text-slate-600 rounded"
                            >
                              {showValues[row.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          </div>
                          <div className="flex items-center justify-center gap-1 w-24 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button onClick={() => copyToClipboard(row.value)} className="p-1.5 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors" title="Copiar valor"><Copy className="w-4 h-4" /></button>
                            <button onClick={() => setEnvRows(envRows.filter(r => r.id !== row.id))} className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors" title="Eliminar"><Trash2 className="w-4 h-4" /></button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="flex justify-end pt-4">
                    <button onClick={handleSaveEnvTable} className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-xl text-sm font-medium shadow-sm transition-all">
                      <Save className="w-4 h-4" /> Guardar Cambios
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex justify-between items-center text-sm text-slate-500">
                    <p>Pega el contenido de tu archivo <code className="bg-slate-100 px-1 rounded text-slate-700">.env</code> aquí.</p>
                    <button className="flex items-center gap-1.5 hover:text-slate-900 transition-colors"><Upload className="w-4 h-4" /> Importar archivo</button>
                  </div>
                  <textarea
                    value={envText}
                    onChange={e => setEnvText(e.target.value)}
                    className="w-full h-[400px] p-4 bg-slate-50 text-slate-900 border border-slate-200 rounded-xl font-mono text-sm leading-relaxed focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 resize-none shadow-inner"
                    placeholder="PORT=3000&#10;DATABASE_URL=postgres://user:pass@localhost:5432/db"
                    spellCheck="false"
                  />
                  <div className="flex justify-end pt-4">
                    <button onClick={handleSaveEnvRaw} className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-xl text-sm font-medium shadow-sm transition-all">
                      <CheckCircle2 className="w-4 h-4" /> Guardar Variables
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'storage' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-4">
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-bold text-slate-900 flex items-center gap-2 text-lg"><Database className="w-5 h-5"/> Volúmenes Persistentes</h3>
                <button className="text-sm font-medium text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-sm flex items-center gap-1">
                  <Plus className="w-4 h-4" /> Añadir Volumen
                </button>
              </div>
              <div className="border border-slate-200 rounded-xl overflow-hidden">
 <div className="grid grid-cols-[1.5fr_1fr_1fr] gap-4 bg-slate-50 p-3 border-b border-slate-200 text-xs font-semibold text-slate-500">
                  <div>Nombre</div>
                  <div>Ruta Contenedor (Mount)</div>
                  <div>Ruta Host</div>
                </div>
                <div className="divide-y divide-slate-100">
                  {(!project.volumes || project.volumes.length === 0) && (
                    <div className="p-8 text-center text-slate-500 text-sm">No hay volúmenes configurados.</div>
                  )}
                  {project.volumes?.map((vol, i) => (
                    <div key={i} className="grid grid-cols-[1.5fr_1fr_1fr] gap-4 p-3 items-center text-sm">
                      <div className="font-medium text-slate-700">{vol.name || `Volumen ${i+1}`}</div>
                      <div className="font-mono text-slate-500">{vol.mount_path || vol.mountPath || '/data'}</div>
                      <div className="font-mono text-slate-500">{vol.host_path || vol.hostPath || '-'}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-4">
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-bold text-slate-900 flex items-center gap-2 text-lg"><Box className="w-5 h-5"/> Archivos Montados (File Mounts)</h3>
                <button className="text-sm font-medium text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-3 py-1.5 rounded-lg shadow-sm flex items-center gap-1">
                  <Plus className="w-4 h-4" /> Montar Archivo
                </button>
              </div>
              <div className="border border-slate-200 rounded-xl overflow-hidden">
 <div className="grid grid-cols-[2fr_1fr] gap-4 bg-slate-50 p-3 border-b border-slate-200 text-xs font-semibold text-slate-500">
                  <div>Ruta de Montaje</div>
                  <div>Permisos (chmod / chown)</div>
                </div>
                <div className="divide-y divide-slate-100">
                  {(!project.fileMounts || project.fileMounts.length === 0) && (
                    <div className="p-8 text-center text-slate-500 text-sm">No hay archivos montados.</div>
                  )}
                  {project.fileMounts?.map((fm, i) => (
                    <div key={i} className="grid grid-cols-[2fr_1fr] gap-4 p-3 items-center text-sm">
                      <div className="font-mono text-slate-700">{fm.mountPath || fm.mount_path || '/etc/config.json'}</div>
                      <div className="font-mono text-slate-500 text-xs bg-slate-100 px-2 py-1 rounded inline-block w-max">
                        chmod {fm.chmod || '644'} &bull; chown {fm.chown || 'root:root'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'config' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-4">
              <h3 className="font-bold text-slate-900 flex items-center gap-2 text-lg"><Settings className="w-5 h-5"/> Configuración del Proyecto</h3>
              <form onSubmit={async (e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                const wp = formData.get('watchPaths') as string || '';
                const updates = {
                  name: formData.get('name'),
                  description: formData.get('description'),
                  icon: formData.get('icon'),
                  gitRepo: formData.get('gitRepo'),
                  gitBranch: formData.get('gitBranch'),
                  buildCommand: formData.get('buildCommand'),
                  startCommand: formData.get('startCommand'),
                  baseDirectory: formData.get('baseDirectory'),
                  watchPaths: wp.split(',').map(s => s.trim()).filter(Boolean)
                };
                try {
                  await api.updateProject(projectId, updates);
                  onNotify('Configuración guardada correctamente');
                  fetchProject();
                } catch (err) {
                  onNotify('Error al guardar configuración');
                }
              }} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Nombre</label>
                    <input name="name" defaultValue={project.name} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Icono (Emoji)</label>
                    <input name="icon" defaultValue={project.icon} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" />
                  </div>
                  <div className="col-span-2">
                    <label className="block text-sm font-medium text-slate-700 mb-1">Descripción</label>
                    <textarea name="description" defaultValue={project.description} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" rows={2} />
                  </div>
                  <div className="col-span-2">
                    <h4 className="font-medium text-slate-900 mt-4 mb-2">Repositorio Git</h4>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">URL del Repositorio</label>
                    <input name="gitRepo" defaultValue={project.gitRepo} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" placeholder="https://github.com/..." />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Rama (Branch)</label>
                    <input name="gitBranch" defaultValue={project.gitBranch} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" placeholder="main" />
                  </div>
                  <div className="col-span-2">
                    <h4 className="font-medium text-slate-900 mt-4 mb-2">Pipeline y Despliegue</h4>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Directorio Base</label>
                    <input name="baseDirectory" defaultValue={project.baseDirectory} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" placeholder="/" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Rutas Vigiladas (Watch Paths)</label>
                    <input name="watchPaths" defaultValue={(project.watchPaths || []).join(', ')} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" placeholder="src/**, backend/src/**" />
                    <p className="text-xs text-slate-500 mt-1">Vital para el motor de hot-sync. Separadas por comas.</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Comando Build</label>
                    <input name="buildCommand" defaultValue={project.buildCommand} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" placeholder="npm run build" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Comando Start</label>
                    <input name="startCommand" defaultValue={project.startCommand} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm" placeholder="npm start" />
                  </div>
                </div>
                <div className="flex justify-end pt-4 border-t border-slate-100">
                  <button type="submit" className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-medium shadow-sm transition-colors flex items-center gap-2">
                    <Save className="w-4 h-4" /> Guardar Configuración
                  </button>
                </div>
              </form>
            </div>

            {/* Webhook de GitHub para Despliegue Automático */}
            <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-blue-50 text-blue-600 rounded-xl border border-blue-100 flex items-center justify-center">
                    <Webhook className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-bold text-slate-900 text-lg">
                      Webhook de GitHub para Despliegue Automático
                    </h3>
                    <p className="text-sm text-slate-500">
                      Sincroniza y despliega automáticamente tu aplicación en tiempo real en cada <code className="text-xs bg-slate-100 px-1 py-0.5 rounded font-mono">git push</code>
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      const nextState = project.autoDeploy === false ? true : false;
                      try {
                        await api.updateProject(projectId, { autoDeploy: nextState });
                        onNotify(`Auto-despliegue ${nextState ? 'activado' : 'desactivado'}`);
                        fetchProject();
                      } catch (e) {
                        onNotify('Error al actualizar estado');
                      }
                    }}
                    className={`px-3 py-1.5 rounded-full text-xs font-semibold flex items-center gap-1.5 transition-colors ${project.autoDeploy !== false ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100' : 'bg-slate-100 text-slate-600 border border-slate-200 hover:bg-slate-200'}`}
                  >
                    <span className={`w-2 h-2 rounded-full ${project.autoDeploy !== false ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                    {project.autoDeploy !== false ? 'Auto-Deploy Activo' : 'Auto-Deploy Desactivado'}
                  </button>
                </div>
              </div>

              <div className="space-y-4">
                <div>
 <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                    URL del Webhook (Payload URL)
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      readOnly
                      value={`${window.location.origin}/api/webhooks/github?projectId=${project.id}`}
                      className="flex-1 px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-700 select-all"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        const url = `${window.location.origin}/api/webhooks/github?projectId=${project.id}`;
                        navigator.clipboard.writeText(url);
                        setCopiedUrl(true);
                        setTimeout(() => setCopiedUrl(false), 2000);
                        onNotify('URL del Webhook copiada al portapapeles');
                      }}
                      className="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-xl text-xs flex items-center gap-1.5 transition-colors"
                    >
                      {copiedUrl ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                      {copiedUrl ? '¡Copiado!' : 'Copiar URL'}
                    </button>
                  </div>
                </div>

                <div>
                  <div className="flex justify-between items-center mb-1.5">
 <label className="block text-xs font-semibold text-slate-700">
                      Secreto del Webhook (Secret)
                    </label>
                    <button
                      type="button"
                      onClick={async () => {
                        const newSecret = Array.from(crypto.getRandomValues(new Uint8Array(16)))
                          .map(b => b.toString(16).padStart(2, '0'))
                          .join('');
                        try {
                          await api.updateProject(projectId, { webhookSecret: newSecret });
                          onNotify('Nuevo secreto de webhook generado y guardado');
                          fetchProject();
                        } catch (e) {
                          onNotify('Error al regenerar secreto');
                        }
                      }}
                      className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1 hover:underline"
                    >
                      <RefreshCw className="w-3 h-3" /> Regenerar secreto
                    </button>
                  </div>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        readOnly
                        value={project.webhookSecret || 'culkibo_default_webhook_secret'}
                        className="w-full px-3.5 py-2.5 pr-10 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-700 select-all"
                      />
                      <button
                        type="button"
                        onClick={() => setShowSecret(!showSecret)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                        title={showSecret ? 'Ocultar secreto' : 'Mostrar secreto'}
                      >
                        {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        const sec = project.webhookSecret || 'culkibo_default_webhook_secret';
                        navigator.clipboard.writeText(sec);
                        setCopiedSecret(true);
                        setTimeout(() => setCopiedSecret(false), 2000);
                        onNotify('Secreto de Webhook copiado al portapapeles');
                      }}
                      className="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-xl text-xs flex items-center gap-1.5 transition-colors"
                    >
                      {copiedSecret ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                      {copiedSecret ? '¡Copiado!' : 'Copiar Secreto'}
                    </button>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3.5 bg-slate-50 rounded-xl border border-slate-200/80 gap-3">
                  <div>
                    <div className="text-xs font-semibold text-slate-800">
                      Rama monitoreada para despliegue
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      Solo los pushes a esta rama dispararán el pipeline automatizado en tiempo real.
                    </div>
                  </div>
                  <span className="px-2.5 py-1 bg-white border border-slate-300 rounded-lg text-xs font-mono font-semibold text-slate-800 flex items-center gap-1">
                    <GitBranch className="w-3.5 h-3.5 text-blue-600" />
                    {project.gitBranch || 'main'}
                  </span>
                </div>

                {project.lastCommit && (
                  <div className="p-3.5 bg-emerald-50/80 border border-emerald-200 rounded-xl text-xs space-y-1">
                    <div className="font-semibold text-emerald-900 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                      Último push desplegado automáticamente
                    </div>
                    <div className="text-slate-700 text-xs">
                      <span className="font-mono bg-white px-1.5 py-0.5 rounded border border-emerald-200 text-emerald-800 font-semibold mr-1.5">
                        {project.lastCommit.sha}
                      </span>
                      {project.lastCommit.message}
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Por <strong>{project.lastCommit.author}</strong> &bull; {new Date(project.lastCommit.timestamp).toLocaleString('es-ES')}
                    </div>
                  </div>
                )}

                <div className="p-4 bg-blue-50/50 border border-blue-100 rounded-xl text-xs text-slate-600 space-y-1.5">
                  <div className="font-semibold text-slate-900">Instrucciones de configuración en GitHub:</div>
                  <ol className="list-decimal list-inside space-y-1 text-slate-600">
                    <li>Abre tu repositorio en GitHub y ve a <strong>Settings &gt; Webhooks &gt; Add webhook</strong>.</li>
                    <li>Pega la <strong>URL del Webhook</strong> copiada arriba en el campo <strong>Payload URL</strong>.</li>
                    <li>Selecciona <strong>Content type:</strong> <code>application/json</code>.</li>
                    <li>Pega el <strong>Secreto</strong> en el campo <strong>Secret</strong>.</li>
                    <li>En eventos, deja seleccionado <strong>Just the push event</strong> y haz clic en <strong>Add webhook</strong>.</li>
                  </ol>
                  {window.location.hostname === 'localhost' && (
                    <div className="mt-2 p-2.5 bg-amber-50 border border-amber-200 rounded-lg text-amber-800 text-[11px]">
                      <strong>💡 Nota de entorno local:</strong> Para recibir webhooks reales directamente desde GitHub a este equipo, utiliza un túnel público (como Cloudflare Tunnel o ngrok) y reemplaza <code>{window.location.origin}</code> por la URL pública del túnel.
                    </div>
                  )}
                </div>

                {/* Test simulation button */}
                <div className="flex justify-end pt-1">
                  <button
                    type="button"
                    onClick={handleSimulatePush}
                    disabled={simulatingWebhook}
                    className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold rounded-xl text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${simulatingWebhook ? 'animate-spin text-blue-600' : ''}`} />
                    {simulatingWebhook ? 'Simulando push...' : 'Probar Webhook (Simular Push)'}
                  </button>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-red-200 shadow-sm space-y-4">
              <h3 className="font-bold text-red-600 flex items-center gap-2 text-lg"><ShieldAlert className="w-5 h-5"/> Zona de Peligro</h3>
              <p className="text-sm text-slate-600 max-w-2xl">Al eliminar este proyecto, se detendrán todos los contenedores asociados, se eliminarán las variables de entorno y los datos en volúmenes. Esta acción no se puede deshacer.</p>
              <div className="pt-2">
                <button onClick={handleDelete} className="px-5 py-2.5 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-xl text-sm font-bold flex items-center gap-2 transition-colors">
                  <Trash2 className="w-4 h-4" /> Eliminar Proyecto Definitivamente
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {showAddService && (
        <div className="fixed inset-0 bg-slate-900/50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-xl animate-in fade-in zoom-in-95 duration-200">
            <h3 className="text-xl font-bold text-slate-900 mb-4">Añadir Servicio</h3>
            <form onSubmit={handleAddService} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Nombre del Servicio</label>
                <input required type="text" value={newService.name} onChange={e => setNewService({...newService, name: e.target.value})} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20" placeholder="Ej: mi-bd-postgres" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Tipo</label>
                <select value={newService.type} onChange={e => setNewService({...newService, type: e.target.value})} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20">
                  <option>Aplicación Web</option>
                  <option>Base de Datos PostgreSQL</option>
                  <option>Redis</option>
                  <option>MongoDB</option>
                  <option>Docker Compose</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Puerto</label>
                <input required type="text" value={newService.port} onChange={e => setNewService({...newService, port: e.target.value})} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20" placeholder="Ej: 5432" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Imagen o Repositorio Git</label>
                <input required type="text" value={newService.image} onChange={e => setNewService({...newService, image: e.target.value})} className="w-full px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20" placeholder="Ej: postgres:15-alpine" />
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <button type="button" onClick={() => setShowAddService(false)} className="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors">Cancelar</button>
                <button type="submit" className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-sm font-medium transition-colors shadow-sm">Añadir Servicio</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
