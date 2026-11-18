import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Search, Package, Play, Square, RotateCw, Trash2, ExternalLink, KeyRound,
  ScrollText, AlertTriangle, Check, Copy, X, Globe, Cpu, HardDrive, Info,
  CircleCheck, CircleAlert, Loader2
} from 'lucide-react';
import {
  api,
  type ServiceTemplate,
  type ServiceCategory,
  type ServiceInstallation,
  type ServiceSecrets
} from '../lib/api';

interface Props {
  onNotify: (msg: string) => void;
}

/**
 * Estado visual de una instalación.
 *
 * Los textos son sustantivos y adjetivos en minúscula, no imperativos ni
 * versalitas: en español las mayúsculas de estilo son una falta de ortografía y
 * a 11 px las tildes de «Instalación» desaparecen. La jerarquía la da el peso.
 */
const STATUS_STYLE: Record<string, { dot: string; label: string; text: string }> = {
  installing: { dot: 'bg-slate-400 animate-pulse', label: 'Instalando', text: 'text-slate-600' },
  running: { dot: 'bg-emerald-500', label: 'En marcha', text: 'text-emerald-700' },
  degraded: { dot: 'bg-amber-500', label: 'Arrancó sin responder', text: 'text-amber-700' },
  stopped: { dot: 'bg-slate-300', label: 'Detenido', text: 'text-slate-500' },
  error: { dot: 'bg-red-500', label: 'Con errores', text: 'text-red-700' }
};

function formatMemory(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(mb % 1024 === 0 ? 0 : 1)} GB` : `${mb} MB`;
}

// ---------------------------------------------------------------------------

export const ServiceCatalog: React.FC<Props> = ({ onNotify }) => {
  const [tab, setTab] = useState<'catalogo' | 'instalados'>('catalogo');
  const [templates, setTemplates] = useState<ServiceTemplate[]>([]);
  const [categories, setCategories] = useState<ServiceCategory[]>([]);
  const [installations, setInstallations] = useState<ServiceInstallation[]>([]);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [chosen, setChosen] = useState<ServiceTemplate | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [secrets, setSecrets] = useState<Record<string, ServiceSecrets>>({});
  const [logs, setLogs] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<ServiceInstallation | null>(null);

  const loadRef = useRef<() => void>(() => {});

  const load = async () => {
    try {
      const [cat, inst] = await Promise.all([api.getCatalog(), api.getInstallations()]);
      setTemplates(cat.templates);
      setCategories(cat.categories);
      setInstallations(inst.installations);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'No se pudo cargar el catálogo');
    } finally {
      setLoading(false);
    }
  };
  loadRef.current = load;

  useEffect(() => { load(); }, []);

  // Mientras haya algo instalándose se refresca solo. El progreso llega también
  // por WebSocket, pero el sondeo es lo que hace que recargar la página no
  // pierda el hilo de una instalación que lleva tres minutos descargando.
  const installing = installations.some((i) => i.status === 'installing');
  useEffect(() => {
    if (!installing) return;
    const timer = setInterval(() => loadRef.current(), 1500);
    return () => clearInterval(timer);
  }, [installing]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return templates.filter((t) => {
      if (category && t.category !== category) return false;
      if (!needle) return true;
      return (
        t.name.toLowerCase().includes(needle) ||
        t.summary.toLowerCase().includes(needle) ||
        t.description.toLowerCase().includes(needle) ||
        t.tags.some((tag) => tag.includes(needle))
      );
    });
  }, [templates, query, category]);

  const guard = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Ha ocurrido un error');
    } finally {
      setBusy(null);
    }
  };

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1800);
  };

  const handleInstall = async (template: ServiceTemplate, name: string, domain: string) => {
    setChosen(null);
    await guard(`install-${template.id}`, async () => {
      await api.installService({
        templateId: template.id,
        name: name.trim() || template.name,
        domain: domain.trim() || null
      });
      onNotify(`Instalando ${template.name}. El progreso se ve en «Instalados».`);
      setTab('instalados');
      await load();
    });
  };

  const toggleSecrets = (inst: ServiceInstallation) => guard(`sec-${inst.id}`, async () => {
    if (secrets[inst.id]) {
      const next = { ...secrets };
      delete next[inst.id];
      setSecrets(next);
      return;
    }
    setSecrets({ ...secrets, [inst.id]: await api.getInstallationSecrets(inst.id) });
  });

  const toggleLogs = (inst: ServiceInstallation) => guard(`log-${inst.id}`, async () => {
    if (logs[inst.id]) {
      const next = { ...logs };
      delete next[inst.id];
      setLogs(next);
      return;
    }
    const res = await api.getInstallationLogs(inst.id, 300);
    setLogs({ ...logs, [inst.id]: res.output || '(sin salida)' });
  });

  // -------------------------------------------------------------------------

  if (loading) {
    return (
      <div className="flex items-center gap-2.5 text-sm text-slate-500 py-16 justify-center">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Cargando el catálogo…</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {loadError && (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-amber-900">No se pudo cargar el catálogo</p>
            <p className="text-amber-800">{loadError}</p>
          </div>
        </div>
      )}

      {/* Cabecera y pestañas. gap generoso: «Servicios instalados» en español
          mide casi el doble que «Installed», y una pastilla de ancho fijo
          cortaría la palabra. */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 tracking-tight">Catálogo de servicios</h2>
          <p className="text-sm text-slate-500 mt-1 max-w-2xl">
            Servicios listos para usar, con la imagen fijada a una versión concreta, límites de recursos,
            volumen persistente y contraseñas generadas al instalar.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {([
            { id: 'catalogo', label: 'Catálogo', count: templates.length },
            { id: 'instalados', label: 'Servicios instalados', count: installations.length }
          ] as const).map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors cursor-pointer ${
                tab === t.id
                  ? 'bg-slate-100 text-slate-900 border-slate-200 shadow-sm'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50 border-transparent'
              }`}
            >
              <span>{t.label}</span>
              <span className={`text-xs tabular-nums rounded-md px-1.5 py-0.5 ${tab === t.id ? 'bg-white text-slate-600 border border-slate-200' : 'bg-slate-100 text-slate-500'}`}>
                {t.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {tab === 'catalogo' && (
        <>
          <div className="flex flex-col lg:flex-row gap-3">
            <div className="relative flex-1 min-w-0">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Buscar por nombre, descripción o etiqueta…"
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-200 bg-white text-sm text-slate-900 placeholder:text-slate-400 shadow-xs"
              />
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setCategory(null)}
                className={`px-3 py-2 rounded-lg text-sm font-medium border transition-colors cursor-pointer whitespace-nowrap ${
                  category === null ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                Todas
              </button>
              {categories.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setCategory(c.id === category ? null : c.id)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium border transition-colors cursor-pointer whitespace-nowrap ${
                    category === c.id ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          {visible.length === 0 ? (
            <div className="text-center py-16 text-sm text-slate-500">
              No hay ningún servicio que encaje con «{query}».
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {visible.map((t) => (
                <article
                  key={t.id}
                  className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col gap-3 hover:shadow-sm transition-shadow"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="font-semibold text-slate-900 leading-tight">{t.name}</h3>
                      <p className="text-xs text-slate-500 mt-0.5">{t.categoryLabel}</p>
                    </div>
                    {t.installedCount > 0 && (
                      <span className="shrink-0 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-2 py-1">
                        {t.installedCount} instalado{t.installedCount > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>

                  <p className="text-sm text-slate-600 leading-relaxed flex-1">{t.summary}</p>

                  <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs text-slate-500 border-t border-slate-100 pt-3">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <HardDrive className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                      <span className="truncate">{formatMemory(t.totalMemoryMb)} de memoria</span>
                    </div>
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Cpu className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                      <span className="truncate">{t.cpus} CPU</span>
                    </div>
                    <div className="col-span-2 flex items-center gap-1.5 min-w-0">
                      <Package className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                      <code className="font-mono text-[11px] truncate text-slate-500">{t.image}</code>
                    </div>
                  </dl>

                  <div className="flex items-center justify-between gap-3 pt-1">
                    <span className="text-xs text-slate-400 truncate" title={t.licence}>{t.licence}</span>
                    <button
                      onClick={() => setChosen(t)}
                      className="shrink-0 px-4 py-2 rounded-lg text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 transition-colors cursor-pointer"
                    >
                      Instalar
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </>
      )}

      {tab === 'instalados' && (
        <InstalledList
          installations={installations}
          busy={busy}
          secrets={secrets}
          logs={logs}
          copied={copied}
          onCopy={copy}
          onToggleSecrets={toggleSecrets}
          onToggleLogs={toggleLogs}
          onControl={(inst, action) => guard(`ctl-${inst.id}`, async () => {
            await api.controlInstallation(inst.id, action);
            await load();
          })}
          onRefreshHealth={(inst) => guard(`hp-${inst.id}`, async () => {
            await api.refreshInstallationHealth(inst.id);
            await load();
          })}
          onRemove={setConfirmRemove}
          onBrowse={() => setTab('catalogo')}
        />
      )}

      {chosen && (
        <InstallDialog
          template={chosen}
          onCancel={() => setChosen(null)}
          onConfirm={handleInstall}
        />
      )}

      {confirmRemove && (
        <RemoveDialog
          installation={confirmRemove}
          onCancel={() => setConfirmRemove(null)}
          onConfirm={async (deleteVolumes) => {
            const inst = confirmRemove;
            setConfirmRemove(null);
            await guard(`rm-${inst.id}`, async () => {
              await api.removeInstallation(inst.id, deleteVolumes);
              onNotify(
                deleteVolumes
                  ? `${inst.name} desinstalado y sus datos borrados.`
                  : `${inst.name} desinstalado. Sus volúmenes se conservan.`
              );
              await load();
            });
          }}
        />
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Diálogo de instalación
// ---------------------------------------------------------------------------

const InstallDialog: React.FC<{
  template: ServiceTemplate;
  onCancel: () => void;
  onConfirm: (t: ServiceTemplate, name: string, domain: string) => void;
}> = ({ template, onCancel, onConfirm }) => {
  const [name, setName] = useState(template.name);
  const [domain, setDomain] = useState('');

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/20 backdrop-blur-[2px] flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-xl w-full max-w-2xl my-8">
        <header className="flex items-start justify-between gap-4 px-6 py-5 border-b border-slate-100">
          <div className="min-w-0">
            <h3 className="font-semibold text-slate-900">Instalar {template.name}</h3>
            <p className="text-sm text-slate-500 mt-1">{template.description}</p>
          </div>
          <button onClick={onCancel} className="shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-slate-900 hover:bg-slate-100 cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </header>

        <div className="px-6 py-5 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <label className="block">
              <span className="text-sm font-medium text-slate-700">Nombre</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-1.5 w-full px-3 py-2 rounded-lg border border-slate-200 text-sm text-slate-900"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-700">Dominio</span>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={`${template.id}.midominio.com`}
                className="mt-1.5 w-full px-3 py-2 rounded-lg border border-slate-200 text-sm text-slate-900 placeholder:text-slate-400 font-mono"
              />
            </label>
          </div>

          <div className="flex items-start gap-2.5 text-sm text-slate-600 bg-slate-50 border border-slate-200 rounded-xl p-3.5">
            <Globe className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              Con un dominio, el servicio se publica con HTTPS automático: apunta antes un registro A
              a la IP de este servidor. Sin dominio, queda accesible sólo desde el propio servidor en
              un puerto local, y podrás añadirle uno después.
            </p>
          </div>

          <div>
            <h4 className="text-sm font-medium text-slate-700 mb-2">Qué se va a crear</h4>
            <ul className="text-sm text-slate-600 space-y-1.5">
              <li className="flex items-start gap-2">
                <Package className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                <span>
                  Un contenedor con <code className="font-mono text-xs text-slate-700">{template.image}</code>,
                  limitado a {formatMemory(template.memoryMb)} y {template.cpus} CPU.
                </span>
              </li>
              {template.database && (
                <li className="flex items-start gap-2">
                  <HardDrive className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                  <span>
                    Una base de datos {template.database.engine} gestionada, con contraseña generada
                    y copias programables como cualquier otra.
                  </span>
                </li>
              )}
              {template.sidecars.map((c) => (
                <li key={c.name} className="flex items-start gap-2">
                  <Package className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                  <span>
                    Un contenedor auxiliar «{c.name}» con <code className="font-mono text-xs text-slate-700">{c.image}</code>.
                  </span>
                </li>
              ))}
              {template.secretNames.length > 0 && (
                <li className="flex items-start gap-2">
                  <KeyRound className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                  <span>
                    {template.secretNames.length === 1 ? 'Un secreto generado' : `${template.secretNames.length} secretos generados`}{' '}
                    con entropía criptográfica: {template.secretNames.join(', ')}.
                  </span>
                </li>
              )}
              <li className="flex items-start gap-2">
                <Cpu className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                <span>Memoria total reservada: <strong className="font-semibold text-slate-800">{formatMemory(template.totalMemoryMb)}</strong>.</span>
              </li>
            </ul>
          </div>

          {template.notes.length > 0 && (
            <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5">
              <div className="flex items-center gap-2 mb-1.5">
                <Info className="w-4 h-4 text-amber-600 shrink-0" />
                <span className="text-sm font-semibold text-amber-900">Antes de instalar</span>
              </div>
              <ul className="text-sm text-amber-800 space-y-1 leading-relaxed">
                {template.notes.map((n, i) => <li key={i}>· {n}</li>)}
              </ul>
            </div>
          )}

          <p className="text-xs text-slate-500">
            {template.licence} · <a href={template.website} target="_blank" rel="noreferrer" className="underline hover:text-slate-900">{template.website}</a>
          </p>
        </div>

        <footer className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-100">
          <button onClick={onCancel} className="px-4 py-2 rounded-lg text-sm font-medium text-slate-600 hover:bg-slate-100 cursor-pointer">
            Cancelar
          </button>
          <button
            onClick={() => onConfirm(template, name, domain)}
            className="px-5 py-2 rounded-lg text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 cursor-pointer"
          >
            Instalar {template.name}
          </button>
        </footer>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Diálogo de desinstalación
// ---------------------------------------------------------------------------

const RemoveDialog: React.FC<{
  installation: ServiceInstallation;
  onCancel: () => void;
  onConfirm: (deleteVolumes: boolean) => void;
}> = ({ installation, onCancel, onConfirm }) => {
  const [deleteVolumes, setDeleteVolumes] = useState(false);

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/20 backdrop-blur-[2px] flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-xl w-full max-w-lg">
        <div className="px-6 py-5">
          <h3 className="font-semibold text-slate-900">Desinstalar {installation.name}</h3>
          <p className="text-sm text-slate-600 mt-2 leading-relaxed">
            Se eliminarán el contenedor, sus auxiliares y la red de la instalación. El dominio
            asociado se retirará del ingress.
          </p>

          <label className="flex items-start gap-3 mt-4 p-3.5 rounded-xl border border-slate-200 cursor-pointer hover:bg-slate-50">
            <input
              type="checkbox"
              checked={deleteVolumes}
              onChange={(e) => setDeleteVolumes(e.target.checked)}
              className="mt-0.5 w-4 h-4 accent-red-600"
            />
            <span className="text-sm">
              <span className="font-medium text-slate-900">Borrar también los datos</span>
              <span className="block text-slate-500 mt-0.5">
                Volúmenes, base de datos y copias de seguridad. Es irreversible y no hay forma de
                recuperarlo después.
              </span>
            </span>
          </label>

          {deleteVolumes && (
            <div className="mt-3 flex items-start gap-2.5 text-sm text-red-800 bg-red-50 border border-red-200 rounded-xl p-3.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
              <span>Vas a borrar permanentemente todos los datos de {installation.name}.</span>
            </div>
          )}
        </div>
        <footer className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-100">
          <button onClick={onCancel} className="px-4 py-2 rounded-lg text-sm font-medium text-slate-600 hover:bg-slate-100 cursor-pointer">
            Cancelar
          </button>
          <button
            onClick={() => onConfirm(deleteVolumes)}
            className={`px-5 py-2 rounded-lg text-sm font-semibold text-white cursor-pointer ${
              deleteVolumes ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-900 hover:bg-slate-800'
            }`}
          >
            {deleteVolumes ? 'Desinstalar y borrar los datos' : 'Desinstalar'}
          </button>
        </footer>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Lista de servicios instalados
// ---------------------------------------------------------------------------

const InstalledList: React.FC<{
  installations: ServiceInstallation[];
  busy: string | null;
  secrets: Record<string, ServiceSecrets>;
  logs: Record<string, string>;
  copied: string | null;
  onCopy: (text: string, key: string) => void;
  onToggleSecrets: (i: ServiceInstallation) => void;
  onToggleLogs: (i: ServiceInstallation) => void;
  onControl: (i: ServiceInstallation, action: 'start' | 'stop' | 'restart') => void;
  onRefreshHealth: (i: ServiceInstallation) => void;
  onRemove: (i: ServiceInstallation) => void;
  onBrowse: () => void;
}> = ({ installations, busy, secrets, logs, copied, onCopy, onToggleSecrets, onToggleLogs, onControl, onRefreshHealth, onRemove, onBrowse }) => {
  if (installations.length === 0) {
    return (
      <div className="text-center py-16 bg-white border border-slate-200 rounded-2xl">
        <Package className="w-8 h-8 text-slate-300 mx-auto" />
        <p className="text-sm text-slate-600 mt-3 font-medium">Todavía no hay ningún servicio instalado</p>
        <p className="text-sm text-slate-500 mt-1">Elige uno del catálogo y estará en marcha en un par de minutos.</p>
        <button onClick={onBrowse} className="mt-4 px-4 py-2 rounded-lg text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 cursor-pointer">
          Ver el catálogo
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {installations.map((inst) => {
        const style = STATUS_STYLE[inst.status] || STATUS_STYLE.stopped;
        const sec = secrets[inst.id];
        const log = logs[inst.id];

        return (
          <section key={inst.id} className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
            <div className="p-5 flex flex-col xl:flex-row xl:items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${style.dot}`} />
                  <h3 className="font-semibold text-slate-900">{inst.name}</h3>
                  <span className={`text-xs font-medium ${style.text}`}>{style.label}</span>
                  <span className="text-xs text-slate-400">·</span>
                  <span className="text-xs text-slate-500">{inst.templateName}</span>
                </div>

                <div className="mt-2 flex items-center gap-3 flex-wrap text-sm">
                  {inst.domain ? (
                    <a href={inst.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-slate-700 hover:text-slate-900 font-medium">
                      <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                      {inst.domain}
                    </a>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-slate-500">
                      <Globe className="w-3.5 h-3.5 text-slate-400" />
                      Sin dominio, accesible en 127.0.0.1:{inst.hostPort}
                    </span>
                  )}
                  <span className="text-xs text-slate-400 font-mono truncate">{inst.image}</span>
                </div>

                {inst.status === 'installing' && inst.progress && (
                  <ProgressBar progress={inst.progress} />
                )}

                {inst.ingress && !inst.ingress.applied && inst.domain && (
                  <p className="mt-3 text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-xl px-3.5 py-2.5 leading-relaxed">
                    El dominio está registrado pero no hay ruta publicada:{' '}
                    {inst.ingress.reason || 'no se pudo hablar con el plano de datos.'} Mientras tanto,
                    el servicio sigue accesible en 127.0.0.1:{inst.hostPort}.
                  </p>
                )}

                {inst.lastError && inst.status !== 'installing' && (
                  <p className="mt-3 text-sm text-red-800 bg-red-50 border border-red-200 rounded-xl px-3.5 py-2.5 leading-relaxed">
                    {inst.lastError}
                  </p>
                )}

                {inst.status === 'running' && inst.nextSteps.length > 0 && (
                  <ul className="mt-3 text-sm text-slate-600 space-y-1 leading-relaxed">
                    {inst.nextSteps.map((s, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <CircleCheck className="w-3.5 h-3.5 text-slate-300 shrink-0 mt-1" />
                        <span>{s}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {inst.status !== 'installing' && (
                <div className="flex items-center gap-2 flex-wrap shrink-0">
                  <IconButton label="Comprobar" icon={inst.health === 'healthy' ? CircleCheck : CircleAlert} onClick={() => onRefreshHealth(inst)} busy={busy === `hp-${inst.id}`} />
                  <IconButton label="Secretos" icon={KeyRound} onClick={() => onToggleSecrets(inst)} busy={busy === `sec-${inst.id}`} active={Boolean(sec)} />
                  <IconButton label="Registros" icon={ScrollText} onClick={() => onToggleLogs(inst)} busy={busy === `log-${inst.id}`} active={Boolean(log)} />
                  {inst.status === 'stopped' ? (
                    <IconButton label="Iniciar" icon={Play} onClick={() => onControl(inst, 'start')} busy={busy === `ctl-${inst.id}`} />
                  ) : (
                    <IconButton label="Detener" icon={Square} onClick={() => onControl(inst, 'stop')} busy={busy === `ctl-${inst.id}`} />
                  )}
                  <IconButton label="Reiniciar" icon={RotateCw} onClick={() => onControl(inst, 'restart')} busy={busy === `ctl-${inst.id}`} />
                  <IconButton label="Desinstalar" icon={Trash2} onClick={() => onRemove(inst)} danger />
                </div>
              )}
            </div>

            {sec && (
              <div className="border-t border-slate-100 bg-slate-50 px-5 py-4 space-y-2">
                <p className="text-sm font-medium text-slate-700">Credenciales generadas</p>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Sólo se muestran aquí. Guárdalas en tu gestor de contraseñas: no aparecen en el
                  listado ni en los registros.
                </p>
                {Object.entries(sec.secrets).map(([key, value]) => (
                  <SecretRow key={key} label={key} value={value} copied={copied === `${inst.id}-${key}`} onCopy={() => onCopy(value, `${inst.id}-${key}`)} />
                ))}
                {sec.database && (
                  <SecretRow
                    label="Cadena de conexión de la base de datos"
                    value={sec.database.internalConnectionString}
                    copied={copied === `${inst.id}-db`}
                    onCopy={() => onCopy(sec.database!.internalConnectionString, `${inst.id}-db`)}
                  />
                )}
                {Object.keys(sec.secrets).length === 0 && !sec.database && (
                  <p className="text-sm text-slate-500">Este servicio no genera ningún secreto.</p>
                )}
              </div>
            )}

            {log && (
              <div className="border-t border-slate-100 bg-slate-50 px-5 py-4">
                <pre className="text-xs font-mono text-slate-800 whitespace-pre-wrap max-h-80 overflow-y-auto leading-relaxed">{log}</pre>
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Piezas pequeñas
// ---------------------------------------------------------------------------

/**
 * Progreso real, no una ruleta.
 *
 * El paso y el mensaje vienen del backend: «Descargando ghcr.io/…» o «Esperando
 * respuesta en /api/health; quedan 94 s». Una barra indeterminada durante tres
 * minutos es indistinguible de un cuelgue, y eso es justo lo que hace que la
 * gente recargue la página a mitad de una instalación.
 */
const ProgressBar: React.FC<{ progress: NonNullable<ServiceInstallation['progress']> }> = ({ progress }) => {
  const pct = Math.round(((progress.stepIndex + 1) / progress.totalSteps) * 100);
  return (
    <div className="mt-3">
      <div className="flex items-baseline justify-between gap-3 mb-1.5">
        <span className="text-sm font-medium text-slate-700">{progress.label}</span>
        <span className="text-xs text-slate-500 tabular-nums shrink-0">paso {progress.stepIndex + 1} de {progress.totalSteps}</span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
        <div
          className={`h-full rounded-full transition-[width] duration-500 ${progress.failed ? 'bg-red-500' : 'bg-slate-800'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-xs text-slate-500 mt-1.5 leading-relaxed">{progress.message}</p>
    </div>
  );
};

const IconButton: React.FC<{
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  onClick: () => void;
  busy?: boolean;
  active?: boolean;
  danger?: boolean;
}> = ({ label, icon: Icon, onClick, busy, active, danger }) => (
  <button
    onClick={onClick}
    disabled={busy}
    title={label}
    className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium border transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap ${
      danger
        ? 'text-red-700 border-red-200 bg-white hover:bg-red-50'
        : active
          ? 'text-slate-900 border-slate-300 bg-slate-100'
          : 'text-slate-600 border-slate-200 bg-white hover:bg-slate-50'
    }`}
  >
    {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Icon className="w-3.5 h-3.5" />}
    <span>{label}</span>
  </button>
);

const SecretRow: React.FC<{ label: string; value: string; copied: boolean; onCopy: () => void }> = ({ label, value, copied, onCopy }) => (
  <div className="flex items-center gap-3 bg-white border border-slate-200 rounded-lg px-3 py-2">
    <span className="text-xs font-medium text-slate-600 shrink-0 max-w-[16rem] truncate" title={label}>{label}</span>
    <code className="text-xs font-mono text-slate-800 truncate flex-1 min-w-0">{value}</code>
    <button onClick={onCopy} className="shrink-0 p-1.5 rounded-md text-slate-400 hover:text-slate-900 hover:bg-slate-100 cursor-pointer" title="Copiar">
      {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  </div>
);
