import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Search,
  Package,
  Play,
  Square,
  RotateCw,
  Trash2,
  ExternalLink,
  KeyRound,
  ScrollText,
  AlertTriangle,
  Check,
  Copy,
  Globe,
  Cpu,
  HardDrive,
  Info,
  CircleCheck,
  CircleAlert,
  Loader2,
} from 'lucide-react';
import {
  api,
  type ServiceTemplate,
  type ServiceCategory,
  type ServiceInstallation,
  type ServiceSecrets,
} from '../lib/api';
import { liveEvents } from '../lib/liveEvents';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';

interface Props {
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
  initialTab?: 'catalogo' | 'instalados';
  tabTrigger?: number;
}

const STATUS_STYLE: Record<string, { dot: string; label: string; text: string }> = {
  installing: { dot: 'bg-slate-400 animate-pulse', label: 'Instalando', text: 'text-slate-600' },
  running: { dot: 'bg-emerald-500', label: 'En marcha', text: 'text-emerald-700' },
  degraded: { dot: 'bg-amber-500', label: 'Arrancó sin responder', text: 'text-amber-700' },
  stopped: { dot: 'bg-slate-300', label: 'Detenido', text: 'text-slate-500' },
  error: { dot: 'bg-red-500', label: 'Con errores', text: 'text-red-700' },
};

function formatMemory(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(mb % 1024 === 0 ? 0 : 1)} GB` : `${mb} MB`;
}

export const ServiceCatalog: React.FC<Props> = ({ onNotify, initialTab = 'catalogo', tabTrigger = 0 }) => {
  const [tab, setTab] = useState<'catalogo' | 'instalados'>(initialTab);
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
  const [domainTarget, setDomainTarget] = useState<ServiceInstallation | null>(null);
  const [domainInput, setDomainInput] = useState('');

  const [prevTabTrigger, setPrevTabTrigger] = useState(tabTrigger);
  if (tabTrigger !== prevTabTrigger) {
    setPrevTabTrigger(tabTrigger);
    setTab(initialTab);
  }

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

  useEffect(() => {
    loadRef.current = () => { void load(); };
  });

  useEffect(() => {
    let active = true;
    Promise.all([api.getCatalog(), api.getInstallations()])
      .then(([cat, inst]) => {
        if (!active) return;
        setTemplates(cat.templates);
        setCategories(cat.categories);
        setInstallations(inst.installations);
        setLoadError(null);
      })
      .catch((err) => {
        if (!active) return;
        setLoadError(err instanceof Error ? err.message : 'No se pudo cargar el catálogo');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const offProg = liveEvents.onServiceProgress((ev) => {
      setInstallations((prev) => prev.map((inst) => (
        inst.id === ev.id ? { ...inst, progress: ev.progress ?? inst.progress } : inst
      )));
    });
    const offDone = liveEvents.onServiceInstalled(() => loadRef.current());
    const offFail = liveEvents.onServiceFailed(() => loadRef.current());
    return () => {
      offProg();
      offDone();
      offFail();
    };
  }, []);

  const installing = installations.some((i) => i.status === 'installing');
  useEffect(() => {
    if (!installing) return;
    const timer = setInterval(() => loadRef.current(), 2500);
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
      onNotify(err instanceof Error ? err.message : 'Ha ocurrido un error', 'error');
    } finally {
      setBusy(null);
    }
  };

  const copy = async (text: string, key: string) => {
    const ok = await copyToClipboard(text);
    if (!ok) return;
    setCopied(key);
    window.setTimeout(() => setCopied(null), 1800);
  };

  const handleInstall = async (template: ServiceTemplate, name: string, domain: string) => {
    setChosen(null);
    await guard(`install-${template.id}`, async () => {
      await api.installService({
        templateId: template.id,
        name: name.trim() || template.name,
        domain: domain.trim() || null,
      });
      onNotify(`Instalando ${template.name}. Sigue el progreso en «Instalados».`, 'info');
      setTab('instalados');
      await load();
    });
  };

  const handleAttachDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domainTarget || !domainInput.trim()) return;
    const target = domainTarget;
    const cleanDom = domainInput.trim().toLowerCase();
    await guard(`dom-${target.id}`, async () => {
      const res = await api.attachCatalogDomain(target.id, cleanDom);
      setDomainTarget(null);
      setDomainInput('');
      onNotify(
        res.ingress?.applied
          ? `Dominio ${cleanDom} conectado y publicado en Caddy.`
          : `Dominio ${cleanDom} guardado (${res.ingress?.reason || 'pendiente de Caddy'}).`,
        'success'
      );
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

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-xs text-slate-500 py-16 justify-center">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Cargando catálogo…</span>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {loadError && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <div className="text-xs">
            <p className="font-semibold text-amber-900">No se pudo cargar el catálogo</p>
            <p className="text-amber-800 mt-0.5">{loadError}</p>
          </div>
        </div>
      )}

      {/* Cabecera */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 tracking-tight">Catálogo de servicios</h1>
          <p className="text-sm text-slate-500 mt-1 max-w-2xl">
            Servicios listos en un clic con versión fijada, límites de recursos, volumen persistente y secretos aleatorios.
          </p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0 bg-slate-100 p-1 rounded-lg border border-slate-200 self-start lg:self-auto">
          {([
            { id: 'catalogo', label: 'Catálogo', count: templates.length },
            { id: 'instalados', label: 'Instalados', count: installations.length },
          ] as const).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                tab === t.id
                  ? 'bg-white text-slate-900 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <span>{t.label}</span>
              <span className="text-[11px] tabular-nums text-slate-500">({t.count})</span>
            </button>
          ))}
        </div>
      </div>

      {tab === 'catalogo' && (
        <>
          <div className="flex flex-col lg:flex-row gap-3">
            <div className="relative flex-1 min-w-0">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Buscar servicio por nombre, descripción o etiqueta…"
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-200 bg-white text-sm text-slate-900 placeholder:text-slate-400"
              />
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={() => setCategory(null)}
                className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer whitespace-nowrap ${
                  category === null ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                Todas
              </button>
              {categories.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => setCategory(c.id === category ? null : c.id)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer whitespace-nowrap ${
                    category === c.id ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          {visible.length === 0 ? (
            <div className="text-center py-12 text-xs text-slate-500">
              No hay servicios que coincidan con «{query}».
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {visible.map((t) => (
                <article
                  key={t.id}
                  className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col gap-3 hover:border-slate-300 transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h2 className="font-semibold text-sm text-slate-900 leading-tight">{t.name}</h2>
                      <p className="text-xs text-slate-500 mt-0.5">{t.categoryLabel}</p>
                    </div>
                    {t.installedCount > 0 && (
                      <span className="shrink-0 text-[11px] font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-2 py-0.5 tabular-nums">
                        {t.installedCount} {t.installedCount === 1 ? 'instalado' : 'instalados'}
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-slate-600 leading-relaxed flex-1">{t.summary}</p>

                  <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs text-slate-500 border-t border-slate-100 pt-3 tabular-nums">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <HardDrive className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                      <span className="truncate">{formatMemory(t.totalMemoryMb)}</span>
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
                    <span className="text-[11px] text-slate-400 truncate" title={t.licence}>{t.licence}</span>
                    <button
                      type="button"
                      onClick={() => setChosen(t)}
                      className="shrink-0 px-3.5 py-1.5 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 transition-colors cursor-pointer"
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
          onCopy={(text, key) => { void copy(text, key); }}
          onToggleSecrets={(inst) => { void toggleSecrets(inst); }}
          onToggleLogs={(inst) => { void toggleLogs(inst); }}
          onControl={(inst, action) => {
            void guard(`ctl-${inst.id}`, async () => {
              await api.controlInstallation(inst.id, action);
              await load();
            });
          }}
          onRefreshHealth={(inst) => {
            void guard(`hp-${inst.id}`, async () => {
              await api.refreshInstallationHealth(inst.id);
              await load();
            });
          }}
          onAttachDomain={(inst) => {
            setDomainTarget(inst);
            setDomainInput(inst.domain || '');
          }}
          onRemove={setConfirmRemove}
          onBrowse={() => setTab('catalogo')}
        />
      )}

      {chosen && (
        <InstallDialog
          template={chosen}
          onCancel={() => setChosen(null)}
          onConfirm={(t, name, domain) => { void handleInstall(t, name, domain); }}
        />
      )}

      {confirmRemove && (
        <RemoveDialog
          installation={confirmRemove}
          onCancel={() => setConfirmRemove(null)}
          onConfirm={(deleteVolumes) => {
            const inst = confirmRemove;
            setConfirmRemove(null);
            void guard(`rm-${inst.id}`, async () => {
              await api.removeInstallation(inst.id, deleteVolumes);
              onNotify(
                deleteVolumes
                  ? `${inst.name} desinstalado y sus datos borrados.`
                  : `${inst.name} desinstalado. Sus volúmenes se conservan.`,
                'info'
              );
              await load();
            });
          }}
        />
      )}

      {/* Modal: Conectar o cambiar dominio del servicio */}
      <Modal
        open={Boolean(domainTarget)}
        onClose={() => setDomainTarget(null)}
        title={`Conectar dominio a ${domainTarget?.name || ''}`}
        subtitle="Publica el servicio con HTTPS automático a través de Caddy."
        maxWidthClass="max-w-md"
      >
        <form onSubmit={handleAttachDomain} className="p-5 space-y-4">
          <label className="block">
            <span className="text-xs font-medium text-slate-700">Dominio</span>
            <input
              type="text"
              required
              autoFocus
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="miweb.tudominio.com"
              className="mt-1.5 w-full px-3 py-2 rounded-lg border border-slate-200 text-sm font-mono text-slate-900"
            />
          </label>
          <p className="text-xs text-slate-500 leading-relaxed">
            Apunta antes el registro A del dominio hacia la IP de este servidor. Caddy solicitará el certificado TLS automáticamente.
          </p>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setDomainTarget(null)} className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 border border-slate-200 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={!domainInput.trim() || busy === `dom-${domainTarget?.id}`}
              className="px-4 py-2 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
            >
              {busy === `dom-${domainTarget?.id}` ? 'Guardando…' : 'Conectar dominio'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

const InstallDialog: React.FC<{
  template: ServiceTemplate;
  onCancel: () => void;
  onConfirm: (t: ServiceTemplate, name: string, domain: string) => void;
}> = ({ template, onCancel, onConfirm }) => {
  const [name, setName] = useState(template.name);
  const [domain, setDomain] = useState('');
  const [serverIp, setServerIp] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.getServerIp()
      .then((res) => { if (active && res?.ip) setServerIp(res.ip); })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  return (
    <Modal
      open
      onClose={onCancel}
      title={`Instalar ${template.name}`}
      subtitle={template.description}
      maxWidthClass="max-w-2xl"
    >
      <div className="p-5 space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <label className="block">
            <span className="text-xs font-medium text-slate-700">Nombre</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-sm text-slate-900"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-slate-700">Dominio (opcional)</span>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder={`${template.id}.midominio.com`}
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-sm text-slate-900 placeholder:text-slate-400 font-mono"
            />
          </label>
        </div>

        <div className="flex items-start gap-2.5 text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-xl p-3.5">
          <Globe className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            Con dominio, el servicio se publica con HTTPS automático apuntando un registro A a{' '}
            {serverIp ? <strong className="font-mono text-slate-800">{serverIp}</strong> : 'la IP de este servidor'}.
            Sin dominio, queda accesible solo en local y puedes añadirle uno después.
          </p>
        </div>

        <div>
          <h4 className="text-xs font-semibold text-slate-700 mb-2">Recursos que se crearán</h4>
          <ul className="text-xs text-slate-600 space-y-1.5">
            <li className="flex items-start gap-2">
              <Package className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
              <span>
                Contenedor <code className="font-mono text-slate-800">{template.image}</code> ({formatMemory(template.memoryMb)}, {template.cpus} CPU).
              </span>
            </li>
            {template.database && (
              <li className="flex items-start gap-2">
                <HardDrive className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                <span>Base de datos {template.database.engine} gestionada en red privada con copias programables.</span>
              </li>
            )}
            {template.sidecars.map((c) => (
              <li key={c.name} className="flex items-start gap-2">
                <Package className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                <span>Contenedor auxiliar «{c.name}» (<code className="font-mono text-slate-800">{c.image}</code>).</span>
              </li>
            ))}
            {template.secretNames.length > 0 && (
              <li className="flex items-start gap-2">
                <KeyRound className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                <span>
                  {template.secretNames.length === 1 ? '1 secreto aleatorio' : `${template.secretNames.length} secretos aleatorios`}:{' '}
                  {template.secretNames.join(', ')}.
                </span>
              </li>
            )}
            <li className="flex items-start gap-2">
              <Cpu className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
              <span>Memoria total reservada: <strong className="font-medium text-slate-800 tabular-nums">{formatMemory(template.totalMemoryMb)}</strong>.</span>
            </li>
          </ul>
        </div>

        {template.notes.length > 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5">
            <div className="flex items-center gap-1.5 mb-1">
              <Info className="w-3.5 h-3.5 text-amber-600 shrink-0" />
              <span className="text-xs font-semibold text-amber-900">Antes de instalar</span>
            </div>
            <ul className="text-xs text-amber-800 space-y-1 leading-relaxed">
              {template.notes.map((n, i) => <li key={i}>· {n}</li>)}
            </ul>
          </div>
        )}

        <p className="text-[11px] text-slate-500">
          {template.licence} · <a href={template.website} target="_blank" rel="noreferrer" className="underline hover:text-slate-900">{template.website}</a>
        </p>
      </div>

      <footer className="flex items-center justify-end gap-2 px-5 py-3.5 border-t border-slate-200 bg-slate-50">
        <button type="button" onClick={onCancel} className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 border border-slate-200 bg-white hover:bg-slate-50 cursor-pointer">
          Cancelar
        </button>
        <button
          type="button"
          onClick={() => onConfirm(template, name, domain)}
          className="px-4 py-2 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 cursor-pointer"
        >
          Instalar {template.name}
        </button>
      </footer>
    </Modal>
  );
};

const RemoveDialog: React.FC<{
  installation: ServiceInstallation;
  onCancel: () => void;
  onConfirm: (deleteVolumes: boolean) => void;
}> = ({ installation, onCancel, onConfirm }) => {
  const [deleteVolumes, setDeleteVolumes] = useState(false);

  return (
    <Modal
      open
      onClose={onCancel}
      title={`Desinstalar ${installation.name}`}
      subtitle="Se eliminarán el contenedor, sus auxiliares, la red y la ruta en Caddy."
      maxWidthClass="max-w-md"
    >
      <div className="p-5 space-y-4">
        <label className="flex items-start gap-3 p-3.5 rounded-xl border border-slate-200 cursor-pointer hover:bg-slate-50">
          <input
            type="checkbox"
            checked={deleteVolumes}
            onChange={(e) => setDeleteVolumes(e.target.checked)}
            className="mt-0.5 w-4 h-4 accent-red-600"
          />
          <span className="text-xs">
            <span className="font-medium text-slate-900">Borrar también los datos</span>
            <span className="block text-slate-500 mt-0.5 leading-relaxed">
              Volúmenes, base de datos asociada y copias de seguridad. Esta acción es irreversible.
            </span>
          </span>
        </label>

        {deleteVolumes && (
          <div className="flex items-start gap-2 text-xs text-red-800 bg-red-50 border border-red-200 rounded-xl p-3">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
            <span>Se borrarán permanentemente todos los datos de {installation.name}.</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={onCancel} className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 border border-slate-200 hover:bg-slate-50 cursor-pointer">
            Cancelar
          </button>
          <button
            type="button"
            onClick={() => onConfirm(deleteVolumes)}
            className={`px-4 py-2 rounded-lg text-xs font-medium text-white cursor-pointer ${
              deleteVolumes ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-900 hover:bg-slate-800'
            }`}
          >
            {deleteVolumes ? 'Desinstalar y borrar datos' : 'Desinstalar'}
          </button>
        </div>
      </div>
    </Modal>
  );
};

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
  onAttachDomain: (i: ServiceInstallation) => void;
  onRemove: (i: ServiceInstallation) => void;
  onBrowse: () => void;
}> = ({
  installations,
  busy,
  secrets,
  logs,
  copied,
  onCopy,
  onToggleSecrets,
  onToggleLogs,
  onControl,
  onRefreshHealth,
  onAttachDomain,
  onRemove,
  onBrowse,
}) => {
  if (installations.length === 0) {
    return (
      <div className="text-center py-14 bg-white border border-slate-200 rounded-xl">
        <Package className="w-7 h-7 text-slate-300 mx-auto" />
        <p className="text-sm text-slate-700 mt-3 font-medium">Todavía no hay servicios instalados</p>
        <p className="text-xs text-slate-500 mt-1">Elige una plantilla del catálogo para desplegarla en minutos.</p>
        <button type="button" onClick={onBrowse} className="mt-4 px-3.5 py-2 rounded-lg text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 cursor-pointer">
          Explorar catálogo
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
          <section key={inst.id} className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="p-5 flex flex-col xl:flex-row xl:items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${style.dot}`} />
                  <h3 className="font-semibold text-sm text-slate-900">{inst.name}</h3>
                  <span className={`text-xs font-medium ${style.text}`}>{style.label}</span>
                  <span className="text-xs text-slate-300">·</span>
                  <span className="text-xs text-slate-500">{inst.templateName}</span>
                </div>

                <div className="mt-2 flex items-center gap-3 flex-wrap text-xs">
                  {inst.domain ? (
                    <a href={inst.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-slate-800 hover:underline font-mono">
                      <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                      {inst.domain}
                    </a>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-slate-500 font-mono tabular-nums">
                      <Globe className="w-3.5 h-3.5 text-slate-400" />
                      127.0.0.1:{inst.hostPort} (sin dominio)
                    </span>
                  )}
                  <span className="text-slate-400 font-mono truncate">{inst.image}</span>
                </div>

                {inst.status === 'installing' && inst.progress && <ProgressBar progress={inst.progress} />}

                {inst.ingress && !inst.ingress.applied && inst.domain && (
                  <p className="mt-3 text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 leading-relaxed">
                    El dominio está registrado pero no hay ruta en Caddy: {inst.ingress.reason || 'Caddy no responde.'} Accesible localmente en 127.0.0.1:{inst.hostPort}.
                  </p>
                )}

                {inst.lastError && inst.status !== 'installing' && (
                  <p className="mt-3 text-xs text-red-800 bg-red-50 border border-red-200 rounded-lg px-3 py-2 leading-relaxed">
                    {inst.lastError}
                  </p>
                )}

                {inst.status === 'running' && inst.nextSteps.length > 0 && (
                  <ul className="mt-3 text-xs text-slate-600 space-y-1 leading-relaxed">
                    {inst.nextSteps.map((s, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <CircleCheck className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                        <span>{s}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {inst.status !== 'installing' && (
                <div className="flex items-center gap-1.5 flex-wrap shrink-0">
                  <IconButton label="Dominio" icon={Globe} onClick={() => onAttachDomain(inst)} />
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
              <div className="border-t border-slate-200 bg-slate-50 px-5 py-4 space-y-2">
                <p className="text-xs font-semibold text-slate-800">Credenciales generadas</p>
                <p className="text-xs text-slate-500">
                  Solo se muestran aquí. Guárdalas en tu gestor de contraseñas: no aparecen en listados ni registros.
                </p>
                {Object.entries(sec.secrets).map(([key, value]) => (
                  <SecretRow key={key} label={key} value={value} copied={copied === `${inst.id}-${key}`} onCopy={() => onCopy(value, `${inst.id}-${key}`)} />
                ))}
                {sec.database && (
                  <SecretRow
                    label="Cadena de conexión BD"
                    value={sec.database.internalConnectionString}
                    copied={copied === `${inst.id}-db`}
                    onCopy={() => onCopy(sec.database!.internalConnectionString, `${inst.id}-db`)}
                  />
                )}
                {Object.keys(sec.secrets).length === 0 && !sec.database && (
                  <p className="text-xs text-slate-500">Este servicio no genera secretos.</p>
                )}
              </div>
            )}

            {log && (
              <div className="border-t border-slate-200 bg-slate-50 px-5 py-4">
                <pre className="text-xs font-mono text-slate-800 whitespace-pre-wrap max-h-80 overflow-y-auto leading-relaxed">{log}</pre>
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
};

const ProgressBar: React.FC<{ progress: NonNullable<ServiceInstallation['progress']> }> = ({ progress }) => {
  const pct = Math.round(((progress.stepIndex + 1) / progress.totalSteps) * 100);
  return (
    <div className="mt-3">
      <div className="flex items-baseline justify-between gap-3 mb-1.5">
        <span className="text-xs font-medium text-slate-700">{progress.label}</span>
        <span className="text-[11px] text-slate-500 tabular-nums shrink-0">
          Paso {progress.stepIndex + 1} de {progress.totalSteps}
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
        <div
          className={`h-full rounded-full transition-[width] duration-500 ${progress.failed ? 'bg-red-500' : 'bg-slate-900'}`}
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
    type="button"
    onClick={onClick}
    disabled={busy}
    title={label}
    className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap ${
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
    <span className="text-xs font-medium text-slate-600 shrink-0 max-w-[14rem] truncate" title={label}>{label}</span>
    <code className="text-xs font-mono text-slate-800 truncate flex-1 min-w-0">{value}</code>
    <button
      type="button"
      aria-label={`Copiar ${label}`}
      onClick={onCopy}
      className="shrink-0 p-1 rounded text-slate-400 hover:text-slate-900 hover:bg-slate-100 cursor-pointer"
      title="Copiar"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  </div>
);
