import React, { useState } from 'react';
import {
  Globe,
  Download,
  FileCode2,
  GitBranch,
  Layers,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Database,
  Server,
  Upload,
  Search,
  ArrowRight,
} from 'lucide-react';
import {
  api,
  type ComposeParseResult,
  type GitInspectResult,
  type PlatformParseResult,
} from '../lib/api';
import { WordPressMigrationWizard } from './WordPressMigrationWizard';
import { CoolifyImport } from './CoolifyImport';

export type ImportSourceTab = 'wordpress' | 'coolify' | 'compose' | 'git' | 'platforms' | 'platform';

interface UniversalImporterProps {
  initialSource?: ImportSourceTab;
  sourceTrigger?: number;
  onComplete: (createdProjectId?: string) => void;
  onOpenCatalogInstalled?: () => void;
  onOpenDomains: () => void;
  onNotify: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

function normalizeSource(s?: ImportSourceTab): 'wordpress' | 'coolify' | 'compose' | 'git' | 'platforms' {
  if (s === 'platform') return 'platforms';
  if (s === 'coolify' || s === 'compose' || s === 'git' || s === 'platforms') return s;
  return 'wordpress';
}

export const UniversalImporter: React.FC<UniversalImporterProps> = ({
  initialSource = 'wordpress',
  sourceTrigger = 0,
  onComplete,
  onOpenCatalogInstalled,
  onOpenDomains,
  onNotify,
}) => {
  const [source, setSource] = useState<'wordpress' | 'coolify' | 'compose' | 'git' | 'platforms'>(() =>
    normalizeSource(initialSource)
  );

  const [prevTrigger, setPrevTrigger] = useState(sourceTrigger);
  if (sourceTrigger !== prevTrigger) {
    setPrevTrigger(sourceTrigger);
    setSource(normalizeSource(initialSource));
  }

  // Compose
  const [composeYaml, setComposeYaml] = useState('');
  const [composeName, setComposeName] = useState('');
  const [composePreview, setComposePreview] = useState<ComposeParseResult | null>(null);
  const [composeSelected, setComposeSelected] = useState<Set<string>>(new Set());
  const [composeBusy, setComposeBusy] = useState(false);
  const [composeError, setComposeError] = useState<string | null>(null);

  // Git URL
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [gitBusy, setGitBusy] = useState(false);
  const [gitInfo, setGitInfo] = useState<GitInspectResult | null>(null);
  const [gitError, setGitError] = useState<string | null>(null);
  const [gitProjectName, setGitProjectName] = useState('');
  const [gitBuildCmd, setGitBuildCmd] = useState('');
  const [gitStartCmd, setGitStartCmd] = useState('');
  const [gitPort, setGitPort] = useState(3000);

  // Plataformas
  const [platformKind, setPlatformKind] = useState<'auto' | 'vercel' | 'netlify' | 'railway' | 'render' | 'dokploy'>('auto');
  const [platformConfigText, setPlatformConfigText] = useState('');
  const [platformEnvText, setPlatformEnvText] = useState('');
  const [platformGitUrl, setPlatformGitUrl] = useState('');
  const [platformName, setPlatformName] = useState('');
  const [platformParsed, setPlatformParsed] = useState<PlatformParseResult | null>(null);
  const [platformBusy, setPlatformBusy] = useState(false);
  const [platformError, setPlatformError] = useState<string | null>(null);

  const cards = [
    { id: 'wordpress' as const, title: 'WordPress', subtitle: 'Analiza y migra tu web o WooCommerce', icon: Globe },
    { id: 'coolify' as const, title: 'Coolify v4', subtitle: 'Apps, bases de datos y dominios', icon: Download },
    { id: 'compose' as const, title: 'Docker Compose', subtitle: 'Pega o sube docker-compose.yml', icon: FileCode2 },
    { id: 'git' as const, title: 'URL Git', subtitle: 'GitHub, GitLab, Bitbucket, Gitea', icon: GitBranch },
    { id: 'platforms' as const, title: 'Otras nubes', subtitle: 'Vercel, Netlify, Railway, Render, Dokploy', icon: Layers },
  ];

  const handleParseCompose = async () => {
    setComposeBusy(true);
    setComposeError(null);
    try {
      const res = await api.parseCompose(composeYaml);
      setComposePreview(res);
      setComposeSelected(new Set(res.services.map((s) => s.name)));
      if (!composeName && res.services[0]) setComposeName(res.services[0].name);
    } catch (err: any) {
      setComposeError(err?.message || 'No se pudo interpretar el archivo Compose');
    } finally {
      setComposeBusy(false);
    }
  };

  const handleApplyCompose = async () => {
    setComposeBusy(true);
    setComposeError(null);
    try {
      const res = await api.applyCompose({
        yamlText: composeYaml,
        projectName: composeName.trim() || undefined,
        selectedServices: Array.from(composeSelected),
      });
      const count = res.importedServices || 0;
      onNotify(`Stack importado con ${count} ${count === 1 ? 'servicio' : 'servicios'}`, 'success');
      onComplete(res.project?.id);
    } catch (err: any) {
      setComposeError(err?.message || 'No se pudo importar el stack');
    } finally {
      setComposeBusy(false);
    }
  };

  const handleInspectGit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!gitUrl.trim()) return;
    setGitBusy(true);
    setGitError(null);
    try {
      const info = await api.inspectGitUrl(gitUrl.trim(), gitBranch.trim() || undefined);
      setGitInfo(info);
      setGitProjectName(info.suggestedName || info.repo);
      setGitBuildCmd(info.buildCommand || '');
      setGitStartCmd(info.startCommand || '');
      setGitPort(info.port || 3000);
    } catch (err: any) {
      setGitError(err?.message || 'No se pudo inspeccionar el repositorio');
    } finally {
      setGitBusy(false);
    }
  };

  const handleCreateFromGit = async () => {
    if (!gitInfo) return;
    setGitBusy(true);
    setGitError(null);
    try {
      const res = await api.createImportedProject({
        name: gitProjectName.trim() || gitInfo.suggestedName,
        description: gitInfo.description || `Repositorio ${gitInfo.provider} (${gitInfo.owner}/${gitInfo.repo})`,
        icon: 'app',
        platform: gitInfo.provider,
        source: `${gitInfo.provider}-import`,
        gitRepo: gitInfo.cloneUrl,
        gitBranch: gitBranch.trim() || gitInfo.defaultBranch || 'main',
        buildCommand: gitBuildCmd,
        startCommand: gitStartCmd,
        port: gitPort,
      });
      onNotify(`Proyecto «${res.project.name}» importado desde ${gitInfo.provider}`, 'success');
      onComplete(res.project?.id);
    } catch (err: any) {
      setGitError(err?.message || 'No se pudo crear el proyecto');
    } finally {
      setGitBusy(false);
    }
  };

  const handleParsePlatform = async () => {
    setPlatformBusy(true);
    setPlatformError(null);
    try {
      const res = await api.parsePlatformConfig({
        platform: platformKind,
        configText: platformConfigText,
        envText: platformEnvText,
      });
      setPlatformParsed(res);
      if (res.name && !platformName) setPlatformName(res.name);
      if (res.gitRepo && !platformGitUrl) setPlatformGitUrl(res.gitRepo);
    } catch (err: any) {
      setPlatformError(err?.message || 'No se pudo leer la configuración');
    } finally {
      setPlatformBusy(false);
    }
  };

  const handleCreateFromPlatform = async () => {
    if (!platformParsed) return;
    setPlatformBusy(true);
    setPlatformError(null);
    try {
      const res = await api.createImportedProject({
        name: platformName.trim() || platformParsed.name || `Proyecto ${platformParsed.platform}`,
        platform: platformParsed.platform,
        source: `${platformParsed.platform}-import`,
        gitRepo: platformGitUrl.trim() || platformParsed.gitRepo,
        gitBranch: platformParsed.gitBranch || 'main',
        buildCommand: platformParsed.buildCommand,
        startCommand: platformParsed.startCommand,
        baseDirectory: platformParsed.baseDirectory || '/',
        healthPath: platformParsed.healthPath || '/',
        port: platformParsed.port || 3000,
        envVars: platformParsed.envVars,
        domains: platformParsed.domains,
      });
      onNotify(`Proyecto importado desde ${platformParsed.platform}`, 'success');
      onComplete(res.project?.id);
    } catch (err: any) {
      setPlatformError(err?.message || 'No se pudo crear el proyecto');
    } finally {
      setPlatformBusy(false);
    }
  };

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-slate-900 tracking-tight">Importar y migrar</h1>
        <p className="text-sm text-slate-500 mt-1">
          Trae sitios WordPress, stacks Docker Compose, repositorios Git o proyectos de otras plataformas.
        </p>
      </div>

      {/* Selector de origen */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {cards.map((c) => {
          const Icon = c.icon;
          const active = source === c.id;
          return (
            <button
              key={c.id}
              type="button"
              aria-pressed={active}
              onClick={() => setSource(c.id)}
              className={`p-3.5 rounded-xl border text-left transition-colors cursor-pointer space-y-1.5 ${
                active
                  ? 'bg-slate-900 text-white border-slate-900'
                  : 'bg-white text-slate-900 border-slate-200 hover:border-slate-300'
              }`}
            >
              <Icon className={`w-4 h-4 ${active ? 'text-white' : 'text-slate-600'}`} />
              <div className="text-xs font-semibold leading-tight">{c.title}</div>
              <div className={`text-[11px] leading-snug ${active ? 'text-slate-300' : 'text-slate-500'}`}>{c.subtitle}</div>
            </button>
          );
        })}
      </div>

      {source === 'wordpress' && (
        <WordPressMigrationWizard
          onComplete={() => onComplete()}
          onOpenCatalogInstalled={onOpenCatalogInstalled}
          onOpenDomains={onOpenDomains}
          onNotify={onNotify}
        />
      )}

      {source === 'coolify' && (
        <CoolifyImport
          onComplete={() => onComplete()}
          onCancel={() => onComplete()}
          onNotify={onNotify}
        />
      )}

      {source === 'compose' && (
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Importar docker-compose.yml</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Detecta aplicaciones, bases de datos, puertos, volúmenes y avisos de seguridad antes de importar.
              </p>
            </div>
            <label className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 cursor-pointer self-start">
              <Upload className="w-3.5 h-3.5" />
              <span>Cargar archivo .yml</span>
              <input
                type="file"
                accept=".yml,.yaml,.txt"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  e.target.value = '';
                  if (!file) return;
                  const reader = new FileReader();
                  reader.onload = () => setComposeYaml(String(reader.result || ''));
                  reader.readAsText(file);
                }}
              />
            </label>
          </div>

          {composeError && (
            <div role="alert" className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" /> {composeError}
            </div>
          )}

          <textarea
            value={composeYaml}
            onChange={(e) => setComposeYaml(e.target.value)}
            rows={8}
            placeholder={'services:\n  web:\n    image: node:22-alpine\n    ports:\n      - "3000:3000"\n  db:\n    image: postgres:16-alpine'}
            className="w-full p-3.5 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs text-slate-800 focus:bg-white"
          />

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => void handleParseCompose()}
              disabled={composeBusy || !composeYaml.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
            >
              {composeBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              <span>Analizar servicios</span>
            </button>
          </div>

          {composePreview && (
            <div className="space-y-4 pt-4 border-t border-slate-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="text-xs font-medium text-slate-700 tabular-nums">
                  Detectados: {composePreview.appsCount} {composePreview.appsCount === 1 ? 'aplicación' : 'aplicaciones'} y{' '}
                  {composePreview.databasesCount} {composePreview.databasesCount === 1 ? 'base de datos' : 'bases de datos'}
                </div>
                <input
                  type="text"
                  value={composeName}
                  onChange={(e) => setComposeName(e.target.value)}
                  placeholder="Nombre del proyecto"
                  className="px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs w-full sm:w-64"
                />
              </div>

              <div className="space-y-2">
                {composePreview.services.map((svc) => {
                  const checked = composeSelected.has(svc.name);
                  return (
                    <label key={svc.name} className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-50 border border-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => {
                          setComposeSelected((prev) => {
                            const next = new Set(prev);
                            if (next.has(svc.name)) next.delete(svc.name);
                            else next.add(svc.name);
                            return next;
                          });
                        }}
                        className="mt-0.5 rounded border-slate-300 accent-slate-900"
                      />
                      <div className="flex-1 min-w-0 text-xs space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          {svc.kind === 'database'
                            ? <Database className="w-3.5 h-3.5 text-slate-600" />
                            : <Server className="w-3.5 h-3.5 text-slate-600" />}
                          <span className="font-semibold text-slate-900">{svc.name}</span>
                          <span className="font-mono text-slate-500">{svc.image || `build: ${svc.build}`}</span>
                          {svc.containerPort && (
                            <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 font-mono text-[11px] tabular-nums">
                              :{svc.containerPort}
                            </span>
                          )}
                        </div>
                        {svc.warnings.map((w, i) => (
                          <div key={i} className="text-[11px] text-amber-800 flex items-start gap-1">
                            <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-amber-600" />
                            <span>{w}</span>
                          </div>
                        ))}
                      </div>
                    </label>
                  );
                })}
              </div>

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => void handleApplyCompose()}
                  disabled={composeBusy || composeSelected.size === 0}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50 tabular-nums"
                >
                  <span>
                    Importar {composeSelected.size} {composeSelected.size === 1 ? 'servicio' : 'servicios'}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {source === 'git' && (
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Importar desde URL Git</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Compatible con GitHub, GitLab, Bitbucket o Gitea. Los repositorios públicos no requieren token.
            </p>
          </div>

          {gitError && (
            <div role="alert" className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" /> {gitError}
            </div>
          )}

          <form onSubmit={handleInspectGit} className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={gitUrl}
              onChange={(e) => {
                setGitUrl(e.target.value);
                if (gitInfo) setGitInfo(null);
              }}
              placeholder="https://github.com/usuario/mi-app o usuario/mi-app"
              className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
            />
            <input
              type="text"
              value={gitBranch}
              onChange={(e) => setGitBranch(e.target.value)}
              placeholder="Rama (opcional)"
              className="sm:w-36 px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
            />
            <button
              type="submit"
              disabled={gitBusy || !gitUrl.trim()}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              {gitBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              <span>Analizar</span>
            </button>
          </form>

          {gitInfo && (
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-4 text-xs">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-slate-600" />
                  <span className="font-semibold text-slate-900 font-mono">{gitInfo.owner}/{gitInfo.repo}</span>
                  <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-600">{gitInfo.provider}</span>
                  {gitInfo.framework && (
                    <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-800 font-medium">
                      {gitInfo.framework}
                    </span>
                  )}
                </div>
                {gitInfo.verifiedPublic && (
                  <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Repositorio público
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Nombre del proyecto</label>
                  <input value={gitProjectName} onChange={(e) => setGitProjectName(e.target.value)} className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg" />
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Puerto interno</label>
                  <input type="number" value={gitPort} onChange={(e) => setGitPort(Number(e.target.value))} className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono tabular-nums" />
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Comando de compilación</label>
                  <input value={gitBuildCmd} onChange={(e) => setGitBuildCmd(e.target.value)} placeholder="npm run build" className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Comando de inicio</label>
                  <input value={gitStartCmd} onChange={(e) => setGitStartCmd(e.target.value)} placeholder="npm start" className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => void handleCreateFromGit()}
                  disabled={gitBusy}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  <span>Crear proyecto</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {source === 'platforms' && (
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Migrar desde Vercel, Netlify, Railway, Render o Dokploy</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Pega tu configuración (<code className="font-mono">vercel.json</code>, <code className="font-mono">netlify.toml</code>, <code className="font-mono">railway.json</code>, <code className="font-mono">render.yaml</code> o JSON de Dokploy) y tus variables <code className="font-mono">.env</code>.
            </p>
          </div>

          {platformError && (
            <div role="alert" className="p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-800 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" /> {platformError}
            </div>
          )}

          <div className="flex flex-wrap gap-1.5 text-xs">
            {([
              { id: 'auto', label: 'Detectar automáticamente' },
              { id: 'vercel', label: 'Vercel' },
              { id: 'netlify', label: 'Netlify' },
              { id: 'railway', label: 'Railway' },
              { id: 'render', label: 'Render' },
              { id: 'dokploy', label: 'Dokploy' },
            ] as const).map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setPlatformKind(p.id)}
                className={`px-2.5 py-1.5 rounded-lg border font-medium cursor-pointer ${
                  platformKind === p.id ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Archivo de configuración</label>
              <textarea
                value={platformConfigText}
                onChange={(e) => setPlatformConfigText(e.target.value)}
                rows={7}
                placeholder="Pega vercel.json, netlify.toml, railway.json, render.yaml o JSON de Dokploy…"
                className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs focus:bg-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Variables .env (opcional)</label>
              <textarea
                value={platformEnvText}
                onChange={(e) => setPlatformEnvText(e.target.value)}
                rows={7}
                placeholder={'DATABASE_URL=postgres://...\nREDIS_URL=redis://...'}
                className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs focus:bg-white"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => void handleParsePlatform()}
              disabled={platformBusy || (!platformConfigText.trim() && !platformEnvText.trim())}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
            >
              {platformBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              <span>Analizar configuración</span>
            </button>
          </div>

          {platformParsed && (
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-4 text-xs">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="font-semibold text-slate-900">Plataforma: {platformParsed.platform}</span>
                <span className="text-slate-500 font-mono tabular-nums">
                  {Object.keys(platformParsed.envVars || {}).length} variables · puerto :{platformParsed.port}
                </span>
              </div>

              {(platformParsed.buildCommand || platformParsed.startCommand) && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                  <div className="bg-white border border-slate-200 rounded-lg px-3 py-2">
                    <span className="text-slate-400 block">Compilación</span>
                    <code className="font-mono text-slate-800">{platformParsed.buildCommand || '—'}</code>
                  </div>
                  <div className="bg-white border border-slate-200 rounded-lg px-3 py-2">
                    <span className="text-slate-400 block">Inicio</span>
                    <code className="font-mono text-slate-800">{platformParsed.startCommand || '—'}</code>
                  </div>
                </div>
              )}

              {platformParsed.recommendedDatabases.length > 0 && (
                <div className="p-3 rounded-lg bg-white border border-slate-200 text-slate-700">
                  Bases de datos detectadas en <code className="font-mono">.env</code>:{' '}
                  <strong>{platformParsed.recommendedDatabases.map((d) => `${d.label} (${d.envKey})`).join(', ')}</strong>.
                  Puedes crearlas desde la pestaña «Bases de datos» del proyecto.
                </div>
              )}

              {platformParsed.notes.map((n, i) => (
                <div key={i} className="text-slate-600">· {n}</div>
              ))}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-slate-700 mb-1">Nombre del proyecto</label>
                  <input value={platformName} onChange={(e) => setPlatformName(e.target.value)} placeholder="Mi proyecto" className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg" />
                </div>
                <div>
                  <label className="block font-medium text-slate-700 mb-1">URL del repositorio Git (opcional)</label>
                  <input value={platformGitUrl} onChange={(e) => setPlatformGitUrl(e.target.value)} placeholder="https://github.com/usuario/repo" className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono" />
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => void handleCreateFromPlatform()}
                  disabled={platformBusy}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
                >
                  <span>Importar proyecto</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
