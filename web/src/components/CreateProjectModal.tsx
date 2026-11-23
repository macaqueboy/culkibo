import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  GitBranch,
  Star,
  Lock,
  Globe,
  ExternalLink,
  RefreshCw,
  CheckCircle2,
  Check,
  Terminal,
} from 'lucide-react';
import { api, type GitHubStatus, type GitHubRepo, type GitHubBranch, type GitHubAutoDetectResult } from '../lib/api';
import { Modal } from './Modal';

interface CreateProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (createdProjectId?: string) => void;
}

export const CreateProjectModal: React.FC<CreateProjectModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [tab, setTab] = useState<'giturl' | 'github' | 'manual'>('giturl');

  // Estado URL Git pública
  const [publicGitUrl, setPublicGitUrl] = useState('');
  const [publicGitBranch, setPublicGitBranch] = useState('');
  const [inspectingUrl, setInspectingUrl] = useState(false);
  const [inspectedUrl, setInspectedUrl] = useState<any>(null);

  // Formulario común / manual
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [forgePort, setForgePort] = useState(3000);
  const [startCommand, setStartCommand] = useState('npm start');
  const [buildCommand, setBuildCommand] = useState('');
  const [deployOnCreate, setDeployOnCreate] = useState(false);
  const [loading, setLoading] = useState(false);

  // Estado GitHub
  const [ghStatus, setGhStatus] = useState<GitHubStatus | null>(null);
  const [ghToken, setGhToken] = useState('');
  const [ghConnecting, setGhConnecting] = useState(false);
  const [ghError, setGhError] = useState<string | null>(null);

  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [repoSearch, setRepoSearch] = useState('');
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepo | null>(null);

  const [branches, setBranches] = useState<GitHubBranch[]>([]);
  const [branchesLoading, setBranchesLoading] = useState(false);
  const [selectedBranch, setSelectedBranch] = useState('main');

  const [detecting, setDetecting] = useState(false);
  const [detectedStack, setDetectedStack] = useState<GitHubAutoDetectResult | null>(null);
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const resetForm = () => {
    setName('');
    setDescription('');
    setForgePort(3000);
    setStartCommand('npm start');
    setBuildCommand('');
    setDeployOnCreate(false);
    setSelectedRepo(null);
    setDetectedStack(null);
    setRepoSearch('');
    setPublicGitUrl('');
    setPublicGitBranch('');
    setInspectedUrl(null);
    setGhError(null);
  };

  const handleClose = () => {
    if (loading) return;
    resetForm();
    onClose();
  };

  const switchTab = (next: 'giturl' | 'github' | 'manual') => {
    setTab(next);
    setGhError(null);
    if (next === 'github' && !ghStatus?.connected) {
      void checkGitHubStatus();
    }
  };

  const loadRepositories = async (search = '') => {
    setReposLoading(true);
    setGhError(null);
    try {
      const res = await api.getGitHubRepos({ perPage: 100, search });
      setRepos(res.repos);
    } catch (e: any) {
      setGhError(e?.message || 'Error al listar repositorios de GitHub');
    } finally {
      setReposLoading(false);
    }
  };

  const checkGitHubStatus = async () => {
    try {
      const status = await api.getGitHubStatus();
      setGhStatus(status);
      if (status.connected) {
        void loadRepositories();
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    if (!isOpen) return;
    let active = true;
    api.getGitHubStatus()
      .then((status) => {
        if (!active) return;
        setGhStatus(status);
        if (status.connected) {
          setReposLoading(true);
          setGhError(null);
          api.getGitHubRepos({ perPage: 100, search: '' })
            .then((res) => { if (active) setRepos(res.repos); })
            .catch((err: any) => { if (active) setGhError(err?.message || 'Error al listar repositorios de GitHub'); })
            .finally(() => { if (active) setReposLoading(false); });
        }
      })
      .catch((e) => console.error(e));
    return () => {
      active = false;
      if (searchTimeoutRef.current) clearTimeout(searchTimeoutRef.current);
    };
  }, [isOpen]);

  const handleConnectGitHub = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ghToken.trim()) return;
    setGhConnecting(true);
    setGhError(null);
    try {
      await api.connectGitHub(ghToken.trim());
      setGhToken('');
      await checkGitHubStatus();
    } catch (e: any) {
      setGhError(e?.message || 'Error al conectar con GitHub');
    } finally {
      setGhConnecting(false);
    }
  };

  const handleSelectRepo = async (repo: GitHubRepo) => {
    setSelectedRepo(repo);
    setName(repo.name);
    setDescription(repo.description || '');
    const defaultBr = repo.default_branch || 'main';
    setSelectedBranch(defaultBr);

    setBranchesLoading(true);
    setDetecting(true);
    setDetectedStack(null);

    try {
      const branchList = await api.getGitHubBranches(repo.owner.login, repo.name);
      setBranches(branchList);
      if (branchList.length > 0 && !branchList.some((b) => b.name === defaultBr)) {
        setSelectedBranch(branchList[0].name);
      }
    } catch {
      setBranches([{ name: defaultBr, commitSha: '' }]);
    } finally {
      setBranchesLoading(false);
    }

    try {
      const detected = await api.autoDetectGitHub(repo.owner.login, repo.name, defaultBr);
      setDetectedStack(detected);
      if (detected.port) setForgePort(detected.port);
      if (detected.startCommand) setStartCommand(detected.startCommand);
      if (detected.buildCommand) setBuildCommand(detected.buildCommand);
    } catch (e) {
      console.error('Error in auto-detect:', e);
    } finally {
      setDetecting(false);
    }
  };

  const handleBranchChange = async (br: string) => {
    setSelectedBranch(br);
    if (!selectedRepo) return;
    setDetecting(true);
    try {
      const detected = await api.autoDetectGitHub(selectedRepo.owner.login, selectedRepo.name, br);
      setDetectedStack(detected);
      if (detected.port) setForgePort(detected.port);
      if (detected.startCommand) setStartCommand(detected.startCommand);
      if (detected.buildCommand) setBuildCommand(detected.buildCommand);
    } catch (e) {
      console.error(e);
    } finally {
      setDetecting(false);
    }
  };

  const handleInspectPublicUrl = async () => {
    if (!publicGitUrl.trim()) return;
    setInspectingUrl(true);
    setGhError(null);
    try {
      const info = await api.inspectGitUrl(publicGitUrl.trim(), publicGitBranch.trim() || undefined);
      setInspectedUrl(info);
      setName(info.suggestedName || info.repo || 'mi-app');
      setDescription(info.description || '');
      if (info.port) setForgePort(info.port);
      if (info.buildCommand) setBuildCommand(info.buildCommand);
      if (info.startCommand) setStartCommand(info.startCommand);
      if (info.defaultBranch && !publicGitBranch) setPublicGitBranch(info.defaultBranch);
    } catch (err: any) {
      setGhError(err?.message || 'No se pudo analizar esa URL Git');
    } finally {
      setInspectingUrl(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setLoading(true);
    setGhError(null);
    try {
      const isGitHub = tab === 'github' && Boolean(selectedRepo);
      const isPublicGit = tab === 'giturl' && Boolean(inspectedUrl || publicGitUrl.trim());
      const projectPayload: any = {
        name: name.trim(),
        description: description.trim(),
        icon: 'app',
        status: 'active',
        forgePort: forgePort || 3000,
        citadelPort: 8000 + (crypto.getRandomValues(new Uint16Array(1))[0] % 1000),
        trafficSplit: { forge: 100, citadel: 0 },
        domains: [],
        envVars: detectedStack?.envVars || {},
        source: isGitHub ? 'github' : isPublicGit ? `${inspectedUrl?.provider || 'git'}-import` : 'manual',
        startCommand,
        buildCommand,
        gitRepo: isGitHub && selectedRepo ? selectedRepo.clone_url : isPublicGit ? (inspectedUrl?.cloneUrl || publicGitUrl.trim()) : '',
        gitBranch: isGitHub ? selectedBranch : isPublicGit ? (publicGitBranch.trim() || inspectedUrl?.defaultBranch || 'main') : 'main',
        githubOwner: isGitHub && selectedRepo ? selectedRepo.owner.login : (isPublicGit && inspectedUrl?.provider === 'github' ? inspectedUrl.owner : ''),
        githubRepo: isGitHub && selectedRepo ? selectedRepo.name : (isPublicGit && inspectedUrl?.provider === 'github' ? inspectedUrl.repo : ''),
        watchPaths: detectedStack?.watchPaths || ['src/**', 'public/**'],
        autoDeploy: isGitHub,
      };

      const created = await api.createProject(projectPayload);
      if (created && created.id) {
        await api.activateProject(created.id);
        if (deployOnCreate && projectPayload.gitRepo) {
          void api.startDeploy(created.id).catch(() => {});
        }
      }
      onSuccess(created?.id);
      resetForm();
      onClose();
    } catch (err: any) {
      setGhError(err?.message || 'Error al crear el proyecto');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      open={isOpen}
      onClose={handleClose}
      title="Nuevo proyecto"
      subtitle="Importa un repositorio Git o configura un proyecto vacío."
      maxWidthClass="max-w-xl"
      closeDisabled={loading}
    >
      {/* Selector de pestaña */}
      <div className="flex border-b border-slate-200 bg-slate-50/70 p-1.5 gap-1">
        <button
          type="button"
          onClick={() => switchTab('giturl')}
          className={`flex-1 py-1.5 px-2.5 text-xs font-medium rounded-lg transition-colors flex items-center justify-center gap-1.5 cursor-pointer ${
            tab === 'giturl'
              ? 'bg-white text-slate-900 shadow-2xs border border-slate-200'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <GitBranch className="w-3.5 h-3.5" />
          URL Git
        </button>
        <button
          type="button"
          onClick={() => switchTab('github')}
          className={`flex-1 py-1.5 px-2.5 text-xs font-medium rounded-lg transition-colors flex items-center justify-center gap-1.5 cursor-pointer ${
            tab === 'github'
              ? 'bg-white text-slate-900 shadow-2xs border border-slate-200'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
            <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
          </svg>
          GitHub
          {ghStatus?.connected && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title="Cuenta conectada" />}
        </button>
        <button
          type="button"
          onClick={() => switchTab('manual')}
          className={`flex-1 py-1.5 px-2.5 text-xs font-medium rounded-lg transition-colors flex items-center justify-center gap-1.5 cursor-pointer ${
            tab === 'manual'
              ? 'bg-white text-slate-900 shadow-2xs border border-slate-200'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Manual
        </button>
      </div>

      {/* Contenido */}
      <div className="p-5 space-y-4">
        {ghError && (
          <div role="alert" className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">
            {ghError}
          </div>
        )}

        {/* Pestaña URL Git pública */}
        {tab === 'giturl' && (
          <div className="space-y-4">
            <p className="text-xs text-slate-500 leading-relaxed">
              Pega una URL de GitHub, GitLab, Bitbucket o Gitea (o <code className="font-mono text-slate-700">usuario/repo</code>) y pulsa Detectar para inferir el stack sin token.
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                value={publicGitUrl}
                onChange={(e) => {
                  const val = e.target.value;
                  setPublicGitUrl(val);
                  if (inspectedUrl) setInspectedUrl(null);
                  const cleaned = val.trim().replace(/\/+$/, '').replace(/\.git$/i, '');
                  const lastSeg = cleaned.split(/[/:]/).filter(Boolean).pop();
                  if (lastSeg && !name && cleaned.includes('/')) {
                    setName(lastSeg);
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleInspectPublicUrl();
                  }
                }}
                placeholder="https://github.com/usuario/mi-app"
                className="flex-1 px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono text-slate-900 placeholder:text-slate-400"
              />
              <button
                type="button"
                onClick={handleInspectPublicUrl}
                disabled={inspectingUrl || !publicGitUrl.trim()}
                className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${inspectingUrl ? 'animate-spin' : ''}`} />
                <span>{inspectingUrl ? 'Analizando…' : 'Detectar'}</span>
              </button>
            </div>

            {!inspectedUrl && !name && publicGitUrl.trim() && (
              <p className="text-[11px] text-slate-400">
                Pulsa «Detectar» (o Enter) para rellenar automáticamente nombre, rama y comandos.
              </p>
            )}

            {(inspectedUrl || name) && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3 text-xs">
                {inspectedUrl?.framework && (
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-700">Stack detectado</span>
                    <span className="px-2 py-0.5 rounded-md bg-white border border-slate-200 text-slate-800 font-medium">
                      {inspectedUrl.framework}
                    </span>
                  </div>
                )}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">Nombre del proyecto</label>
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      required
                      className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">Rama</label>
                    <input
                      type="text"
                      value={publicGitBranch}
                      onChange={(e) => setPublicGitBranch(e.target.value)}
                      placeholder="main"
                      className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">Comando de compilación</label>
                    <input
                      type="text"
                      value={buildCommand}
                      onChange={(e) => setBuildCommand(e.target.value)}
                      placeholder="npm run build"
                      className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">Comando de inicio</label>
                    <input
                      type="text"
                      value={startCommand}
                      onChange={(e) => setStartCommand(e.target.value)}
                      placeholder="npm start"
                      className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Pestaña GitHub */}
        {tab === 'github' && (
          <div className="space-y-4">
            {!ghStatus?.connected ? (
              <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 text-center space-y-4">
                <div className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center mx-auto">
                  <svg className="w-5 h-5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
                    <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Conecta tu cuenta de GitHub</h3>
                  <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1 leading-relaxed">
                    Usa un Personal Access Token con alcance <code className="bg-slate-200/80 px-1 py-0.5 rounded font-mono">repo</code> para importar repositorios privados y activar webhooks automáticos.
                  </p>
                </div>

                <form onSubmit={handleConnectGitHub} className="space-y-3 max-w-md mx-auto text-left">
                  <input
                    type="password"
                    value={ghToken}
                    onChange={(e) => setGhToken(e.target.value)}
                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                    className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                  />
                  <div className="flex items-center justify-between gap-2">
                    <a
                      href="https://github.com/settings/tokens/new?scopes=repo,read:user&description=Culkibo%20Cloud"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-slate-600 hover:text-slate-900 font-medium inline-flex items-center gap-1 underline"
                    >
                      Generar token en GitHub
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    <button
                      type="submit"
                      disabled={ghConnecting || !ghToken.trim()}
                      className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50 inline-flex items-center gap-1.5 cursor-pointer"
                    >
                      {ghConnecting && <RefreshCw className="w-3 h-3 animate-spin" />}
                      {ghConnecting ? 'Verificando…' : 'Conectar GitHub'}
                    </button>
                  </div>
                </form>
              </div>
            ) : (
              <div className="space-y-3.5">
                <div className="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-200">
                  <div className="flex items-center gap-2.5">
                    <img
                      src={ghStatus.user?.avatar_url}
                      alt={ghStatus.user?.login}
                      className="w-8 h-8 rounded-full border border-slate-200"
                    />
                    <div>
                      <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                        {ghStatus.user?.name || ghStatus.user?.login}
                        <span className="text-[11px] text-slate-500 font-normal">@{ghStatus.user?.login}</span>
                      </div>
                      <span className="text-[11px] text-emerald-700 font-medium flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Conectado
                      </span>
                    </div>
                  </div>
                  <button
                    type="button"
                    aria-label="Actualizar repositorios"
                    onClick={() => void loadRepositories(repoSearch)}
                    className="p-1.5 hover:bg-slate-200/70 rounded-lg text-slate-600 transition-colors cursor-pointer"
                    title="Actualizar repositorios"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${reposLoading ? 'animate-spin' : ''}`} />
                  </button>
                </div>

                <div className="relative">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={repoSearch}
                    onChange={(e) => {
                      const val = e.target.value;
                      setRepoSearch(val);
                      if (searchTimeoutRef.current) clearTimeout(searchTimeoutRef.current);
                      searchTimeoutRef.current = setTimeout(() => {
                        void loadRepositories(val);
                      }, 250);
                    }}
                    placeholder="Buscar repositorio…"
                    className="w-full pl-9 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-sm"
                  />
                </div>

                <div className="border border-slate-200 rounded-xl overflow-hidden max-h-48 overflow-y-auto divide-y divide-slate-100 bg-white">
                  {reposLoading ? (
                    <div className="p-6 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-500" />
                      Cargando repositorios…
                    </div>
                  ) : repos.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500">
                      No se encontraron repositorios.
                    </div>
                  ) : (
                    repos.map((repo) => {
                      const isSelected = selectedRepo?.id === repo.id;
                      return (
                        <button
                          key={repo.id}
                          type="button"
                          onClick={() => void handleSelectRepo(repo)}
                          className={`w-full p-3 text-left transition-colors cursor-pointer flex items-center justify-between hover:bg-slate-50 ${
                            isSelected ? 'bg-slate-100/80 border-l-2 border-slate-900' : ''
                          }`}
                        >
                          <div className="min-w-0 flex-1 pr-2">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-xs text-slate-900 truncate">{repo.name}</span>
                              <span className="text-[10px] px-1.5 py-0.5 rounded border border-slate-200 text-slate-600 bg-white flex items-center gap-0.5">
                                {repo.private ? <Lock className="w-2.5 h-2.5" /> : <Globe className="w-2.5 h-2.5" />}
                                {repo.private ? 'Privado' : 'Público'}
                              </span>
                            </div>
                            {repo.description && (
                              <p className="text-[11px] text-slate-500 truncate mt-0.5">{repo.description}</p>
                            )}
                            <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-400">
                              {repo.language && <span className="font-medium text-slate-600">{repo.language}</span>}
                              {repo.stars > 0 && (
                                <span className="flex items-center gap-0.5 tabular-nums">
                                  <Star className="w-2.5 h-2.5 text-slate-400" />
                                  {repo.stars}
                                </span>
                              )}
                            </div>
                          </div>
                          {isSelected && (
                            <span className="p-1 rounded-full bg-slate-900 text-white shrink-0">
                              <Check className="w-3 h-3" />
                            </span>
                          )}
                        </button>
                      );
                    })
                  )}
                </div>

                {selectedRepo && (
                  <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                      <div className="min-w-0">
                        <span className="font-semibold text-xs text-slate-900 block truncate">{selectedRepo.full_name}</span>
                        <span className="text-[11px] text-slate-500">Configuración detectada</span>
                      </div>
                      {detecting ? (
                        <span className="text-[11px] text-slate-600 flex items-center gap-1">
                          <RefreshCw className="w-3 h-3 animate-spin" /> Analizando…
                        </span>
                      ) : detectedStack ? (
                        <span className="px-2 py-0.5 bg-white border border-slate-200 text-slate-700 rounded-md text-[11px] font-medium">
                          {detectedStack.framework}
                        </span>
                      ) : null}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      <div>
                        <label className="block font-medium text-slate-700 mb-1">Nombre del proyecto</label>
                        <input
                          type="text"
                          value={name}
                          onChange={(e) => setName(e.target.value)}
                          required
                          className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm"
                        />
                      </div>

                      <div>
                        <label className="block font-medium text-slate-700 mb-1 flex items-center justify-between">
                          <span>Rama</span>
                          {branchesLoading && <RefreshCw className="w-2.5 h-2.5 animate-spin" />}
                        </label>
                        <select
                          value={selectedBranch}
                          onChange={(e) => void handleBranchChange(e.target.value)}
                          className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm"
                        >
                          {branches.map((b) => (
                            <option key={b.name} value={b.name}>{b.name}</option>
                          ))}
                        </select>
                      </div>

                      <div>
                        <label className="block font-medium text-slate-700 mb-1">Comando de compilación</label>
                        <input
                          type="text"
                          value={buildCommand}
                          onChange={(e) => setBuildCommand(e.target.value)}
                          placeholder="npm run build"
                          className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                        />
                      </div>

                      <div>
                        <label className="block font-medium text-slate-700 mb-1">Comando de inicio</label>
                        <input
                          type="text"
                          value={startCommand}
                          onChange={(e) => setStartCommand(e.target.value)}
                          placeholder="npm start"
                          className="w-full px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                        />
                      </div>
                    </div>

                    <div className="pt-1 flex items-center justify-between text-[11px] text-slate-500">
                      <span className="flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                        Despliegue automático preparado para <code className="font-mono">{selectedBranch}</code>
                      </span>
                      <span className="font-mono text-slate-700 tabular-nums">Puerto {forgePort}</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Pestaña Manual */}
        {tab === 'manual' && (
          <div className="space-y-4">
            <div>
              <span className="block text-xs font-medium text-slate-700 mb-1.5">Plantillas rápidas</span>
              <div className="flex gap-1.5 flex-wrap">
                {[
                  { label: 'Node.js API', port: 3000, start: 'node index.js', build: '' },
                  { label: 'React / Vite', port: 5173, start: 'npm run dev', build: 'npm run build' },
                  { label: 'Python FastAPI', port: 8000, start: 'uvicorn main:app --reload', build: 'pip install -r requirements.txt' },
                  { label: 'Contenedor Docker', port: 8080, start: 'npm start', build: '' },
                ].map((tpl) => (
                  <button
                    key={tpl.label}
                    type="button"
                    onClick={() => {
                      setName(tpl.label);
                      setForgePort(tpl.port);
                      setStartCommand(tpl.start);
                      setBuildCommand(tpl.build);
                    }}
                    className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200/80 text-slate-700 rounded-md text-xs font-medium transition-colors cursor-pointer"
                  >
                    {tpl.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="projectName" className="block text-xs font-medium text-slate-700 mb-1">
                Nombre del proyecto
              </label>
              <input
                id="projectName"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm"
                placeholder="mi-aplicacion"
              />
            </div>

            <div>
              <label htmlFor="projectDesc" className="block text-xs font-medium text-slate-700 mb-1">
                Descripción
              </label>
              <input
                id="projectDesc"
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm"
                placeholder="Breve descripción (opcional)"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="projectPort" className="block text-xs font-medium text-slate-700 mb-1">
                  Puerto de desarrollo
                </label>
                <input
                  id="projectPort"
                  type="number"
                  value={forgePort}
                  onChange={(e) => setForgePort(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono tabular-nums"
                />
              </div>
              <div>
                <label htmlFor="projectCommand" className="block text-xs font-medium text-slate-700 mb-1">
                  Comando de inicio
                </label>
                <input
                  id="projectCommand"
                  type="text"
                  value={startCommand}
                  onChange={(e) => setStartCommand(e.target.value)}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Pie del modal */}
      <div className="px-5 py-3.5 border-t border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between gap-2">
        {tab !== 'manual' ? (
          <label className="inline-flex items-center gap-2 text-xs text-slate-600 cursor-pointer">
            <input
              type="checkbox"
              checked={deployOnCreate}
              onChange={(e) => setDeployOnCreate(e.target.checked)}
              className="rounded border-slate-300 accent-slate-900"
            />
            <span>Desplegar al crear</span>
          </label>
        ) : <span />}
        <div className="flex items-center gap-2 ml-auto">
        <button
          type="button"
          onClick={handleClose}
          disabled={loading}
          className="px-3.5 py-2 bg-white hover:bg-slate-50 text-slate-700 font-medium rounded-lg text-xs border border-slate-200 transition-colors cursor-pointer"
        >
          Cancelar
        </button>
        <button
          type="button"
          onClick={handleSubmit}
          disabled={loading || !name.trim() || (tab === 'github' && !selectedRepo)}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white font-medium rounded-lg text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5 cursor-pointer"
        >
          {loading ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              {tab === 'github' ? 'Importando…' : 'Creando…'}
            </>
          ) : deployOnCreate && tab !== 'manual' ? (
            'Crear y desplegar'
          ) : tab === 'github' ? (
            'Importar proyecto'
          ) : (
            'Crear proyecto'
          )}
        </button>
        </div>
      </div>
    </Modal>
  );
};
