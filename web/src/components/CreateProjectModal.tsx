import React, { useState, useEffect, useRef } from 'react';
import { X, Search, GitBranch, Star, Lock, Globe, ExternalLink, RefreshCw, CheckCircle2, Sparkles, Check } from 'lucide-react';
import { api, type GitHubStatus, type GitHubRepo, type GitHubBranch, type GitHubAutoDetectResult } from '../lib/api';

interface CreateProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const EMOJIS = ['🚀', '⚡', '🌐', '📦', '🤖', '🎮', '💎', '🔥', '🐳', '🐍'];

export const CreateProjectModal: React.FC<CreateProjectModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [tab, setTab] = useState<'manual' | 'github'>('manual');

  // Manual form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [icon, setIcon] = useState(EMOJIS[0]);
  const [forgePort, setForgePort] = useState(3000);
  const [startCommand, setStartCommand] = useState('npm start');
  const [buildCommand, setBuildCommand] = useState('');
  const [loading, setLoading] = useState(false);

  // GitHub state
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
  const searchTimeoutRef = useRef<any>(null);

  const loadRepositories = async (search = '') => {
    setReposLoading(true);
    setGhError(null);
    try {
      const res = await api.getGitHubRepos({ perPage: 100, search });
      setRepos(res.repos);
    } catch (e: any) {
      setGhError(e.message || 'Error al listar repositorios de GitHub');
    } finally {
      setReposLoading(false);
    }
  };

  const checkGitHubStatus = async () => {
    try {
      const status = await api.getGitHubStatus();
      setGhStatus(status);
      if (status.connected) {
        loadRepositories();
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
    return () => { active = false; };
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
      setGhError(e.message || 'Error al conectar token con GitHub');
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

    // Fetch branches and auto-detect in parallel
    setBranchesLoading(true);
    setDetecting(true);
    setDetectedStack(null);

    try {
      const branchList = await api.getGitHubBranches(repo.owner.login, repo.name);
      setBranches(branchList);
      if (branchList.length > 0 && !branchList.some(b => b.name === defaultBr)) {
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
      if (detected.icon) setIcon(detected.icon);
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
      if (detected.icon) setIcon(detected.icon);
      if (detected.port) setForgePort(detected.port);
      if (detected.startCommand) setStartCommand(detected.startCommand);
      if (detected.buildCommand) setBuildCommand(detected.buildCommand);
    } catch (e) {
      console.error(e);
    } finally {
      setDetecting(false);
    }
  };

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setLoading(true);
    try {
      const isGitHub = tab === 'github' && Boolean(selectedRepo);
      const projectPayload: any = {
        name: name.trim(),
        description: description.trim(),
        icon,
        status: 'active',
        forgePort: forgePort || 3000,
        citadelPort: 8000 + (crypto.getRandomValues(new Uint16Array(1))[0] % 1000),
        trafficSplit: { forge: 100, citadel: 0 },
        domains: [],
        envVars: detectedStack?.envVars || {},
        source: isGitHub ? 'github' : 'manual',
        startCommand,
        buildCommand,
        gitRepo: isGitHub && selectedRepo ? selectedRepo.clone_url : '',
        gitBranch: isGitHub ? selectedBranch : 'main',
        githubOwner: isGitHub && selectedRepo ? selectedRepo.owner.login : '',
        githubRepo: isGitHub && selectedRepo ? selectedRepo.name : '',
        watchPaths: detectedStack?.watchPaths || ['src/**', 'public/**'],
        autoDeploy: isGitHub ? true : false
      };

      const created = await api.createProject(projectPayload);
      if (created && created.id) {
        await api.activateProject(created.id);
      }
      onSuccess();
      onClose();
      resetForm();
    } catch (err: any) {
      console.error(err);
      setGhError(err.message || 'Error al guardar el proyecto');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setName('');
    setDescription('');
    setIcon(EMOJIS[0]);
    setForgePort(3000);
    setStartCommand('npm start');
    setBuildCommand('');
    setSelectedRepo(null);
    setDetectedStack(null);
    setRepoSearch('');
    setGhError(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 animate-in fade-in duration-150">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-xl overflow-hidden border border-slate-200">
        {/* Header */}
        <div className="flex justify-between items-center p-4 border-b border-slate-100 bg-slate-50/60">
          <div>
            <h2 className="text-lg font-bold text-slate-900">Nuevo Proyecto</h2>
            <p className="text-xs text-slate-500">Crea un entorno de despliegue ultrarrápido en tiempo real</p>
          </div>
          <button onClick={onClose} className="p-1.5 hover:bg-slate-200/70 rounded-lg text-slate-400 hover:text-slate-700 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="flex border-b border-slate-200 bg-slate-50/40 p-1.5 gap-1.5">
          <button
            type="button"
            onClick={() => setTab('manual')}
            className={`flex-1 py-2 px-3 text-xs font-semibold rounded-xl transition-all flex items-center justify-center gap-2 ${tab === 'manual' ? 'bg-white text-slate-900 shadow-sm border border-slate-200/80' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'}`}
          >
            <span>🚀</span> Plantillas Rápidas / Manual
          </button>
          <button
            type="button"
            onClick={() => {
              setTab('github');
              if (!ghStatus?.connected) checkGitHubStatus();
            }}
            className={`flex-1 py-2 px-3 text-xs font-semibold rounded-xl transition-all flex items-center justify-center gap-2 ${tab === 'github' ? 'bg-white text-slate-900 shadow-sm border border-slate-200/80' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'}`}
          >
            <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
            </svg>
            Crear desde GitHub
            {ghStatus?.connected && (
              <span className="w-2 h-2 rounded-full bg-emerald-500" title="Cuenta conectada" />
            )}
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 max-h-[75vh] overflow-y-auto space-y-4">
          {ghError && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
              <span className="font-bold">Error:</span> {ghError}
            </div>
          )}

          {/* GITHUB TAB CONTENT */}
          {tab === 'github' && (
            <div className="space-y-4">
              {/* Not connected to GitHub */}
              {!ghStatus?.connected ? (
                <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 text-center space-y-4">
                  <div className="w-12 h-12 rounded-2xl bg-slate-900 text-white flex items-center justify-center mx-auto shadow-sm">
                    <svg className="w-7 h-7 fill-current" viewBox="0 0 24 24">
                      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-900">Conecta tu cuenta de GitHub</h3>
                    <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
                      Vincula tu Personal Access Token (PAT) con permisos <code className="bg-slate-200 px-1 py-0.5 rounded">repo</code> para importar proyectos con 1 clic y desplegar automáticamente con cada push.
                    </p>
                  </div>

                  <form onSubmit={handleConnectGitHub} className="space-y-3 max-w-md mx-auto text-left">
                    <div>
                      <input
                        type="password"
                        value={ghToken}
                        onChange={(e) => setGhToken(e.target.value)}
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                        className="w-full px-3.5 py-2.5 bg-white border border-slate-300 rounded-xl text-xs font-mono focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <a
                        href="https://github.com/settings/tokens/new?scopes=repo,read:user&description=Culkibo%20Cloud"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-600 hover:text-blue-800 font-medium inline-flex items-center gap-1 hover:underline"
                      >
                        Crear token en GitHub en 1 clic
                        <ExternalLink className="w-3 h-3" />
                      </a>
                      <button
                        type="submit"
                        disabled={ghConnecting || !ghToken.trim()}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold transition-colors disabled:opacity-50 flex items-center gap-1.5"
                      >
                        {ghConnecting && <RefreshCw className="w-3 h-3 animate-spin" />}
                        {ghConnecting ? 'Verificando...' : 'Conectar GitHub'}
                      </button>
                    </div>
                  </form>
                </div>
              ) : (
                /* Connected to GitHub: Show profile + repo browser */
                <div className="space-y-4">
                  {/* Connected user badge */}
                  <div className="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-200/80">
                    <div className="flex items-center gap-2.5">
                      <img
                        src={ghStatus.user?.avatar_url}
                        alt={ghStatus.user?.login}
                        className="w-8 h-8 rounded-full border border-slate-200"
                      />
                      <div>
                        <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                          {ghStatus.user?.name || ghStatus.user?.login}
                          <span className="text-[10px] text-slate-500 font-normal">(@{ghStatus.user?.login})</span>
                        </div>
                        <span className="text-[10px] text-emerald-700 font-semibold flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" /> Conectado a GitHub
                        </span>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => loadRepositories(repoSearch)}
                      className="p-1.5 hover:bg-slate-200/70 rounded-lg text-slate-600 transition-colors"
                      title="Refrescar repositorios"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${reposLoading ? 'animate-spin' : ''}`} />
                    </button>
                  </div>

                  {/* Repository Search */}
                  <div>
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
                            loadRepositories(val);
                          }, 250);
                        }}
                        placeholder="Buscar repositorio en tu cuenta..."
                        className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                      />
                    </div>
                  </div>

                  {/* Repositories List */}
                  <div className="border border-slate-200 rounded-xl overflow-hidden max-h-48 overflow-y-auto divide-y divide-slate-100 bg-white">
                    {reposLoading ? (
                      <div className="p-6 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
                        <RefreshCw className="w-4 h-4 animate-spin text-blue-600" />
                        Cargando repositorios...
                      </div>
                    ) : repos.length === 0 ? (
                      <div className="p-6 text-center text-xs text-slate-500">
                        No se encontraron repositorios coincidentes.
                      </div>
                    ) : (
                      repos.map((repo) => {
                        const isSelected = selectedRepo?.id === repo.id;
                        return (
                          <div
                            key={repo.id}
                            onClick={() => handleSelectRepo(repo)}
                            className={`p-3 text-left transition-colors cursor-pointer flex items-center justify-between hover:bg-blue-50/50 ${isSelected ? 'bg-blue-50/80 border-l-4 border-blue-600' : ''}`}
                          >
                            <div className="min-w-0 flex-1 pr-2">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-xs text-slate-900 truncate">{repo.name}</span>
                                <span className="text-[10px] px-1.5 py-0.5 rounded-full border text-slate-600 bg-slate-50 flex items-center gap-0.5">
                                  {repo.private ? <Lock className="w-2.5 h-2.5" /> : <Globe className="w-2.5 h-2.5" />}
                                  {repo.private ? 'Privado' : 'Público'}
                                </span>
                              </div>
                              {repo.description && (
                                <p className="text-[11px] text-slate-500 truncate mt-0.5">{repo.description}</p>
                              )}
                              <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-400">
                                {repo.language && (
                                  <span className="font-medium text-slate-600 flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                                    {repo.language}
                                  </span>
                                )}
                                {repo.stars > 0 && (
                                  <span className="flex items-center gap-0.5">
                                    <Star className="w-2.5 h-2.5 fill-amber-400 text-amber-400" />
                                    {repo.stars}
                                  </span>
                                )}
                              </div>
                            </div>
                            {isSelected && (
                              <div className="p-1 rounded-full bg-blue-600 text-white">
                                <Check className="w-3.5 h-3.5" />
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>

                  {/* Selected Repository Configuration */}
                  {selectedRepo && (
                    <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-3 animate-in fade-in duration-150">
                      <div className="flex items-center justify-between pb-2 border-b border-slate-200/80">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">{icon}</span>
                          <div>
                            <span className="font-bold text-xs text-slate-900 block">{selectedRepo.full_name}</span>
                            <span className="text-[10px] text-slate-500">Configuración inferida automáticamente</span>
                          </div>
                        </div>

                        {detecting ? (
                          <span className="text-[11px] text-blue-600 flex items-center gap-1">
                            <RefreshCw className="w-3 h-3 animate-spin" /> Analizando stack...
                          </span>
                        ) : detectedStack ? (
                          <span className="px-2 py-0.5 bg-blue-100/70 border border-blue-200 text-blue-800 rounded-full text-[10px] font-bold flex items-center gap-1">
                            <Sparkles className="w-3 h-3 text-blue-600" />
                            {detectedStack.framework}
                          </span>
                        ) : null}
                      </div>

                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <label className="block font-medium text-slate-700 mb-1">Nombre del Proyecto</label>
                          <input
                            type="text"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            required
                            className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-semibold focus:outline-none focus:border-blue-500"
                          />
                        </div>

                        <div>
                          <label className="block font-medium text-slate-700 mb-1 flex items-center justify-between">
                            <span className="flex items-center gap-1">
                              <GitBranch className="w-3 h-3 text-slate-500" />
                              Rama (Branch)
                            </span>
                            {branchesLoading && <RefreshCw className="w-2.5 h-2.5 animate-spin" />}
                          </label>
                          <select
                            value={selectedBranch}
                            onChange={(e) => handleBranchChange(e.target.value)}
                            className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs focus:outline-none focus:border-blue-500"
                          >
                            {branches.map((b) => (
                              <option key={b.name} value={b.name}>
                                {b.name}
                              </option>
                            ))}
                          </select>
                        </div>

                        <div>
                          <label className="block font-medium text-slate-700 mb-1">Comando Build</label>
                          <input
                            type="text"
                            value={buildCommand}
                            onChange={(e) => setBuildCommand(e.target.value)}
                            placeholder="npm run build"
                            className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-mono focus:outline-none focus:border-blue-500"
                          />
                        </div>

                        <div>
                          <label className="block font-medium text-slate-700 mb-1">Comando Start</label>
                          <input
                            type="text"
                            value={startCommand}
                            onChange={(e) => setStartCommand(e.target.value)}
                            placeholder="npm start"
                            className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-mono focus:outline-none focus:border-blue-500"
                          />
                        </div>
                      </div>

                      <div className="pt-2 flex items-center justify-between text-[11px] text-slate-500">
                        <span className="flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          Auto-deploy en tiempo real activo para <code className="font-mono">{selectedBranch}</code>
                        </span>
                        <span className="font-mono text-slate-700 font-bold">Puerto: {forgePort}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* MANUAL TAB CONTENT */}
          {tab === 'manual' && (
            <div className="space-y-4">
              <div>
 <label className="block text-xs font-semibold text-slate-700 mb-2">Plantillas Rápidas</label>
                <div className="flex gap-2 flex-wrap">
                  <button type="button" onClick={() => { setName('Node.js API'); setIcon('🚀'); setForgePort(3000); setStartCommand('node index.js'); setBuildCommand(''); }} className="px-3 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full text-xs font-medium transition-colors">Node.js API</button>
                  <button type="button" onClick={() => { setName('React / Vite'); setIcon('⚡'); setForgePort(5173); setStartCommand('npm run dev'); setBuildCommand('npm run build'); }} className="px-3 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full text-xs font-medium transition-colors">React / Vite</button>
                  <button type="button" onClick={() => { setName('Python FastAPI'); setIcon('🔥'); setForgePort(8000); setStartCommand('uvicorn main:app --reload'); setBuildCommand('pip install -r requirements.txt'); }} className="px-3 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full text-xs font-medium transition-colors">Python FastAPI</button>
                  <button type="button" onClick={() => { setName('Docker Compose'); setIcon('🐳'); setForgePort(8080); setStartCommand('docker-compose up -d'); setBuildCommand('docker build -t app .'); }} className="px-3 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full text-xs font-medium transition-colors">Docker Compose</button>
                </div>
              </div>

              <div>
 <label className="block text-xs font-semibold text-slate-700 mb-1.5">Icono</label>
                <div className="flex gap-1.5 flex-wrap">
                  {EMOJIS.map((emoji) => (
                    <button
                      key={emoji}
                      type="button"
                      onClick={() => setIcon(emoji)}
                      className={`w-9 h-9 flex items-center justify-center text-lg rounded-xl transition-all ${icon === emoji ? 'bg-blue-100 border-blue-500 border-2' : 'bg-slate-50 border border-slate-200 hover:bg-slate-100'}`}
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              </div>

              <div>
 <label htmlFor="projectName" className="block text-xs font-semibold text-slate-700 mb-1">Nombre del proyecto</label>
                <input
                  id="projectName"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                  placeholder="Mi proyecto asombroso"
                />
              </div>

              <div>
 <label htmlFor="projectDesc" className="block text-xs font-semibold text-slate-700 mb-1">Descripción</label>
                <input
                  id="projectDesc"
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                  placeholder="Breve descripción (opcional)"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
 <label htmlFor="projectPort" className="block text-xs font-semibold text-slate-700 mb-1">Puerto de desarrollo</label>
                  <input
                    id="projectPort"
                    type="number"
                    value={forgePort}
                    onChange={(e) => setForgePort(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                  />
                </div>
                <div>
 <label htmlFor="projectCommand" className="block text-xs font-semibold text-slate-700 mb-1">Comando de inicio</label>
                  <input
                    id="projectCommand"
                    type="text"
                    value={startCommand}
                    onChange={(e) => setStartCommand(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50/60 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 bg-white hover:bg-slate-100 text-slate-700 font-medium rounded-xl text-sm border border-slate-200 transition-colors"
          >
            Cancelar
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={loading || !name.trim() || (tab === 'github' && !selectedRepo)}
            className="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm flex items-center gap-2"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                {tab === 'github' ? 'Importando y Desplegando...' : 'Guardando...'}
              </>
            ) : tab === 'github' ? (
              'Importar y Desplegar'
            ) : (
              'Guardar Proyecto'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
