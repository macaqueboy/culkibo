import React, { useState, useEffect } from 'react';
import {
  Globe,
  Search,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Database,
  Upload,
  ExternalLink,
  ShoppingBag,
  Cloud,
  Server,
  XCircle,
} from 'lucide-react';
import { api, type WordPressAnalysis, type ServiceInstallation, type DomainWizardPreset } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';

interface WordPressMigrationWizardProps {
  onComplete: () => void;
  onOpenCatalogInstalled?: () => void;
  onOpenDomains?: (preset?: DomainWizardPreset) => void;
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

const MAX_SQL_UPLOAD_BYTES = 50 * 1024 * 1024;

export const WordPressMigrationWizard: React.FC<WordPressMigrationWizardProps> = ({
  onComplete,
  onOpenCatalogInstalled,
  onOpenDomains,
  onNotify,
}) => {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [dockerOk, setDockerOk] = useState<boolean | null>(null);
  const [sourceUrl, setSourceUrl] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<WordPressAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [siteName, setSiteName] = useState('Mi WordPress');
  const [domainMode, setDomainMode] = useState<'sslip' | 'custom' | 'local'>('sslip');
  const [customDomain, setCustomDomain] = useState('');
  const [serverIp, setServerIp] = useState('');
  const [provisioning, setProvisioning] = useState(false);

  const [installation, setInstallation] = useState<ServiceInstallation | null>(null);
  const [wpAdminUrl, setWpAdminUrl] = useState('');
  const [previewUrl, setPreviewUrl] = useState('');
  const [checklist, setChecklist] = useState<string[]>([]);

  const [importMethod, setImportMethod] = useState<'plugin' | 'sql'>('plugin');
  const [sqlContent, setSqlContent] = useState('');
  const [sqlFile, setSqlFile] = useState<File | null>(null);
  const [oldDomain, setOldDomain] = useState('');
  const [importingSql, setImportingSql] = useState(false);
  const [sqlResult, setSqlResult] = useState<any>(null);

  useEffect(() => {
    let active = true;
    api.getServerIp()
      .then((res) => { if (active && res?.ip) setServerIp(res.ip); })
      .catch(() => {});
    api.getDbDockerStatus()
      .then((res) => { if (active) setDockerOk(Boolean(res?.available)); })
      .catch(() => { if (active) setDockerOk(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!installation?.id) return;
    const targetId = installation.id;

    const refresh = () => {
      api.getInstallations()
        .then((res) => {
          const found = (res.installations || []).find((i) => i.id === targetId);
          if (found) {
            setInstallation(found);
            if ((found.status === 'running' || found.status === 'degraded') && step === 3) {
              setStep(4);
            }
          }
        })
        .catch(() => {});
    };

    const offProg = liveEvents.onServiceProgress((ev) => {
      if (ev.id === targetId) {
        setInstallation((prev) => (prev ? { ...prev, progress: ev.progress || prev.progress } : prev));
      }
    });
    const offDone = liveEvents.onServiceInstalled((ev) => {
      if (ev?.id === targetId) refresh();
    });
    const offFail = liveEvents.onServiceFailed((ev) => {
      if (ev?.id === targetId) refresh();
    });

    const timer = installation.status === 'installing' ? setInterval(refresh, 2500) : null;
    return () => {
      offProg();
      offDone();
      offFail();
      if (timer) clearInterval(timer);
    };
  }, [installation?.id, installation?.status, step]);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sourceUrl.trim()) return;
    setAnalyzing(true);
    setError(null);
    try {
      const res = await api.analyzeWordPress(sourceUrl.trim());
      setAnalysis(res);
      setSiteName(res.siteName || 'Mi WordPress');
      setOldDomain(res.hostname || '');
    } catch (err: any) {
      setError(err?.message || 'No se pudo analizar esa URL');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleProvision = async () => {
    setProvisioning(true);
    setError(null);
    try {
      const res = await api.provisionWordPress({
        name: siteName.trim() || 'Mi WordPress',
        domain: domainMode === 'custom' ? customDomain.trim() || null : null,
        sourceUrl: analysis?.url || sourceUrl.trim() || null,
        useSslip: domainMode === 'sslip',
        serverIp: domainMode === 'sslip' ? serverIp.trim() || null : null,
      });
      setInstallation(res.installation);
      setPreviewUrl(res.previewUrl);
      setWpAdminUrl(res.wpAdminUrl);
      setChecklist(res.migrationChecklist || []);
      setStep(res.installation.status === 'running' ? 4 : 3);
      onNotify?.('Creando WordPress y MariaDB aislados en el servidor…', 'info');
    } catch (err: any) {
      setError(err?.message || 'No se pudo crear la instancia de WordPress');
    } finally {
      setProvisioning(false);
    }
  };

  const handleSqlFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > MAX_SQL_UPLOAD_BYTES) {
      setError('El archivo supera los 50 MB permitidos en subida directa. Comprímelo como .sql.gz o usa el plugin All-in-One WP Migration.');
      return;
    }
    setError(null);
    setSqlFile(file);
    setSqlContent('');
  };

  const handleImportSql = async () => {
    if (!installation?.id || (!sqlFile && !sqlContent.trim())) return;
    setImportingSql(true);
    setError(null);
    try {
      const res = sqlFile
        ? await api.uploadWordPressSql(sqlFile, {
            installationId: installation.id,
            oldDomain: oldDomain.trim() || analysis?.hostname || '',
            newDomain: previewUrl,
          })
        : await api.importWordPressSql({
            installationId: installation.id,
            sqlContent,
            oldDomain: oldDomain.trim() || analysis?.hostname || '',
            newDomain: previewUrl,
          });
      setSqlResult(res);
      setSqlFile(null);
      onNotify?.('Volcado SQL importado y URLs actualizadas', 'success');
    } catch (err: any) {
      setError(err?.message || 'Error al importar el archivo SQL');
    } finally {
      setImportingSql(false);
    }
  };

  const isRunning = installation?.status === 'running' || installation?.status === 'degraded';
  const isDegraded = installation?.status === 'degraded';
  const isInstallFailed = installation?.status === 'error';

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      <div className="p-5 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
            <Globe className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-900">Migrar WordPress a Culkibo</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Trae tu blog o tienda WooCommerce sin cortes, con MariaDB aislada, 512 MB de subida y HTTPS automático.
            </p>
          </div>
        </div>
        <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-white border border-slate-200 text-slate-700 self-start sm:self-auto tabular-nums">
          Paso {step} de 4
        </span>
      </div>

      {/* Stepper */}
      <div className="px-5 py-3 border-b border-slate-200 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        {[
          { n: 1, t: '1. Analizar web' },
          { n: 2, t: '2. Elegir destino' },
          { n: 3, t: '3. Crear servidor' },
          { n: 4, t: '4. Pasar contenido' },
        ].map((s) => (
          <div
            key={s.n}
            className={`px-2.5 py-1.5 rounded-lg font-medium text-center border ${
              step === s.n
                ? 'bg-slate-900 text-white border-slate-900'
                : step > s.n
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-50 text-slate-400 border-slate-200'
            }`}
          >
            {s.t}
          </div>
        ))}
      </div>

      <div className="p-5 space-y-5">
        {dockerOk === false && (
          <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600" />
            <span>Docker no está disponible ahora mismo. Puedes analizar webs WordPress, pero crear el servidor en el paso 2 requiere Docker en marcha.</span>
          </div>
        )}
        {error && (
          <div role="alert" className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
            <span>{error}</span>
          </div>
        )}

        {/* PASO 1 */}
        {step === 1 && (
          <div className="space-y-5">
            <form onSubmit={handleAnalyze} className="space-y-3">
              <label className="block text-xs font-medium text-slate-700">
                Dirección actual de tu web WordPress
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    type="text"
                    value={sourceUrl}
                    onChange={(e) => setSourceUrl(e.target.value)}
                    placeholder="https://mitienda.com"
                    className="w-full pl-9 pr-3 py-2 bg-white border border-slate-200 rounded-lg text-sm font-mono"
                  />
                </div>
                <button
                  type="submit"
                  disabled={analyzing || !sourceUrl.trim()}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  {analyzing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                  <span>{analyzing ? 'Analizando…' : 'Analizar web'}</span>
                </button>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                <span>Solo inspeccionamos metadatos públicos (versión, tema y plugins visibles).</span>
                <button
                  type="button"
                  onClick={() => { setAnalysis(null); setStep(2); }}
                  className="text-slate-700 hover:text-slate-900 underline font-medium cursor-pointer"
                >
                  Crear WordPress nuevo desde cero →
                </button>
              </div>
            </form>

            {analysis && (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-semibold text-slate-900">{analysis.siteName}</h3>
                      <span className={`text-[11px] font-medium px-2 py-0.5 rounded-full border ${
                        analysis.isWordPress
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}>
                        {analysis.isWordPress ? `WordPress ${analysis.wpVersion || 'detectado'}` : 'Señales WordPress no visibles'}
                      </span>
                      {analysis.hasWooCommerce && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full bg-white text-slate-700 border border-slate-200">
                          <ShoppingBag className="w-3 h-3" /> WooCommerce
                        </span>
                      )}
                      {analysis.usesCloudflare && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full bg-white text-slate-700 border border-slate-200">
                          <Cloud className="w-3 h-3" /> Cloudflare
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-1 font-mono">{analysis.url}</p>
                  </div>
                  <div className="text-xs text-slate-600 bg-white border border-slate-200 rounded-lg px-3 py-1.5 tabular-nums">
                    RAM recomendada: <strong className="text-slate-900">{analysis.estimatedRamMb} MB</strong>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-white border border-slate-200 rounded-lg">
                    <div className="text-slate-400 mb-0.5">Tema detectado</div>
                    <div className="font-mono font-medium text-slate-800">{analysis.theme || 'Oculto o personalizado'}</div>
                  </div>
                  <div className="p-3 bg-white border border-slate-200 rounded-lg">
                    <div className="text-slate-400 mb-0.5 tabular-nums">Plugins visibles ({analysis.plugins.length})</div>
                    <div className="font-mono text-slate-700 truncate" title={analysis.plugins.join(', ')}>
                      {analysis.plugins.length > 0 ? analysis.plugins.slice(0, 6).join(', ') : 'Ninguno expuesto públicamente'}
                    </div>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="text-xs font-medium text-slate-800">Plan de migración sin cortes:</div>
                  <ul className="space-y-1 text-xs text-slate-600 leading-relaxed">
                    {analysis.migrationPlan.map((line, i) => (
                      <li key={i}>{line}</li>
                    ))}
                  </ul>
                </div>

                <div className="flex justify-end pt-1">
                  <button
                    type="button"
                    onClick={() => setStep(2)}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
                  >
                    <span>Continuar y elegir destino</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* PASO 2 */}
        {step === 2 && (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">Nombre del sitio en Culkibo</label>
              <input
                type="text"
                value={siteName}
                onChange={(e) => setSiteName(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-sm"
                placeholder="Mi tienda WordPress"
              />
            </div>

            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-700">Dirección inicial</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {[
                  { id: 'sslip' as const, title: 'URL temporal sslip.io', desc: 'Prueba el sitio sin cortar la web actual.' },
                  { id: 'custom' as const, title: 'Dominio propio', desc: 'Usa tu dominio o un subdominio (nuevo.miweb.com).' },
                  { id: 'local' as const, title: 'Solo puerto local', desc: 'Conecta el dominio más tarde desde el catálogo.' },
                ].map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setDomainMode(opt.id)}
                    className={`p-3.5 rounded-xl border text-left cursor-pointer space-y-1 ${
                      domainMode === opt.id ? 'border-slate-900 bg-slate-50' : 'border-slate-200 bg-white hover:border-slate-300'
                    }`}
                  >
                    <div className="text-xs font-semibold text-slate-900">{opt.title}</div>
                    <p className="text-[11px] text-slate-500">{opt.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {domainMode === 'sslip' && (
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">IP pública del servidor</label>
                <input
                  type="text"
                  value={serverIp}
                  onChange={(e) => setServerIp(e.target.value)}
                  placeholder="203.0.113.10"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                />
              </div>
            )}

            {domainMode === 'custom' && (
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Dominio o subdominio</label>
                <input
                  type="text"
                  value={customDomain}
                  onChange={(e) => setCustomDomain(e.target.value)}
                  placeholder="nuevo.mitienda.com"
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg text-xs font-mono"
                />
              </div>
            )}

            <div className="flex items-center justify-between pt-3 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setStep(1)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium text-slate-600 border border-slate-200 hover:bg-slate-50 cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" /> Atrás
              </button>
              <button
                type="button"
                onClick={() => void handleProvision()}
                disabled={provisioning || !siteName.trim() || (domainMode === 'custom' && !customDomain.trim())}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
              >
                {provisioning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Server className="w-3.5 h-3.5" />}
                <span>{provisioning ? 'Creando WordPress + MariaDB…' : 'Crear WordPress'}</span>
              </button>
            </div>
          </div>
        )}

        {/* PASO 3 */}
        {step === 3 && installation && (
          <div className="space-y-4 py-2">
            <div className="flex items-center gap-3">
              {isInstallFailed ? (
                <XCircle className="w-5 h-5 text-red-600 shrink-0" />
              ) : (
                <Loader2 className="w-5 h-5 text-slate-700 animate-spin shrink-0" />
              )}
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  {isInstallFailed
                    ? `Error al instalar ${installation.name}`
                    : `Instalando ${installation.name} (WordPress 6.7 + MariaDB)`}
                </h3>
                <p className="text-xs text-slate-500">
                  {installation.progress?.label || 'Descargando contenedores y generando contraseñas aleatorias…'}
                </p>
              </div>
            </div>

            {installation.progress && (
              <div className="space-y-1.5">
                <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${isInstallFailed ? 'bg-red-500' : 'bg-slate-900'}`}
                    style={{ width: `${Math.round(((installation.progress.stepIndex + 1) / installation.progress.totalSteps) * 100)}%` }}
                  />
                </div>
                <p className="text-xs text-slate-500">{installation.progress.message}</p>
              </div>
            )}

            {installation.lastError && (
              <div role="alert" className="p-3.5 rounded-xl bg-red-50 border border-red-200 text-xs text-red-800">
                {installation.lastError}
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              {isInstallFailed ? (
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 border border-slate-200 hover:bg-slate-50 cursor-pointer"
                >
                  ← Volver y reintentar
                </button>
              ) : (
                <span className="text-xs text-slate-400">Avanzaremos automáticamente al terminar…</span>
              )}
              <button
                type="button"
                onClick={() => setStep(4)}
                className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 cursor-pointer"
              >
                Ver instrucciones de importación →
              </button>
            </div>
          </div>
        )}

        {/* PASO 4 */}
        {step === 4 && (
          <div className="space-y-4">
            {isRunning ? (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <div className="text-xs text-emerald-900">
                    <div className="font-semibold">WordPress en marcha en Culkibo</div>
                    <div className="font-mono mt-0.5">{previewUrl}</div>
                  </div>
                </div>
                {wpAdminUrl && (
                  <a
                    href={wpAdminUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-emerald-300 text-emerald-800 text-xs font-medium hover:bg-emerald-100 shrink-0"
                  >
                    <span>Abrir /wp-admin</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">
                    {isInstallFailed ? 'La instalación tuvo un error' : 'WordPress todavía se está iniciando'}
                  </div>
                  <p className="mt-0.5 text-amber-800">
                    {installation?.lastError || 'Espera a que el estado cambie a «En marcha» antes de importar el archivo SQL en MariaDB.'}
                  </p>
                </div>
              </div>
            )}

            <div className="flex gap-1 p-1 bg-slate-100 rounded-lg border border-slate-200 text-xs">
              <button
                type="button"
                onClick={() => setImportMethod('plugin')}
                className={`flex-1 py-1.5 px-3 rounded-md font-medium cursor-pointer ${
                  importMethod === 'plugin' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Opción A: Plugin en 1 archivo (hasta 512 MB)
              </button>
              <button
                type="button"
                onClick={() => setImportMethod('sql')}
                className={`flex-1 py-1.5 px-3 rounded-md font-medium cursor-pointer ${
                  importMethod === 'sql' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Opción B: Volcado .sql directo
              </button>
            </div>

            {importMethod === 'plugin' ? (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 text-xs text-slate-700 leading-relaxed">
                <div className="font-semibold text-slate-900">Pasos recomendados (512 MB de subida configurados):</div>
                <ol className="list-decimal list-inside space-y-1.5">
                  {checklist.length > 0 ? checklist.map((c, idx) => <li key={idx}>{c}</li>) : (
                    <>
                      <li>En tu WordPress actual instala <strong>All-in-One WP Migration</strong> y pulsa <strong>Exportar → Archivo</strong>.</li>
                      <li>Abre <code className="font-mono">{wpAdminUrl || '/wp-admin'}</code> en tu nuevo WordPress, instala el mismo plugin e importa el archivo.</li>
                      <li>Comprueba páginas, imágenes y productos antes de cambiar el DNS.</li>
                      <li>Conecta tu dominio definitivo con HTTPS automático desde Dominios o desde Servicios instalados.</li>
                    </>
                  )}
                </ol>
              </div>
            ) : (
              <div className="space-y-3 p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="p-3 rounded-lg bg-white border border-slate-200 text-[11px] text-slate-600 leading-relaxed">
                  <strong className="text-slate-900">Importante sobre imágenes y archivos:</strong> el archivo <code className="font-mono">.sql</code> importa entradas, páginas, usuarios, pedidos y ajustes de MariaDB. Si quieres trasladar también las imágenes de <code className="font-mono">wp-content/uploads</code> y plugins en un solo paso, usa la <strong>Opción A</strong> (hasta 512 MB ya preconfigurados).
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">Dominio antiguo (para reescribir URLs)</label>
                    <input
                      type="text"
                      value={oldDomain}
                      onChange={(e) => setOldDomain(e.target.value)}
                      placeholder="mitienda.com"
                      className="w-full px-3 py-2 bg-white border border-slate-200 rounded-lg font-mono"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">Subir archivo .sql o .sql.gz (streaming hasta 50 MB)</label>
                    <label className="flex items-center justify-center gap-1.5 px-3 py-2 bg-white border border-slate-200 rounded-lg cursor-pointer hover:bg-slate-50 font-medium text-slate-700">
                      <Upload className="w-3.5 h-3.5" />
                      <span className="truncate">{sqlFile ? `${sqlFile.name} (${(sqlFile.size / (1024 * 1024)).toFixed(1)} MB)` : 'Elegir .sql o .sql.gz'}</span>
                      <input type="file" accept=".sql,.gz,.sql.gz,.txt" onChange={handleSqlFile} className="hidden" />
                    </label>
                  </div>
                </div>

                {!sqlFile && (
                  <textarea
                    value={sqlContent}
                    onChange={(e) => setSqlContent(e.target.value)}
                    rows={5}
                    placeholder="-- O pega aquí un volcado SQL pequeño de WordPress…"
                    className="w-full p-3 bg-white border border-slate-200 rounded-lg font-mono text-xs"
                  />
                )}

                {isDegraded && (
                  <p className="text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-lg p-2.5">
                    El contenedor arrancó con aviso de salud; si la importación falla, revisa los registros en Catálogo → Instalados.
                  </p>
                )}

                {sqlResult && (
                  <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
                    {sqlResult.message}
                  </div>
                )}

                <button
                  type="button"
                  onClick={() => void handleImportSql()}
                  disabled={importingSql || (!sqlFile && !sqlContent.trim()) || !installation?.id || !isRunning}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                >
                  {importingSql ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
                  <span>{importingSql ? 'Importando en MariaDB…' : 'Importar SQL y actualizar URLs'}</span>
                </button>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-100">
              <button
                type="button"
                onClick={onOpenCatalogInstalled || onComplete}
                className="px-3.5 py-2 rounded-lg text-xs font-medium text-slate-700 border border-slate-200 bg-white hover:bg-slate-50 cursor-pointer"
              >
                Ver servicios instalados
              </button>
              {onOpenDomains && (
                <button
                  type="button"
                  onClick={() =>
                    onOpenDomains(
                      installation
                        ? {
                            serviceId: installation.id,
                            serviceName: installation.name,
                            targetPort: installation.hostPort || undefined,
                            suggestedHostname: oldDomain.trim() || analysis?.hostname || undefined,
                          }
                        : undefined
                    )
                  }
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Conectar dominio definitivo →</span>
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
