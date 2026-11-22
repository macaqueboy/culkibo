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
  Sparkles,
  Server
} from 'lucide-react';
import { api, type WordPressAnalysis, type ServiceInstallation } from '../lib/api';
import { liveEvents } from '../lib/liveEvents';

interface WordPressMigrationWizardProps {
  onComplete: () => void;
  onOpenDomains?: () => void;
  onNotify?: (msg: string) => void;
}

export const WordPressMigrationWizard: React.FC<WordPressMigrationWizardProps> = ({
  onComplete,
  onOpenDomains,
  onNotify
}) => {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [sourceUrl, setSourceUrl] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<WordPressAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Step 2: destino
  const [siteName, setSiteName] = useState('Mi WordPress');
  const [domainMode, setDomainMode] = useState<'sslip' | 'custom' | 'local'>('sslip');
  const [customDomain, setCustomDomain] = useState('');
  const [serverIp, setServerIp] = useState('');
  const [provisioning, setProvisioning] = useState(false);

  // Step 3: instalación en curso
  const [installation, setInstallation] = useState<ServiceInstallation | null>(null);
  const [wpAdminUrl, setWpAdminUrl] = useState('');
  const [previewUrl, setPreviewUrl] = useState('');
  const [checklist, setChecklist] = useState<string[]>([]);

  // Step 4: SQL import
  const [importMethod, setImportMethod] = useState<'plugin' | 'sql'>('plugin');
  const [sqlContent, setSqlContent] = useState('');
  const [oldDomain, setOldDomain] = useState('');
  const [importingSql, setImportingSql] = useState(false);
  const [sqlResult, setSqlResult] = useState<any>(null);

  useEffect(() => {
    let active = true;
    api.getServerIp()
      .then((res) => { if (active && res?.ip) setServerIp(res.ip); })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  // Escuchar progreso en directo mientras se instala WordPress + MariaDB
  useEffect(() => {
    if (!installation?.id) return;
    const targetId = installation.id;

    const refresh = () => {
      api.getInstallations()
        .then((res) => {
          const found = (res.installations || []).find((i) => i.id === targetId);
          if (found) {
            setInstallation(found);
            if (found.status === 'running' && step === 3) {
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
        serverIp: domainMode === 'sslip' ? serverIp.trim() || null : null
      });
      setInstallation(res.installation);
      setPreviewUrl(res.previewUrl);
      setWpAdminUrl(res.wpAdminUrl);
      setChecklist(res.migrationChecklist || []);
      setStep(res.installation.status === 'running' ? 4 : 3);
      onNotify?.('Creando WordPress + MariaDB aislada en tu servidor…');
    } catch (err: any) {
      setError(err?.message || 'No se pudo crear la instancia de WordPress');
    } finally {
      setProvisioning(false);
    }
  };

  const handleSqlFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setSqlContent(String(reader.result || ''));
    };
    reader.readAsText(file);
  };

  const handleImportSql = async () => {
    if (!installation?.id || !sqlContent.trim()) return;
    setImportingSql(true);
    setError(null);
    try {
      const res = await api.importWordPressSql({
        installationId: installation.id,
        sqlContent,
        oldDomain: oldDomain.trim() || analysis?.hostname || '',
        newDomain: previewUrl
      });
      setSqlResult(res);
      onNotify?.('Volcado SQL importado y URLs actualizadas');
    } catch (err: any) {
      setError(err?.message || 'Error al importar el archivo SQL');
    } finally {
      setImportingSql(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
      <div className="p-6 bg-slate-50 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-200 text-blue-600 flex items-center justify-center shrink-0">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-900">Migrar tu web de WordPress a Culkibo</h2>
            <p className="text-xs text-slate-500">
              Trae tu blog o tienda WooCommerce sin cortes, con MariaDB aislada, límite de 512 MB y HTTPS automático.
            </p>
          </div>
        </div>
        <span className="text-xs font-semibold px-3 py-1 rounded-full bg-white border border-slate-200 text-slate-700 self-start sm:self-auto">
          Paso {step} de 4
        </span>
      </div>

      {/* Stepper */}
      <div className="px-6 py-3 border-b border-slate-100 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        {[
          { n: 1, t: '1. Analizar web' },
          { n: 2, t: '2. Elegir destino' },
          { n: 3, t: '3. Crear servidor' },
          { n: 4, t: '4. Pasar contenido' }
        ].map((s) => (
          <div
            key={s.n}
            className={`px-3 py-1.5 rounded-lg font-medium text-center border ${
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

      <div className="p-6 space-y-5">
        {error && (
          <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* STEP 1 */}
        {step === 1 && (
          <div className="space-y-5">
            <form onSubmit={handleAnalyze} className="space-y-3">
              <label className="block text-sm font-semibold text-slate-800">
                ¿Cuál es la dirección actual de tu web WordPress?
              </label>
              <div className="flex flex-col sm:flex-row gap-2.5">
                <div className="relative flex-1">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    value={sourceUrl}
                    onChange={(e) => setSourceUrl(e.target.value)}
                    placeholder="https://mitienda.com"
                    className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-300 rounded-xl text-sm font-mono focus:outline-none"
                  />
                </div>
                <button
                  type="submit"
                  disabled={analyzing || !sourceUrl.trim()}
                  className="px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold inline-flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {analyzing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                  <span>{analyzing ? 'Analizando…' : 'Analizar mi web'}</span>
                </button>
              </div>
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>No tocamos nada de tu web actual; solo leemos su versión, tema y plugins públicos.</span>
                <button
                  type="button"
                  onClick={() => { setAnalysis(null); setStep(2); }}
                  className="text-blue-600 hover:underline font-semibold cursor-pointer"
                >
                  O empezar WordPress nuevo desde cero →
                </button>
              </div>
            </form>

            {analysis && (
              <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-base font-bold text-slate-900">{analysis.siteName}</h3>
                      <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${
                        analysis.isWordPress
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}>
                        {analysis.isWordPress ? `WordPress ${analysis.wpVersion || 'detectado'}` : 'Señales WordPress no visibles'}
                      </span>
                      {analysis.hasWooCommerce && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                          <ShoppingBag className="w-3 h-3" /> WooCommerce
                        </span>
                      )}
                      {analysis.usesCloudflare && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-orange-50 text-orange-700 border border-orange-200">
                          <Cloud className="w-3 h-3" /> Cloudflare
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-1 font-mono">{analysis.url}</p>
                  </div>
                  <div className="text-xs text-slate-600 bg-white border border-slate-200 rounded-xl px-3 py-2">
                    RAM recomendada: <strong className="text-slate-900">{analysis.estimatedRamMb} MB</strong>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-white border border-slate-200 rounded-xl">
                    <div className="text-slate-400 font-medium mb-1">Tema detectado</div>
                    <div className="font-mono font-semibold text-slate-800">{analysis.theme || 'Oculto o personalizado'}</div>
                  </div>
                  <div className="p-3 bg-white border border-slate-200 rounded-xl">
                    <div className="text-slate-400 font-medium mb-1">Plugins visibles ({analysis.plugins.length})</div>
                    <div className="font-mono text-slate-700 truncate" title={analysis.plugins.join(', ')}>
                      {analysis.plugins.length > 0 ? analysis.plugins.slice(0, 6).join(', ') : 'Ninguno expuesto públicamente'}
                    </div>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-slate-800">Plan de migración sin cortes:</div>
                  <ul className="space-y-1 text-xs text-slate-600 leading-relaxed">
                    {analysis.migrationPlan.map((line, i) => (
                      <li key={i}>{line}</li>
                    ))}
                  </ul>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => setStep(2)}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold cursor-pointer"
                  >
                    <span>Continuar y preparar destino</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* STEP 2 */}
        {step === 2 && (
          <div className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">Nombre de tu web en Culkibo</label>
              <input
                type="text"
                value={siteName}
                onChange={(e) => setSiteName(e.target.value)}
                className="w-full px-3.5 py-2.5 bg-white border border-slate-300 rounded-xl text-sm"
                placeholder="Mi Tienda WordPress"
              />
            </div>

            <div className="space-y-2.5">
              <div className="text-xs font-semibold text-slate-700">¿En qué dirección quieres abrir este WordPress primero?</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setDomainMode('sslip')}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer space-y-1 ${
                    domainMode === 'sslip' ? 'border-slate-900 bg-slate-50' : 'border-slate-200 bg-white'
                  }`}
                >
                  <div className="text-xs font-bold text-slate-900">URL temporal gratis (recomendado)</div>
                  <p className="text-[11px] text-slate-500">Prueba todo en <code className="font-mono">sslip.io</code> sin cortar tu web actual.</p>
                </button>
                <button
                  type="button"
                  onClick={() => setDomainMode('custom')}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer space-y-1 ${
                    domainMode === 'custom' ? 'border-slate-900 bg-slate-50' : 'border-slate-200 bg-white'
                  }`}
                >
                  <div className="text-xs font-bold text-slate-900">Dominio propio</div>
                  <p className="text-[11px] text-slate-500">Usa ya tu dominio o un subdominio como <code className="font-mono">nuevo.miweb.com</code>.</p>
                </button>
                <button
                  type="button"
                  onClick={() => setDomainMode('local')}
                  className={`p-3.5 rounded-xl border text-left cursor-pointer space-y-1 ${
                    domainMode === 'local' ? 'border-slate-900 bg-slate-50' : 'border-slate-200 bg-white'
                  }`}
                >
                  <div className="text-xs font-bold text-slate-900">Solo puerto local</div>
                  <p className="text-[11px] text-slate-500">Conectarás el dominio más tarde desde la pestaña Dominios.</p>
                </button>
              </div>
            </div>

            {domainMode === 'sslip' && (
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">IP pública de tu servidor (detectada automáticamente)</label>
                <input
                  type="text"
                  value={serverIp}
                  onChange={(e) => setServerIp(e.target.value)}
                  placeholder="Ej. 203.0.113.10"
                  className="w-full px-3.5 py-2 bg-white border border-slate-300 rounded-xl text-xs font-mono"
                />
              </div>
            )}

            {domainMode === 'custom' && (
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1.5">Dominio o subdominio</label>
                <input
                  type="text"
                  value={customDomain}
                  onChange={(e) => setCustomDomain(e.target.value)}
                  placeholder="nuevo.mitienda.com"
                  className="w-full px-3.5 py-2 bg-white border border-slate-300 rounded-xl text-xs font-mono"
                />
              </div>
            )}

            <div className="flex items-center justify-between pt-3 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setStep(1)}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:bg-slate-100 cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" /> Atrás
              </button>
              <button
                type="button"
                onClick={handleProvision}
                disabled={provisioning || !siteName.trim() || (domainMode === 'custom' && !customDomain.trim())}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold cursor-pointer disabled:opacity-50"
              >
                {provisioning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Server className="w-4 h-4" />}
                <span>{provisioning ? 'Creando WordPress + MariaDB…' : 'Crear WordPress ahora'}</span>
              </button>
            </div>
          </div>
        )}

        {/* STEP 3 */}
        {step === 3 && installation && (
          <div className="space-y-4 py-4">
            <div className="flex items-center gap-3">
              <Loader2 className="w-5 h-5 text-blue-600 animate-spin shrink-0" />
              <div>
                <h3 className="text-sm font-bold text-slate-900">Instalando {installation.name} (WordPress 6.7 + MariaDB)</h3>
                <p className="text-xs text-slate-500">
                  {installation.progress?.label || 'Descargando contenedores y generando contraseñas seguras…'}
                </p>
              </div>
            </div>

            {installation.progress && (
              <div className="space-y-1.5">
                <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full bg-slate-900 transition-all duration-500"
                    style={{ width: `${Math.round(((installation.progress.stepIndex + 1) / installation.progress.totalSteps) * 100)}%` }}
                  />
                </div>
                <p className="text-xs text-slate-500">{installation.progress.message}</p>
              </div>
            )}

            {installation.lastError && (
              <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800">
                {installation.lastError}
              </div>
            )}

            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setStep(4)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 cursor-pointer"
              >
                Continuar a instrucciones de importación →
              </button>
            </div>
          </div>
        )}

        {/* STEP 4 */}
        {step === 4 && (
          <div className="space-y-5">
            <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div className="text-xs text-emerald-900">
                  <div className="font-bold text-sm">Tu WordPress ya está listo en Culkibo</div>
                  <div className="font-mono mt-0.5">{previewUrl}</div>
                </div>
              </div>
              {wpAdminUrl && (
                <a
                  href={wpAdminUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-white border border-emerald-300 text-emerald-800 text-xs font-semibold hover:bg-emerald-100 shrink-0"
                >
                  <span>Abrir /wp-admin</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              )}
            </div>

            <div className="flex gap-2 p-1 bg-slate-100 rounded-xl border border-slate-200 text-xs">
              <button
                type="button"
                onClick={() => setImportMethod('plugin')}
                className={`flex-1 py-2 px-3 rounded-lg font-semibold cursor-pointer ${
                  importMethod === 'plugin' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Opción A: Sin tocar código (Plugin en 1 archivo)
              </button>
              <button
                type="button"
                onClick={() => setImportMethod('sql')}
                className={`flex-1 py-2 px-3 rounded-lg font-semibold cursor-pointer ${
                  importMethod === 'sql' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Opción B: Subir volcado .sql directo
              </button>
            </div>

            {importMethod === 'plugin' ? (
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 text-xs text-slate-700 leading-relaxed">
                <div className="font-bold text-slate-900">Pasos más sencillos (512 MB de subida ya activados):</div>
                <ol className="list-decimal list-inside space-y-1.5">
                  {checklist.length > 0 ? checklist.map((c, idx) => <li key={idx}>{c}</li>) : (
                    <>
                      <li>En tu WordPress antiguo instala el plugin gratuito <strong>All-in-One WP Migration</strong> y pulsa <strong>Exportar → Archivo</strong>.</li>
                      <li>Abre <code className="font-mono">{wpAdminUrl || '/wp-admin'}</code> en tu nuevo WordPress de Culkibo, instala el mismo plugin y arrastra tu archivo.</li>
                      <li>Verifica que tus páginas, imágenes y productos se ven bien.</li>
                      <li>Pulsa el botón de abajo para apuntar tu dominio definitivo con HTTPS automático.</li>
                    </>
                  )}
                </ol>
              </div>
            ) : (
              <div className="space-y-3 p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">Dominio antiguo (para actualizar URLs)</label>
                    <input
                      type="text"
                      value={oldDomain}
                      onChange={(e) => setOldDomain(e.target.value)}
                      placeholder="mitienda.com"
                      className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg font-mono"
                    />
                  </div>
                  <div>
                    <label className="block font-semibold text-slate-700 mb-1">Cargar archivo .sql</label>
                    <label className="flex items-center justify-center gap-1.5 px-3 py-2 bg-white border border-slate-300 rounded-lg cursor-pointer hover:bg-slate-50 font-medium text-slate-700">
                      <Upload className="w-3.5 h-3.5" />
                      <span>Elegir archivo .sql</span>
                      <input type="file" accept=".sql,.txt" onChange={handleSqlFile} className="hidden" />
                    </label>
                  </div>
                </div>

                <textarea
                  value={sqlContent}
                  onChange={(e) => setSqlContent(e.target.value)}
                  rows={5}
                  placeholder="-- O pega aquí tu volcado SQL de WordPress..."
                  className="w-full p-3 bg-white border border-slate-300 rounded-xl font-mono text-xs"
                />

                {sqlResult && (
                  <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
                    {sqlResult.message}
                  </div>
                )}

                <button
                  type="button"
                  onClick={handleImportSql}
                  disabled={importingSql || !sqlContent.trim() || !installation?.id}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  {importingSql ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
                  <span>{importingSql ? 'Importando en MariaDB…' : 'Importar SQL y actualizar URLs'}</span>
                </button>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-100">
              <button
                type="button"
                onClick={onComplete}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 cursor-pointer"
              >
                Ir a mis servicios
              </button>
              {onOpenDomains && (
                <button
                  type="button"
                  onClick={onOpenDomains}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer"
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Conectar mi dominio definitivo →</span>
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
