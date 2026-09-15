import React, { useState } from 'react';
import { Shield, GitBranch, Tag, RefreshCw, X } from 'lucide-react';
import { api } from '../lib/api';

interface DeployModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const DeployModal: React.FC<DeployModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [imageTag, setImageTag] = useState('v1.0.1');
  const [description, setDescription] = useState('Versión estable para producción');
  const [deploying, setDeploying] = useState(false);
  const [stage, setStage] = useState<string | null>(null);

  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleDeploy = async (e: React.FormEvent) => {
    e.preventDefault();
    setDeploying(true);
    setError(null);
    setStage('Preparando despliegue atómico sin caídas...');

    try {
      const res = await api.deployRelease(imageTag, description);
      if (res.success) {
        setStage('¡Despliegue a Producción completado con éxito!');
        setTimeout(() => {
          setDeploying(false);
          setStage(null);
          onSuccess();
          onClose();
        }, 800);
      } else {
        setError(res.error || 'Fallo en el despliegue');
        setDeploying(false);
      }
    } catch (err: any) {
      setError(err.message || 'Fallo en el despliegue');
      setDeploying(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-xs p-4">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4 text-slate-900">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-blue-600">
            <Shield className="w-5 h-5" />
            <h3 className="text-base font-bold text-slate-900">
              Desplegar a Producción
            </h3>
          </div>
          <button
            onClick={onClose}
            disabled={deploying}
            className="text-slate-400 hover:text-slate-700 p-1 rounded-lg hover:bg-slate-100 cursor-pointer transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-600 leading-relaxed">
          Pasa los cambios actuales de desarrollo a la versión de producción estable sin interrupciones para los usuarios.
        </p>

        <form onSubmit={handleDeploy} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5 flex items-center gap-1.5">
              <Tag className="w-3.5 h-3.5 text-blue-600" />
              Etiqueta de Versión
            </label>
            <input
              type="text"
              value={imageTag}
              onChange={(e) => setImageTag(e.target.value)}
              disabled={deploying}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 font-mono focus:outline-none focus:bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 transition-all"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5 flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-blue-600" />
              Descripción o Cambios
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={deploying}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-xl text-xs text-slate-900 focus:outline-none focus:bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 transition-all"
              required
            />
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 font-medium">
              {error}
            </div>
          )}

          {stage && (
            <div className="p-3 bg-blue-50 border border-blue-200 rounded-xl text-xs font-medium text-blue-800 flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" />
              <span>{stage}</span>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={onClose}
              disabled={deploying}
              className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 cursor-pointer transition-colors"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={deploying}
              className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm flex items-center gap-2 cursor-pointer transition-all active:scale-95 disabled:opacity-50"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>{deploying ? 'Desplegando...' : 'Confirmar Despliegue'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
