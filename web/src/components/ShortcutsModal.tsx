import React, { useEffect } from 'react';
import { Keyboard, X } from 'lucide-react';

interface ShortcutsModalProps {
  open: boolean;
  onClose: () => void;
}

const GROUPS: Array<{
  title: string;
  items: Array<{ keys: string[]; label: string }>;
}> = [
  {
    title: 'General',
    items: [
      { keys: ['Ctrl', 'K'], label: 'Abrir búsqueda y paleta de comandos (⌘K en Mac)' },
      { keys: ['?'], label: 'Mostrar u ocultar estos atajos de teclado' },
      { keys: ['n'], label: 'Crear un nuevo proyecto' },
      { keys: ['Esc'], label: 'Cerrar ventana o panel abierto' },
    ],
  },
  {
    title: 'Navegación rápida (pulsa g y luego la letra)',
    items: [
      { keys: ['g', 'p'], label: 'Ir a Proyectos' },
      { keys: ['g', 'f'], label: 'Ir a Flota de servidores (SSH)' },
      { keys: ['g', 'u'], label: 'Ir a Uptime, Estado y Ahorro' },
      { keys: ['g', 'm'], label: 'Ir a Métricas y Doctor del sistema' },
      { keys: ['g', 'd'], label: 'Ir a Dominios, HTTPS y túneles' },
      { keys: ['g', 'c'], label: 'Ir al Catálogo de servicios (1 clic)' },
      { keys: ['g', 'i'], label: 'Ir a Importar y migrar' },
      { keys: ['g', 'a'], label: 'Ir a Agentes IA (MCP)' },
      { keys: ['g', 'l'], label: 'Ir a Registros en directo' },
      { keys: ['g', 's'], label: 'Ir a Ajustes, Backups y DR' },
    ],
  },
];

export const ShortcutsModal: React.FC<ShortcutsModalProps> = ({ open, onClose }) => {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/25 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Atajos de teclado"
        className="culkibo-modal-enter w-full max-w-lg bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden"
      >
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-200">
          <div className="flex items-center gap-2">
            <Keyboard className="w-4 h-4 text-slate-600" />
            <h2 className="text-sm font-semibold text-slate-900">Atajos de teclado</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Cerrar atajos"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 max-h-[70vh] overflow-y-auto">
          {GROUPS.map((group) => (
            <div key={group.title}>
              <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                {group.title}
              </h3>
              <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg overflow-hidden">
                {group.items.map((item) => (
                  <div
                    key={item.label}
                    className="flex items-center justify-between gap-4 px-3.5 py-2.5 bg-white text-xs"
                  >
                    <span className="text-slate-700">{item.label}</span>
                    <span className="flex items-center gap-1 shrink-0">
                      {item.keys.map((k, idx) => (
                        <React.Fragment key={k + idx}>
                          {idx > 0 && <span className="text-slate-300 text-[10px]">+</span>}
                          <kbd className="px-1.5 py-0.5 text-[11px] font-mono font-medium text-slate-700 bg-slate-100 border border-slate-200 rounded">
                            {k}
                          </kbd>
                        </React.Fragment>
                      ))}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="px-5 py-2.5 border-t border-slate-100 bg-slate-50/70 text-[11px] text-slate-500 flex items-center justify-between">
          <span>Los atajos se desactivan automáticamente al escribir en campos de texto.</span>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-700 font-medium hover:text-slate-900 cursor-pointer"
          >
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
};
