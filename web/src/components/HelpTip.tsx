import React, { useState, useRef, useEffect } from 'react';
import { HelpCircle, X } from 'lucide-react';

interface HelpTipProps {
  title?: string;
  children: React.ReactNode;
  align?: 'left' | 'right' | 'center';
  className?: string;
  label?: string;
}

/**
 * Explicación contextual discreta en español claro.
 * Evita modales intrusivos y explica conceptos de servidor justo donde aparecen.
 */
export const HelpTip: React.FC<HelpTipProps> = ({
  title,
  children,
  align = 'left',
  className = '',
  label,
}) => {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const posClass =
    align === 'right'
      ? 'right-0'
      : align === 'center'
        ? 'left-1/2 -translate-x-1/2'
        : 'left-0';

  return (
    <span ref={rootRef} className={`relative inline-flex items-center align-middle ${className}`}>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        aria-expanded={open}
        aria-label={label || (title ? `Ayuda sobre ${title}` : 'Mostrar explicación')}
        title={title || '¿Qué es esto?'}
        className="inline-flex items-center justify-center w-6 h-6 -m-1 rounded-full text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
      >
        <HelpCircle className="w-3.5 h-3.5" />
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={title || 'Explicación'}
          onClick={(e) => e.stopPropagation()}
          className={`culkibo-modal-enter absolute top-full mt-1.5 z-50 w-72 max-w-[85vw] rounded-xl bg-white border border-slate-200 shadow-lg p-3 text-left text-xs text-slate-600 leading-relaxed font-normal ${posClass}`}
        >
          <div className="flex items-start justify-between gap-2 mb-1">
            {title ? (
              <span className="font-semibold text-slate-900 text-xs">{title}</span>
            ) : (
              <span className="font-semibold text-slate-900 text-xs">Ayuda rápida</span>
            )}
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Cerrar explicación"
              className="p-0.5 -mr-1 -mt-0.5 text-slate-400 hover:text-slate-700 rounded cursor-pointer shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="space-y-1.5">{children}</div>
        </div>
      )}
    </span>
  );
};
