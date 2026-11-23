import React, { useEffect, useId, useRef } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  subtitle?: string;
  maxWidthClass?: string;
  closeDisabled?: boolean;
  hideHeader?: boolean;
  ariaLabel?: string;
  children: React.ReactNode;
}

/**
 * Contenedor modal accesible y unificado para toda la interfaz:
 * - `role="dialog"`, `aria-modal="true"`, `aria-labelledby`
 * - Cierre con tecla `Escape` y clic en el fondo (salvo si `closeDisabled`)
 * - Bloqueo limpio de scroll del documento mientras está abierto
 * - Estética warm-zinc: `rounded-xl`, `bg-slate-900/25 backdrop-blur-[2px]`, borde `slate-200`
 */
export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  subtitle,
  maxWidthClass = 'max-w-lg',
  closeDisabled = false,
  hideHeader = false,
  ariaLabel,
  children,
}) => {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !closeDisabled) {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [open, closeDisabled, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/25 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !closeDisabled) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={!hideHeader && title ? titleId : undefined}
        aria-label={hideHeader || !title ? (ariaLabel || 'Diálogo') : undefined}
        className={`w-full ${maxWidthClass} bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden flex flex-col max-h-[90vh]`}
      >
        {!hideHeader && title && (
          <div className="px-5 py-4 border-b border-slate-200 flex items-start justify-between gap-4 shrink-0">
            <div className="min-w-0">
              <h2 id={titleId} className="text-base font-semibold text-slate-900 tracking-tight truncate">
                {title}
              </h2>
              {subtitle && (
                <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{subtitle}</p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              disabled={closeDisabled}
              aria-label="Cerrar diálogo"
              className="p-1.5 -mr-1 -mt-0.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors disabled:opacity-40 cursor-pointer shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
        <div className="overflow-y-auto flex-1">
          {children}
        </div>
      </div>
    </div>
  );
};
