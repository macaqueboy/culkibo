import React from 'react';

interface CulkiboLogoProps {
  size?: number;
  className?: string;
}

/**
 * Marca propietaria de Culkibo: «Twin Planes K».
 * - Espina vertical blanca: plano de control determinista.
 * - Plano ascendente en ámbar forja (#F59E0B): The Forge (Live Sync en milisegundos).
 * - Plano descendente en blanco puro: The Citadel (producción endurecida sin caídas).
 * - Corte óptico de 2 px entre los dos planos para legibilidad a 16 px y 48 px.
 */
export const CulkiboLogo: React.FC<CulkiboLogoProps> = ({ size = 28, className = '' }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 32 32"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
    className={`shrink-0 ${className}`}
  >
    <rect width="32" height="32" rx="8" fill="#111113" />
    <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" stroke="#FFFFFF" strokeOpacity="0.1" />
    {/* Espina del plano de control */}
    <rect x="8.5" y="7" width="4" height="18" rx="1.25" fill="#FFFFFF" />
    {/* Plano superior (The Forge) — Ámbar forja */}
    <path d="M14.5 15.1L21.3 7H25.2L17.9 15.6L14.5 15.1Z" fill="#F59E0B" />
    {/* Plano inferior (The Citadel) — Blanco puro */}
    <path d="M14.5 16.9L18.1 16.4L25.4 25H21.2L14.5 16.9Z" fill="#FFFFFF" />
  </svg>
);
