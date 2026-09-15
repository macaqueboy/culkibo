const fs = require('fs');
const path = require('path');

const srcDir = 'c:\\Users\\pablo\\Desktop\\Culkibo\\web\\src';

function walkSync(dir, filelist) {
  let files = fs.readdirSync(dir);
  filelist = filelist || [];
  files.forEach(function(file) {
    if (fs.statSync(path.join(dir, file)).isDirectory()) {
      filelist = walkSync(path.join(dir, file), filelist);
    }
    else {
      filelist.push(path.join(dir, file));
    }
  });
  return filelist;
}

const files = walkSync(srcDir);

files.forEach(file => {
  if (!file.endsWith('.tsx') && !file.endsWith('.ts')) return;

  let content = fs.readFileSync(file, 'utf8');
  const original = content;

  // P1
  content = content.replace(/The Forge/g, 'Desarrollo');
  content = content.replace(/The Citadel/g, 'Producción');
  content = content.replace(/Enrutador Ingress/g, 'Enrutador');
  content = content.replace(/Edge Connections/g, 'Conexiones de Borde');
  content = content.replace(/Ingress routes/g, 'Rutas de Enrutamiento');
  content = content.replace(/Cloudflare DNS-01 ACME Wildcard/g, 'Validación automática de dominio');
  content = content.replace(/Zero-Config sslip\.io \/ nip\.io TLS/g, 'Dominios de prueba automáticos');
  content = content.replace(/con balanceo atómico de tráfico \(zero-downtime\)/g, 'sin interrupciones para los usuarios');
  
  if (file.includes('DomainManager.tsx')) {
    content = content.replace(/Pod/g, 'Entorno');
    content = content.replace(/pod/g, 'entorno');
    // Revert code variables
    content = content.replace(/targetEntorno/g, 'targetPod');
    content = content.replace(/currentEntorno/g, 'currentPod');
    content = content.replace(/nextEntorno/g, 'nextPod');
  }

  // P2
  content = content.replace(/Domain \$\{newHostname\} added successfully/g, 'Dominio ${newHostname} añadido con éxito');
  content = content.replace(/Cloudflare Proxy \(Orange ☁️\) enabled for \$\{hostname\}/g, 'Proxy Cloudflare activado para ${hostname}');
  content = content.replace(/Cloudflare Proxy disabled \(DNS Only ☁️\) for \$\{hostname\}/g, 'Proxy Cloudflare desactivado para ${hostname}');
  content = content.replace(/Traffic for \$\{hostname\} re-routed to/g, 'Tráfico de ${hostname} redirigido a');
  content = content.replace(/Are you sure you want to remove domain \$\{name\}\?/g, '¿Confirmas eliminar el dominio ${name}?');
  content = content.replace(/Domain \$\{name\} removed/g, 'Dominio ${name} eliminado');
  content = content.replace(/Initiating ACME DNS-01 challenge order with Cloudflare\.\.\./g, 'Iniciando verificación de dominio con Cloudflare...');
  content = content.replace(/Wildcard certificate successfully issued & active for \$\{wildcardDomain\}!/g, '¡Certificado Wildcard emitido para ${wildcardDomain}!');
  content = content.replace(/Wildcard SSL issued for \$\{wildcardDomain\}/g, 'SSL Wildcard emitido para ${wildcardDomain}');
  content = content.replace(/SSL Issuance error:/g, 'Error de emisión SSL:');
  content = content.replace(/Zero-Config sslip\.io TLS issued for \$\{res\.cert\.domain\}/g, 'Certificado automático emitido para ${res.cert.domain}');
  
  // App.tsx
  content = content.replace(/Traffic routed: \$\{parsed\.data\.citadel\}% Citadel \/ \$\{parsed\.data\.forge\}% Forge/g, 'Tráfico: ${parsed.data.citadel}% Producción / ${parsed.data.forge}% Desarrollo');
  content = content.replace(/Wildcard SSL issued for \$\{parsed\.data\.domain\}!/g, '¡SSL Wildcard emitido para ${parsed.data.domain}!');
  content = content.replace(/AI Agent executed tool: \$\{parsed\.data\.toolName\}/g, 'Agente IA ejecutó: ${parsed.data.toolName}');

  // P3
  content = content.replace(/shadow-xs/g, 'shadow-sm');
  content = content.replace(/shadow-2xl/g, 'shadow-xl');

  if (content !== original) {
    fs.writeFileSync(file, content);
  }
});
console.log('Done');
