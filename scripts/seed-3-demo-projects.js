const http = require('http');

const PORT = 3030;
const BASE_URL = `http://127.0.0.1:${PORT}`;

const demoProjects = [
  {
    id: 'proj_auracv_saas',
    name: 'AuraCV SaaS',
    description: 'Plataforma de generación de CVs inteligentes con IA y exportación PDF en tiempo real',
    icon: '💎',
    status: 'active',
    forgePort: 3002,
    citadelPort: 8082,
    trafficSplit: { forge: 15, citadel: 85 },
    gitRepo: 'pablo-developer/auracv-saas',
    gitBranch: 'main',
    githubOwner: 'pablo-developer',
    githubRepo: 'auracv-saas',
    buildCommand: 'npm run build',
    startCommand: 'npm start',
    domains: ['auracv.culkibo.dev'],
    envVars: {
      NODE_ENV: 'production',
      DATABASE_URL: 'postgresql://postgres:secret123@localhost:5432/auracv',
      OPENAI_API_KEY: 'sk-proj-sample-placeholder',
      PORT: '3000'
    },
    resources: [
      { id: 'res_app_1', name: 'AuraCV WebApp', type: 'app', status: 'running', port: 3000 },
      { id: 'res_db_1', name: 'PostgreSQL 16 DB', type: 'database', status: 'running', port: 5432 }
    ],
    volumes: [
      { name: 'pg-data', mount_path: '/var/lib/postgresql/data', host_path: '/opt/culkibo/volumes/pg-data' },
      { name: 'resumes-cache', mount_path: '/app/cache', host_path: '/opt/culkibo/volumes/resumes' }
    ],
    fileMounts: [
      { mount_path: '/etc/nginx/conf.d/proxy.conf', chmod: '644', chown: 'root:root' }
    ],
    lastCommit: {
      sha: '7f8c9d0',
      message: 'feat: actualización de motor PDF y plantilla Harvard',
      author: 'Pablo Developer',
      timestamp: new Date().toISOString()
    },
    lastDeployedAt: new Date().toISOString(),
    autoDeploy: true
  },
  {
    id: 'proj_mediamate_worker',
    name: 'MediaMate Worker',
    description: 'Worker de procesamiento de vídeo y audio en segundo plano con Redis Queue',
    icon: '⚡',
    status: 'active',
    forgePort: 3003,
    citadelPort: 8083,
    trafficSplit: { forge: 0, citadel: 100 },
    gitRepo: 'pablo-developer/mediamate-worker',
    gitBranch: 'main',
    githubOwner: 'pablo-developer',
    githubRepo: 'mediamate-worker',
    buildCommand: 'pip install -r requirements.txt',
    startCommand: 'uvicorn main:app --host 0.0.0.0 --port 8000',
    domains: ['media-api.culkibo.dev'],
    envVars: {
      PYTHONUNBUFFERED: '1',
      REDIS_URL: 'redis://localhost:6379/0',
      MAX_WORKERS: '4',
      TMP_DIR: '/tmp/transcode'
    },
    resources: [
      { id: 'res_api_2', name: 'FastAPI REST API', type: 'app', status: 'running', port: 8000 },
      { id: 'res_redis_2', name: 'Redis 7 Queue & Cache', type: 'database', status: 'running', port: 6379 }
    ],
    volumes: [
      { name: 'redis-data', mount_path: '/data', host_path: '/opt/culkibo/volumes/redis-data' },
      { name: 'yt-dlp-cache', mount_path: '/root/.cache/yt-dlp', host_path: '/opt/culkibo/volumes/ytdlp' }
    ],
    fileMounts: [],
    lastCommit: {
      sha: '3a1b2c4',
      message: 'perf: optimización ffmpeg hwaccel y cola asíncrona',
      author: 'Pablo Developer',
      timestamp: new Date().toISOString()
    },
    lastDeployedAt: new Date().toISOString(),
    autoDeploy: true
  },
  {
    id: 'proj_ai_voice_bot',
    name: 'AI Voice Bot',
    description: 'Agente conversacional en streaming con WebSockets sub-35ms y síntesis de voz',
    icon: '🤖',
    status: 'active',
    forgePort: 3004,
    citadelPort: 8084,
    trafficSplit: { forge: 50, citadel: 50 },
    gitRepo: 'pablo-developer/ai-voice-bot',
    gitBranch: 'main',
    githubOwner: 'pablo-developer',
    githubRepo: 'ai-voice-bot',
    buildCommand: 'npm run build',
    startCommand: 'node dist/server.js',
    domains: ['voice-agent.culkibo.dev'],
    envVars: {
      NODE_ENV: 'production',
      PORT: '8080',
      ELEVENLABS_API_KEY: 'el_sample_key_voice',
      DEEPGRAM_API_KEY: 'dg_sample_key_stt'
    },
    resources: [
      { id: 'res_voice_app', name: 'WebSocket Voice Server', type: 'app', status: 'running', port: 8080 }
    ],
    volumes: [
      { name: 'audio-recordings', mount_path: '/var/recordings', host_path: '/opt/culkibo/volumes/recordings' }
    ],
    fileMounts: [],
    lastCommit: {
      sha: '9e8d7c6',
      message: 'fix: reducción de latencia de audio a 18ms',
      author: 'Pablo Developer',
      timestamp: new Date().toISOString()
    },
    lastDeployedAt: new Date().toISOString(),
    autoDeploy: true
  }
];

function postJson(urlPath, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const req = http.request({
      hostname: '127.0.0.1',
      port: PORT,
      path: urlPath,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          resolve(body);
        }
      });
    });

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function seed() {
  console.log('🌱 Sembrando 3 proyectos en vivo en Culkibo API (http://localhost:3030)...\n');

  for (const proj of demoProjects) {
    try {
      const res = await postJson('/api/projects', proj);
      console.log(`  ✓ Proyecto creado: ${proj.icon} ${proj.name} (ID: ${res.id || proj.id})`);
    } catch (e) {
      console.error(`  ❌ Error creando ${proj.name}:`, e.message);
    }
  }

  // Registrar dominios de prueba
  try {
    await postJson('/api/domains', { hostname: 'auracv.culkibo.dev', targetPod: 'forge', port: 3002 });
    await postJson('/api/domains', { hostname: 'media-api.culkibo.dev', targetPod: 'citadel', port: 8083 });
    await postJson('/api/domains', { hostname: 'voice-agent.culkibo.dev', targetPod: 'forge', port: 3004 });
  } catch (e) {}

  console.log('\n✨ Los 3 proyectos están ahora cargados en caliente en el dashboard:');
  console.log('🔗 Abre http://localhost:3030 en tu navegador para interactuar con ellos.');
}

seed();
