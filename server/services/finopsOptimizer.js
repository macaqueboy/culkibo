/**
 * Motor Zero-Dep de FinOps, Right-Sizing de RAM/CPU y Comparativa Honesta Cloud vs Self-Hosted.
 *
 * - 0 dependencias npm externas, 0 invocaciones de shell, 0 mutaciones en disco.
 * - Compara costes reales de VPS publicados (Hetzner, OVHcloud, Vultr, DigitalOcean) frente
 *   a tarifas públicas documentadas de Vercel Pro, Railway, Render y Managed Postgres/Redis,
 *   con notas al pie transparentes y cálculos 100% deterministas (invariantes no-negativos).
 */

/** @type {Record<string, any>} */
const CLOUD_PRICING_PROFILES = Object.freeze({
  vercelPro: Object.freeze({
    id: 'vercel_pro',
    name: 'Vercel Pro',
    seatMonthlyUsd: 20,
    includedBandwidthGb: 1000,
    extraBandwidthPer100GbUsd: 15,
    extraAppUsageUsd: 6,
    footnote: 'Vercel Pro published tier ($20/seat/mo + $15 per extra 100 GB bandwidth; excludes managed databases).'
  }),
  railway: Object.freeze({
    id: 'railway_pro',
    name: 'Railway Pro',
    planBaseMonthlyUsd: 20,
    ramPerGbMonthUsd: 10,
    vcpuPerCoreMonthUsd: 20,
    egressPerGbUsd: 0.05,
    footnote: 'Railway usage pricing (~$10/GB RAM-month, ~$20/vCPU-month, $0.05/GB egress, $20 Pro seat baseline).'
  }),
  render: Object.freeze({
    id: 'render_standard',
    name: 'Render',
    starterAppMonthlyUsd: 7,
    standardAppMonthlyUsd: 25,
    managedPostgresMonthlyUsd: 19,
    managedValkeyMonthlyUsd: 10,
    includedBandwidthGb: 100,
    extraBandwidthPer100GbUsd: 30,
    footnote: 'Render published tiers ($7 Starter / $25 Standard web service, $19/mo Managed Postgres, $10/mo Key Value).'
  }),
  managedPostgres: Object.freeze({
    id: 'managed_postgres',
    name: 'Managed Postgres (Neon / Supabase / RDS equiv.)',
    monthlyPerDbUsd: 19,
    footnote: 'Managed production Postgres baseline ($19/mo per instance; HA replicas cost significantly more).'
  }),
  managedRedis: Object.freeze({
    id: 'managed_redis',
    name: 'Managed Redis / Valkey',
    monthlyPerDbUsd: 10,
    footnote: 'Managed Redis/Valkey cache baseline ($10/mo per instance).'
  })
});

/** @type {ReadonlyArray<{ id: string, provider: string, name: string, vcpus: number, ramGb: number, diskGb: number, bandwidthTb: number, monthlyUsd: number, regionHint: string }>} */
const VPS_CATALOG = Object.freeze([
  // Hetzner Cloud (best price/perf baseline)
  Object.freeze({ id: 'hetzner-cx22', provider: 'Hetzner', name: 'CX22', vcpus: 2, ramGb: 4, diskGb: 40, bandwidthTb: 20, monthlyUsd: 4.59, regionHint: 'EU / US-East' }),
  Object.freeze({ id: 'hetzner-cx32', provider: 'Hetzner', name: 'CX32', vcpus: 4, ramGb: 8, diskGb: 80, bandwidthTb: 20, monthlyUsd: 8.29, regionHint: 'EU / US-East' }),
  Object.freeze({ id: 'hetzner-cx42', provider: 'Hetzner', name: 'CX42', vcpus: 8, ramGb: 16, diskGb: 160, bandwidthTb: 20, monthlyUsd: 17.99, regionHint: 'EU / US-East' }),
  Object.freeze({ id: 'hetzner-cx52', provider: 'Hetzner', name: 'CX52', vcpus: 16, ramGb: 32, diskGb: 320, bandwidthTb: 20, monthlyUsd: 35.99, regionHint: 'EU / US-East' }),
  // OVHcloud
  Object.freeze({ id: 'ovh-vps-2', provider: 'OVHcloud', name: 'VPS-2', vcpus: 4, ramGb: 8, diskGb: 75, bandwidthTb: 20, monthlyUsd: 6.70, regionHint: 'EU / NA' }),
  Object.freeze({ id: 'ovh-vps-3', provider: 'OVHcloud', name: 'VPS-3', vcpus: 8, ramGb: 16, diskGb: 150, bandwidthTb: 20, monthlyUsd: 12.90, regionHint: 'EU / NA' }),
  Object.freeze({ id: 'ovh-vps-4', provider: 'OVHcloud', name: 'VPS-4', vcpus: 12, ramGb: 24, diskGb: 250, bandwidthTb: 20, monthlyUsd: 24.50, regionHint: 'EU / NA' }),
  // Vultr
  Object.freeze({ id: 'vultr-vc2-4g', provider: 'Vultr', name: 'vc2-2c-4gb', vcpus: 2, ramGb: 4, diskGb: 80, bandwidthTb: 3, monthlyUsd: 20.00, regionHint: 'Global 32 regions' }),
  Object.freeze({ id: 'vultr-vc2-8g', provider: 'Vultr', name: 'vc2-4c-8gb', vcpus: 4, ramGb: 8, diskGb: 160, bandwidthTb: 4, monthlyUsd: 40.00, regionHint: 'Global 32 regions' }),
  Object.freeze({ id: 'vultr-vc2-16g', provider: 'Vultr', name: 'vc2-6c-16gb', vcpus: 6, ramGb: 16, diskGb: 320, bandwidthTb: 5, monthlyUsd: 80.00, regionHint: 'Global 32 regions' }),
  // DigitalOcean
  Object.freeze({ id: 'do-s-4g', provider: 'DigitalOcean', name: 'Basic 4GB', vcpus: 2, ramGb: 4, diskGb: 80, bandwidthTb: 4, monthlyUsd: 24.00, regionHint: 'Global' }),
  Object.freeze({ id: 'do-s-8g', provider: 'DigitalOcean', name: 'Basic 8GB', vcpus: 4, ramGb: 8, diskGb: 160, bandwidthTb: 5, monthlyUsd: 48.00, regionHint: 'Global' }),
  Object.freeze({ id: 'do-s-16g', provider: 'DigitalOcean', name: 'Basic 16GB', vcpus: 8, ramGb: 16, diskGb: 320, bandwidthTb: 6, monthlyUsd: 96.00, regionHint: 'Global' })
]);

const CULKIBO_OVERHEAD_MB = 128; // ~50 MB Culkibo + ~20 MB Caddy + OS headroom

/** @param {number} n */
function round2(n) {
  return Math.round(Math.max(0, Number(n) || 0) * 100) / 100;
}

/** @param {number} n */
function round1(n) {
  return Math.round(Math.max(0, Number(n) || 0) * 10) / 10;
}

/** Redondea una recomendación de RAM a un escalón limpio de contenedor (128/256/384/512/768/1024...). */
function snapMemoryTierMb(rawMb) {
  const n = Math.max(128, Number(rawMb) || 128);
  const steps = [128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192];
  for (const s of steps) {
    if (s >= n) return s;
  }
  return Math.ceil(n / 1024) * 1024;
}

/**
 * Selecciona el VPS más económico que cubre la RAM, vCPU y ancho de banda requeridos.
 * @param {number} requiredRamGb
 * @param {number} requiredVcpus
 * @param {number} bandwidthGb
 * @param {string | null} [providerFilter]
 */
function pickBestVps(requiredRamGb, requiredVcpus, bandwidthGb, providerFilter = null) {
  const bwTb = bandwidthGb / 1000;
  const pool = providerFilter
    ? VPS_CATALOG.filter((v) => v.provider.toLowerCase() === String(providerFilter).toLowerCase())
    : [...VPS_CATALOG];
  const candidates = (pool.length > 0 ? pool : [...VPS_CATALOG]).sort((a, b) => a.monthlyUsd - b.monthlyUsd);

  const exact = candidates.find(
    (v) => v.ramGb >= requiredRamGb && v.vcpus >= requiredVcpus && v.bandwidthTb >= bwTb
  );
  if (exact) return { ...exact, nodeCount: 1, totalMonthlyUsd: exact.monthlyUsd };

  // Si excede un solo nodo del catálogo, escalar horizontalmente con el nodo mayor
  const largest = candidates.reduce((best, cur) => (cur.ramGb > best.ramGb ? cur : best), candidates[0]);
  const nodesByRam = Math.ceil(requiredRamGb / largest.ramGb);
  const nodesByCpu = Math.ceil(requiredVcpus / largest.vcpus);
  const nodeCount = Math.max(1, nodesByRam, nodesByCpu);
  return {
    ...largest,
    nodeCount,
    totalMonthlyUsd: round2(largest.monthlyUsd * nodeCount)
  };
}

class FinOpsOptimizer {
  /**
   * Calculadora pura de costes Cloud SaaS vs Self-Hosted VPS con Culkibo.
   *
   * @param {{
   *   apps?: number,
   *   databases?: number,
   *   avgRamMbPerApp?: number,
   *   avgRamMbPerDb?: number,
   *   monthlyBandwidthGb?: number,
   *   teamSeats?: number,
   *   preferredProvider?: string | null
   * }} [opts]
   */
  compareCloudCosts(opts = {}) {
    const apps = Math.max(0, Math.min(500, Math.round(Number(opts.apps ?? 3) || 0)));
    const databases = Math.max(0, Math.min(200, Math.round(Number(opts.databases ?? 2) || 0)));
    const avgRamMbPerApp = Math.max(64, Math.min(32768, Number(opts.avgRamMbPerApp ?? 512) || 512));
    const avgRamMbPerDb = Math.max(128, Math.min(32768, Number(opts.avgRamMbPerDb ?? 512) || 512));
    const monthlyBandwidthGb = Math.max(0, Math.min(100000, Number(opts.monthlyBandwidthGb ?? 250) || 0));
    const teamSeats = Math.max(1, Math.min(100, Math.round(Number(opts.teamSeats ?? 2) || 1)));
    const preferredProvider = opts.preferredProvider ? String(opts.preferredProvider).trim() : 'Hetzner';

    const workloadRamMb = (apps * avgRamMbPerApp) + (databases * avgRamMbPerDb);
    const totalRequiredRamMb = workloadRamMb + CULKIBO_OVERHEAD_MB;
    // Factor de margen 1.25x para picos de despliegue Blue/Green sin OOM
    const requiredRamGb = Math.max(2, Math.ceil((totalRequiredRamMb * 1.25) / 1024));
    const requiredVcpus = Math.max(2, Math.ceil((apps * 0.35) + (databases * 0.5)));

    // 1. Vercel Pro + Managed DBs (Postgres/Valkey)
    const vp = CLOUD_PRICING_PROFILES.vercelPro;
    const vercelExtraBw = Math.max(0, monthlyBandwidthGb - vp.includedBandwidthGb);
    const vercelBwUsd = Math.ceil(vercelExtraBw / 100) * vp.extraBandwidthPer100GbUsd;
    const managedDbUsd = databases * CLOUD_PRICING_PROFILES.managedPostgres.monthlyPerDbUsd;
    const vercelPlusManagedDbUsd = round2(
      (teamSeats * vp.seatMonthlyUsd) + (apps * vp.extraAppUsageUsd) + vercelBwUsd + managedDbUsd
    );

    // 2. Railway Pro (uso RAM + vCPU proporcional + egress)
    const rw = CLOUD_PRICING_PROFILES.railway;
    const railwayRamGb = workloadRamMb / 1024;
    const railwayAvgVcpu = (apps * 0.25) + (databases * 0.3);
    const railwayMonthlyUsd = round2(
      rw.planBaseMonthlyUsd +
      (railwayRamGb * rw.ramPerGbMonthUsd) +
      (railwayAvgVcpu * rw.vcpuPerCoreMonthUsd) +
      (monthlyBandwidthGb * rw.egressPerGbUsd)
    );

    // 3. Render (Starter para <=512 MB, Standard para >512 MB + Managed DBs)
    const rn = CLOUD_PRICING_PROFILES.render;
    const renderUnitAppUsd = avgRamMbPerApp > 512 ? rn.standardAppMonthlyUsd : rn.starterAppMonthlyUsd;
    const renderExtraBw = Math.max(0, monthlyBandwidthGb - rn.includedBandwidthGb);
    const renderBwUsd = Math.ceil(renderExtraBw / 100) * rn.extraBandwidthPer100GbUsd;
    const renderMonthlyUsd = round2(
      (apps * renderUnitAppUsd) + (databases * rn.managedPostgresMonthlyUsd) + renderBwUsd
    );

    // Media ponderada honesta de plataformas SaaS gestionadas
    const monthlyCloudUsd = (apps === 0 && databases === 0)
      ? 0
      : round2((vercelPlusManagedDbUsd + railwayMonthlyUsd + renderMonthlyUsd) / 3);

    // Alternativas VPS self-hosted
    const recommendedVps = pickBestVps(requiredRamGb, requiredVcpus, monthlyBandwidthGb, preferredProvider);
    const vpsAlternatives = ['Hetzner', 'OVHcloud', 'Vultr', 'DigitalOcean'].map((prov) =>
      pickBestVps(requiredRamGb, requiredVcpus, monthlyBandwidthGb, prov)
    );

    const monthlySelfHostedUsd = (apps === 0 && databases === 0) ? 0 : round2(recommendedVps.totalMonthlyUsd);
    const monthlySavingsUsd = round2(Math.max(0, monthlyCloudUsd - monthlySelfHostedUsd));
    const annualSavingsUsd = round2(monthlySavingsUsd * 12);
    const savingsPct = monthlyCloudUsd > 0 ? round1((monthlySavingsUsd / monthlyCloudUsd) * 100) : 0;

    return {
      inputs: {
        apps,
        databases,
        avgRamMbPerApp,
        avgRamMbPerDb,
        monthlyBandwidthGb,
        teamSeats,
        preferredProvider
      },
      sizing: {
        workloadRamMb,
        culkiboOverheadMb: CULKIBO_OVERHEAD_MB,
        requiredRamGb,
        requiredVcpus
      },
      cloudBreakdown: {
        vercelPlusManagedDbUsd,
        railwayMonthlyUsd,
        renderMonthlyUsd,
        blendedCloudUsd: monthlyCloudUsd
      },
      monthlyCloudUsd,
      monthlySelfHostedUsd,
      monthlySavingsUsd,
      annualSavingsUsd,
      savingsPct,
      recommendedVps,
      vpsAlternatives,
      pricingFootnotes: [
        CLOUD_PRICING_PROFILES.vercelPro.footnote,
        CLOUD_PRICING_PROFILES.railway.footnote,
        CLOUD_PRICING_PROFILES.render.footnote,
        `Self-hosted estimate uses published ${recommendedVps.provider} ${recommendedVps.name} ($${recommendedVps.monthlyUsd}/mo) with Culkibo control plane (~50 MB RSS, 0 license fees).`
      ]
    };
  }

  /**
   * Analiza proyectos, bases de datos, telemetría reciente y candidatos a auto-sleep
   * para emitir recomendaciones concretas de right-sizing y ahorro FinOps.
   *
   * @param {{
   *   projects?: any[],
   *   databases?: any[],
   *   metricsHistory?: any[] | Record<string, any>,
   *   sleepCandidates?: any[],
   *   monthlyBandwidthGb?: number,
   *   teamSeats?: number,
   *   preferredProvider?: string
   * }} [opts]
   */
  analyzeFleetAndProjects(opts = {}) {
    // Carga perezosa solo cuando no se pasan colecciones explícitas
    /** @type {any[]} */
    let projects = Array.isArray(opts.projects) ? opts.projects : [];
    if (!Array.isArray(opts.projects)) {
      try {
        const pm = require('./projectManager');
        projects = Array.isArray(pm.getAll()) ? pm.getAll() : [];
      } catch (e) {
        projects = [];
      }
    }

    /** @type {any[]} */
    let databases = Array.isArray(opts.databases) ? opts.databases : [];
    if (!Array.isArray(opts.databases)) {
      try {
        const dbm = require('./databaseManager');
        const list = typeof dbm.list === 'function' ? dbm.list() : [];
        databases = Array.isArray(list) ? list : [];
      } catch (e) {
        databases = [];
      }
    }

    /** @type {Set<string>} */
    const sleepCandidateIds = new Set();
    if (Array.isArray(opts.sleepCandidates)) {
      for (const sc of opts.sleepCandidates) {
        if (typeof sc === 'string') sleepCandidateIds.add(sc);
        else if (sc && (sc.projectId || sc.id)) sleepCandidateIds.add(String(sc.projectId || sc.id));
      }
    }

    // Indexar telemetría observada por projectId si existe en `metricsHistory`
    /** @type {Map<string, { peakRamMb: number, avgRamMb: number, avgCpuPct: number }>} */
    const observedByProject = new Map();
    if (opts.metricsHistory) {
      if (Array.isArray(opts.metricsHistory)) {
        /** @type {Map<string, { ramSamples: number[], cpuSamples: number[] }>} */
        const buckets = new Map();
        for (const sample of opts.metricsHistory) {
          if (!sample) continue;
          const perProj = sample.projects && typeof sample.projects === 'object' ? sample.projects : null;
          if (perProj) {
            for (const [pid, m] of Object.entries(perProj)) {
              const entry = buckets.get(pid) || { ramSamples: [], cpuSamples: [] };
              const ramMb = Number(m && (m.memoryMb ?? m.ramMb ?? m.rssMb));
              const cpuPct = Number(m && (m.cpuPct ?? m.cpu));
              if (Number.isFinite(ramMb) && ramMb >= 0) entry.ramSamples.push(ramMb);
              if (Number.isFinite(cpuPct) && cpuPct >= 0) entry.cpuSamples.push(cpuPct);
              buckets.set(pid, entry);
            }
          } else if (sample.projectId) {
            const pid = String(sample.projectId);
            const entry = buckets.get(pid) || { ramSamples: [], cpuSamples: [] };
            const ramMb = Number(sample.memoryMb ?? sample.ramMb ?? sample.rssMb);
            const cpuPct = Number(sample.cpuPct ?? sample.cpu);
            if (Number.isFinite(ramMb) && ramMb >= 0) entry.ramSamples.push(ramMb);
            if (Number.isFinite(cpuPct) && cpuPct >= 0) entry.cpuSamples.push(cpuPct);
            buckets.set(pid, entry);
          }
        }
        for (const [pid, b] of buckets.entries()) {
          const peakRamMb = b.ramSamples.length > 0 ? Math.max(...b.ramSamples) : 0;
          const avgRamMb = b.ramSamples.length > 0 ? b.ramSamples.reduce((s, x) => s + x, 0) / b.ramSamples.length : 0;
          const avgCpuPct = b.cpuSamples.length > 0 ? b.cpuSamples.reduce((s, x) => s + x, 0) / b.cpuSamples.length : 0;
          observedByProject.set(pid, { peakRamMb: round1(peakRamMb), avgRamMb: round1(avgRamMb), avgCpuPct: round1(avgCpuPct) });
        }
      } else if (typeof opts.metricsHistory === 'object') {
        for (const [pid, m] of Object.entries(opts.metricsHistory)) {
          if (!m || typeof m !== 'object') continue;
          const peak = Number(m.peakRamMb ?? m.memoryMb ?? m.ramMb ?? 0);
          const avg = Number(m.avgRamMb ?? m.memoryMb ?? m.ramMb ?? peak);
          const cpu = Number(m.avgCpuPct ?? m.cpuPct ?? 0);
          observedByProject.set(pid, { peakRamMb: round1(peak), avgRamMb: round1(avg), avgCpuPct: round1(cpu) });
        }
      }
    }

    /** @type {any[]} */
    const recommendations = [];
    let totalAllocatedRamMb = 0;
    let totalReclaimableRamMb = 0;
    let overProvisionedCount = 0;
    let oomRiskCount = 0;
    let sleepCandidateCount = 0;

    for (const proj of projects) {
      if (!proj || !proj.id) continue;
      const pid = String(proj.id);
      const allocatedRamMb = Math.max(128, Number(proj.memoryMb || proj.memoryLimitMb || 512) || 512);
      const allocatedCpus = Math.max(0.25, Number(proj.cpus || proj.cpuLimit || 1) || 1);
      totalAllocatedRamMb += allocatedRamMb;

      const obs = observedByProject.get(pid) || {
        peakRamMb: Number(proj.peakRamMb || proj.memoryUsageMb || 0) || 0,
        avgRamMb: Number(proj.avgRamMb || proj.memoryUsageMb || 0) || 0,
        avgCpuPct: Number(proj.avgCpuPct || proj.cpuUsagePct || 0) || 0
      };

      const isSleepCandidate = sleepCandidateIds.has(pid)
        || Boolean(proj.idleMinutes && Number(proj.idleMinutes) >= 30 && !proj.autoSleepEnabled);

      // 1. Riesgo OOM (>85% de límite de memoria)
      if (obs.peakRamMb > 0 && obs.peakRamMb >= allocatedRamMb * 0.85) {
        oomRiskCount++;
        const recommendedMemoryMb = snapMemoryTierMb(obs.peakRamMb * 1.5);
        recommendations.push({
          projectId: pid,
          projectName: proj.name || pid,
          type: 'oom_risk',
          severity: 'high',
          currentMemoryMb: allocatedRamMb,
          observedPeakRamMb: obs.peakRamMb,
          recommendedMemoryMb,
          reclaimableRamMb: 0,
          message: `Peak RAM (${obs.peakRamMb} MB) is >=85% of limit (${allocatedRamMb} MB). Increase memoryMb to ${recommendedMemoryMb} MB to prevent OOMKills.`
        });
        continue;
      }

      // 2. Contenedor sobredimensionado (<35% de uso pico en contenedores >=512 MB)
      if (obs.peakRamMb > 0 && allocatedRamMb >= 512 && obs.peakRamMb <= allocatedRamMb * 0.35) {
        const targetRamMb = snapMemoryTierMb(Math.max(128, obs.peakRamMb * 1.6));
        const reclaimable = Math.max(0, allocatedRamMb - targetRamMb);
        if (reclaimable >= 128) {
          overProvisionedCount++;
          totalReclaimableRamMb += reclaimable;
          recommendations.push({
            projectId: pid,
            projectName: proj.name || pid,
            type: 'right_size_ram',
            severity: 'medium',
            currentMemoryMb: allocatedRamMb,
            observedPeakRamMb: obs.peakRamMb,
            recommendedMemoryMb: targetRamMb,
            reclaimableRamMb: reclaimable,
            currentCpus: allocatedCpus,
            message: `Over-provisioned: peak RAM is only ${obs.peakRamMb} MB out of ${allocatedRamMb} MB. Right-sizing to ${targetRamMb} MB reclaims ${reclaimable} MB.`
          });
        }
      }

      // 3. Candidato a Scale-to-Zero Auto-Sleep
      if (isSleepCandidate) {
        sleepCandidateCount++;
        const sleepReclaim = obs.avgRamMb > 0 ? Math.round(obs.avgRamMb) : Math.round(allocatedRamMb * 0.5);
        totalReclaimableRamMb += sleepReclaim;
        recommendations.push({
          projectId: pid,
          projectName: proj.name || pid,
          type: 'enable_auto_sleep',
          severity: 'low',
          currentMemoryMb: allocatedRamMb,
          observedPeakRamMb: obs.peakRamMb,
          recommendedMemoryMb: allocatedRamMb,
          reclaimableRamMb: sleepReclaim,
          message: `Idle workload detected: enabling Culkibo Scale-to-Zero Auto-Sleep frees ~${sleepReclaim} MB during inactive hours with zero cold-config effort.`
        });
      }
    }

    const avgRamMbPerApp = projects.length > 0
      ? Math.round(totalAllocatedRamMb / projects.length)
      : 512;

    const costComparison = this.compareCloudCosts({
      apps: projects.length,
      databases: databases.length,
      avgRamMbPerApp,
      monthlyBandwidthGb: opts.monthlyBandwidthGb ?? Math.max(100, projects.length * 80),
      teamSeats: opts.teamSeats ?? 2,
      preferredProvider: opts.preferredProvider || 'Hetzner'
    });

    return {
      ok: true,
      generatedAt: new Date().toISOString(),
      fleetSummary: {
        totalApps: projects.length,
        totalDatabases: databases.length,
        totalAllocatedRamMb,
        totalReclaimableRamMb,
        overProvisionedCount,
        oomRiskCount,
        sleepCandidateCount
      },
      recommendations,
      costComparison,
      monthlyCloudUsd: costComparison.monthlyCloudUsd,
      monthlySelfHostedUsd: costComparison.monthlySelfHostedUsd,
      monthlySavingsUsd: costComparison.monthlySavingsUsd,
      annualSavingsUsd: costComparison.annualSavingsUsd,
      savingsPct: costComparison.savingsPct,
      recommendedVps: costComparison.recommendedVps,
      pricingFootnotes: costComparison.pricingFootnotes
    };
  }

  /** Alias práctico para rutas HTTP (`GET /api/finops/report`). */
  getReport(opts = {}) {
    return this.analyzeFleetAndProjects(opts);
  }
}

const instance = /** @type {any} */ (new FinOpsOptimizer());
instance.FinOpsOptimizer = FinOpsOptimizer;
instance.CLOUD_PRICING_PROFILES = CLOUD_PRICING_PROFILES;
instance.VPS_CATALOG = VPS_CATALOG;
module.exports = instance;
