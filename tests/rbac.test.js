const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const express = require('express');

const auth = require('../server/middleware/auth');
const teamManagerMod = require('../server/services/teamManager');
const { TeamManager, DEFAULT_TEAM_ID, generateTotpCode } = teamManagerMod;
const { OidcService, verifyIdToken } = require('../server/services/oidcService');

/** Helper mínimo de mock Express (req/res/next) para probar middlewares RBAC. */
function runMiddleware(mw, req) {
  return new Promise((resolve) => {
    let nextCalled = false;
    let statusCode = 200;
    let body = null;
    const headers = {};
    const res = {
      status(code) {
        statusCode = code;
        return this;
      },
      setHeader(k, v) {
        headers[k.toLowerCase()] = v;
      },
      json(payload) {
        body = payload;
        resolve({ nextCalled, statusCode, body, headers });
        return this;
      }
    };
    mw(req, res, () => {
      nextCalled = true;
      resolve({ nextCalled, statusCode, body, headers });
    });
  });
}

async function testRbac() {
  console.log('🛡️  Testing Teams, Users, RBAC, Scoped API Tokens & Multi-Tenant Auth...');

  // 0. Carga perezosa real: importar `auth.js` + usar master token / loopback NO carga `teamManager.js`
  {
    const script = [
      "const path = require('path');",
      "const auth = require('./server/middleware/auth');",
      "const tok = auth.resolveToken();",
      "const d1 = auth.authorizeRequest({ headers: { authorization: 'Bearer ' + tok }, socket: { remoteAddress: '203.0.113.10' } });",
      "const d2 = auth.authorizeRequest({ headers: { host: 'localhost:3030' }, socket: { remoteAddress: '127.0.0.1' } });",
      "const tmPath = require.resolve('./server/services/teamManager');",
      "const loaded = Boolean(require.cache[tmPath]);",
      "if (!d1.ok || !d1.principal.isSuperAdmin || !d2.ok || !d2.principal.isSuperAdmin || loaded) {",
      "  console.error('FAIL', { d1ok: d1.ok, d2ok: d2.ok, loaded }); process.exit(1);",
      "}",
      "console.log('LAZY_OK');"
    ].join('\n');
    const out = execFileSync(process.execPath, ['-e', script], {
      cwd: path.join(__dirname, '..'),
      encoding: 'utf8'
    });
    assert.ok(out.includes('LAZY_OK'), 'auth.js debe mantener teamManager sin cargar en modo clásico');
    console.log('  ✓ 0. Carga perezosa verificada (0 overhead / 0 require de teamManager en modo master/loopback)');
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-rbac-test-'));
  // Coste 4 en el aislado para que 20+ hashes/verificaciones sean rápidos manteniendo el formato OpenBSD bcrypt completo
  // (y también probamos explícitamente el coste 10 por defecto abajo).
  const tm = new TeamManager({ dataDir: tmpDir, bcryptCost: 4 });
  const revokedEvents = [];
  const unsubAuthRevoked = auth.onPrincipalRevoked((evt) => revokedEvents.push(evt));
  auth._setTeamManagerForTest(tm);

  try {
    // 1. Estado dormido + Bootstrap único + validación estricta de contraseñas UTF-8 (8..72 bytes)
    assert.strictEqual(tm.isMultiUserEnabled(), false, 'Sin usuarios, multi-user debe iniciar desactivado');
    assert.strictEqual(fs.existsSync(path.join(tmpDir, 'teams.json')), false, 'No debe escribir teams.json en lectura vacía');

    // Password demasiado corta (<8) y demasiado larga (>72 bytes UTF-8, evita truncado silencioso bcrypt)
    assert.throws(
      () => tm.bootstrapOwner({ email: 'owner@example.com', password: 'short' }),
      (err) => err.status === 400 && err.code === 'PASSWORD_TOO_SHORT'
    );
    assert.throws(
      () => tm.bootstrapOwner({ email: 'owner@example.com', password: 'A'.repeat(73) }),
      (err) => err.status === 400 && err.code === 'PASSWORD_TOO_LONG'
    );
    assert.throws(
      () => tm.bootstrapOwner({ email: 'owner@example.com', password: '🔑'.repeat(19) }), // 76 bytes UTF-8
      (err) => err.status === 400 && err.code === 'PASSWORD_TOO_LONG'
    );

    // Bootstrap válido (email normalizado a minúsculas)
    const ownerBoot = tm.bootstrapOwner({
      email: '  OWNER@Example.COM  ',
      name: 'Alice Owner',
      password: 'OwnerSuperPassword!2026',
      teamName: 'Acme Core'
    });
    assert.strictEqual(ownerBoot.user.email, 'owner@example.com');
    assert.strictEqual(ownerBoot.role, 'owner');
    assert.strictEqual(ownerBoot.team.id, DEFAULT_TEAM_ID);
    assert.ok(ownerBoot.sessionToken.startsWith('cks_'), 'Bootstrap debe emitir token de sesión cks_');
    assert.strictEqual(tm.isMultiUserEnabled(), true);
    assert.ok(fs.existsSync(path.join(tmpDir, 'teams.json')), 'teams.json debe persistirse');
    assert.ok(fs.existsSync(path.join(tmpDir, '.rbac.key')), '.rbac.key debe persistirse');

    // Verificar que el hash por defecto de una instancia sin override es bcrypt cost 10
    const cost10Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-rbac-cost10-'));
    try {
      const tm10 = new TeamManager({ dataDir: cost10Dir });
      tm10.bootstrapOwner({ email: 'c10@example.com', password: 'ValidPassword10!' });
      const rawJson10 = JSON.parse(fs.readFileSync(path.join(cost10Dir, 'teams.json'), 'utf8'));
      assert.ok(rawJson10.users[0].passwordHash.startsWith('$2b$10$'), 'El coste bcrypt por defecto debe ser 10');
    } finally {
      fs.rmSync(cost10Dir, { recursive: true, force: true });
    }

    // Bootstrap es estrictamente de un solo uso (403 en segundo intento)
    assert.throws(
      () => tm.bootstrapOwner({ email: 'attacker@evil.com', password: 'EvilPassword123!' }),
      (err) => err.status === 403 && err.code === 'ALREADY_BOOTSTRAPPED'
    );

    // Guard de origen/red de bootstrap: bloquea remoto sin token maestro; permite loopback o master token
    assert.strictEqual(
      auth.canBootstrapRequest({ headers: { host: 'vps.example.com' }, socket: { remoteAddress: '203.0.113.55' } }),
      false,
      'Bootstrap remoto sin token maestro debe bloquearse'
    );
    assert.strictEqual(
      auth.canBootstrapRequest({ headers: { host: 'evil.attacker.test' }, socket: { remoteAddress: '127.0.0.1' } }),
      false,
      'Bootstrap loopback con Host rebinding debe bloquearse'
    );
    assert.strictEqual(
      auth.canBootstrapRequest({ headers: { host: 'localhost:3030' }, socket: { remoteAddress: '127.0.0.1' } }),
      true
    );
    assert.strictEqual(
      auth.canBootstrapRequest({
        headers: { host: 'vps.example.com', authorization: `Bearer ${auth.resolveToken()}` },
        socket: { remoteAddress: '203.0.113.55' }
      }),
      true
    );
    console.log('  ✓ 1. Bootstrap único, bcrypt coste 10, política UTF-8 8..72B y almacenamiento atómico .rbac.key');

    const ownerPrincipal = tm.verifySessionToken(ownerBoot.sessionToken).principal;
    assert.ok(ownerPrincipal && ownerPrincipal.role === 'owner');

    // 2. Role Ceiling & Invite Security (Dokploy GHSA-fm9p-wmpw-gxjh, Coolify CVE-2025-22611, CVE-2026-34171)
    // Nadie puede invitar con rol `owner` ni con TTL > 168h ni auto-invitarse
    assert.throws(
      () => tm.createInvite(ownerPrincipal, { email: 'newowner@example.com', role: 'owner' }),
      (err) => err.status === 403 && err.code === 'OWNER_INVITE_FORBIDDEN'
    );
    assert.throws(
      () => tm.createInvite(ownerPrincipal, { email: 'owner@example.com', role: 'admin' }),
      (err) => err.status === 403 && err.code === 'SELF_INVITE_FORBIDDEN'
    );
    assert.throws(
      () => tm.createInvite(ownerPrincipal, { email: 'longttl@example.com', role: 'viewer', ttlHours: 200 }),
      (err) => err.status === 400 && err.code === 'INVALID_INVITE_TTL'
    );

    // Owner invita a Admin
    const adminInv = tm.createInvite(ownerPrincipal, { email: 'Admin@Example.com', role: 'admin', ttlHours: 24 });
    assert.ok(adminInv.inviteToken.startsWith('cki_'), 'Invitación debe tener prefijo cki_');

    // Verificar que el token en claro JAMÁS se escribe en teams.json
    const diskAfterInvite = fs.readFileSync(path.join(tmpDir, 'teams.json'), 'utf8');
    assert.ok(!diskAfterInvite.includes(adminInv.inviteToken), 'El token de invitación en claro jamás debe persistirse en disco');

    // Aceptar con otro correo -> 403 email-bound
    assert.throws(
      () => tm.acceptInvite({ token: adminInv.inviteToken, email: 'thief@evil.com', password: 'ThiefPassword123!' }),
      (err) => err.status === 403 && err.code === 'INVITE_EMAIL_MISMATCH'
    );

    // Aceptar correctamente con email normalizado
    const adminAcc = tm.acceptInvite({
      token: adminInv.inviteToken,
      email: 'admin@example.com',
      name: 'Bob Admin',
      password: 'AdminPassword!2026'
    });
    assert.strictEqual(adminAcc.role, 'admin');
    const adminPrincipal = tm.verifySessionToken(adminAcc.sessionToken).principal;

    // Reutilizar invitación single-use -> 410 INVITE_ALREADY_USED
    assert.throws(
      () => tm.acceptInvite({ token: adminInv.inviteToken, email: 'admin@example.com', password: 'AdminPassword!2026' }),
      (err) => err.status === 410 && err.code === 'INVITE_ALREADY_USED'
    );

    // Techo de rol de Admin: NO puede invitar `admin` ni `owner`, SOLO `developer`/`viewer`
    assert.throws(
      () => tm.createInvite(adminPrincipal, { email: 'peeradmin@example.com', role: 'admin' }),
      (err) => err.status === 403 && err.code === 'ROLE_CEILING_EXCEEDED'
    );
    assert.throws(
      () => tm.createInvite(adminPrincipal, { email: 'peerowner@example.com', role: 'owner' }),
      (err) => err.status === 403 && err.code === 'OWNER_INVITE_FORBIDDEN'
    );

    // Admin invita a Developer y Viewer
    const devInv = tm.createInvite(adminPrincipal, { email: 'dev@example.com', role: 'developer', ttlHours: 12 });
    const viewerInv = tm.createInvite(adminPrincipal, { email: 'viewer@example.com', role: 'viewer', ttlHours: 12 });
    const expiredInv = tm.createInvite(adminPrincipal, { email: 'expired@example.com', role: 'viewer', ttlHours: 1 });

    // Simular expiración real en el registro de invitación
    const expRec = tm._state.invites.find((i) => i.id === expiredInv.invite.id);
    expRec.expiresAt = new Date(Date.now() - 5000).toISOString();
    assert.throws(
      () => tm.acceptInvite({ token: expiredInv.inviteToken, email: 'expired@example.com', password: 'ValidPassword1!' }),
      (err) => err.status === 410 && err.code === 'INVITE_EXPIRED'
    );

    const devAcc = tm.acceptInvite({ token: devInv.inviteToken, email: 'dev@example.com', name: 'Carol Dev', password: 'DevPassword!2026' });
    const viewerAcc = tm.acceptInvite({ token: viewerInv.inviteToken, email: 'viewer@example.com', name: 'Dave Viewer', password: 'ViewerPassword!2026' });
    const devPrincipal = tm.verifySessionToken(devAcc.sessionToken).principal;
    const viewerPrincipal = tm.verifySessionToken(viewerAcc.sessionToken).principal;

    // Developer y Viewer NO pueden listar invitaciones (evita fuga de links admin, Coolify CVE-2025-22611)
    assert.throws(() => tm.listInvites(devPrincipal), (err) => err.status === 403);
    assert.throws(() => tm.listInvites(viewerPrincipal), (err) => err.status === 403);
    const adminInviteList = tm.listInvites(adminPrincipal);
    assert.ok(adminInviteList.length >= 3);
    assert.ok(adminInviteList.every((i) => !i.tokenHash && String(i.tokenPreview).endsWith('_********')));

    // Role ceiling en mutaciones de miembros: admin NO puede tocar al owner ni promover dev->admin ni auto-escalarse
    assert.throws(
      () => tm.updateMemberRole(adminPrincipal, DEFAULT_TEAM_ID, ownerBoot.user.id, 'viewer'),
      (err) => err.status === 403 && err.code === 'ROLE_CEILING_EXCEEDED'
    );
    assert.throws(
      () => tm.updateMemberRole(adminPrincipal, DEFAULT_TEAM_ID, devAcc.user.id, 'admin'),
      (err) => err.status === 403 && err.code === 'ROLE_CEILING_EXCEEDED'
    );
    assert.throws(
      () => tm.updateMemberRole(adminPrincipal, DEFAULT_TEAM_ID, adminAcc.user.id, 'owner'),
      (err) => err.status === 403 && err.code === 'SELF_ESCALATION_BLOCKED'
    );
    assert.throws(
      () => tm.removeMember(adminPrincipal, DEFAULT_TEAM_ID, ownerBoot.user.id),
      (err) => err.status === 403 && err.code === 'ROLE_CEILING_EXCEEDED'
    );

    // Último owner protegido contra degradación, eliminación o deshabilitación
    const superAdmin = auth.SUPERADMIN_MASTER;
    assert.throws(
      () => tm.updateMemberRole(superAdmin, DEFAULT_TEAM_ID, ownerBoot.user.id, 'admin'),
      (err) => err.status === 409 && err.code === 'LAST_OWNER_PROTECTED'
    );
    assert.throws(
      () => tm.removeMember(superAdmin, DEFAULT_TEAM_ID, ownerBoot.user.id),
      (err) => err.status === 409 && err.code === 'LAST_OWNER_PROTECTED'
    );
    assert.throws(
      () => tm.disableUser(superAdmin, ownerBoot.user.id, DEFAULT_TEAM_ID),
      (err) => err.status === 409 && err.code === 'LAST_OWNER_PROTECTED'
    );
    console.log('  ✓ 2. Techo de rol, invitaciones single-use/expiración/email-bound y último owner protegidos');

    // 3. Coolify CVE-2026-34171: aceptar invitación a un 2º equipo NUNCA resetea contraseña de usuario existente
    const teamB = tm.createTeam(ownerPrincipal, { name: 'Team Bravo', slug: 'bravo' });
    const teamBInvForDev = tm.createInvite(ownerPrincipal, { teamId: teamB.id, email: 'dev@example.com', role: 'developer' });
    const devHashBefore = tm._findUserById(devAcc.user.id).passwordHash;

    // Intento con contraseña diferente -> 401 y hash intacto
    assert.throws(
      () => tm.acceptInvite({ token: teamBInvForDev.inviteToken, email: 'dev@example.com', password: 'HijackedPassword999!' }),
      (err) => err.status === 401 && err.code === 'EXISTING_USER_PASSWORD_REQUIRED'
    );
    assert.strictEqual(tm._findUserById(devAcc.user.id).passwordHash, devHashBefore, 'Una invitación jamás puede resetear el passwordHash existente');

    // Con su contraseña actual -> se une a Team Bravo y su passwordHash sigue intacto
    const devTeamBJoin = tm.acceptInvite({ token: teamBInvForDev.inviteToken, email: 'dev@example.com', password: 'DevPassword!2026' });
    assert.strictEqual(devTeamBJoin.createdNewUser, false);
    assert.strictEqual(devTeamBJoin.team.id, teamB.id);
    assert.strictEqual(tm._findUserById(devAcc.user.id).passwordHash, devHashBefore);
    console.log('  ✓ 3. Coolify CVE-2026-34171 mitigado: invitaciones nunca resetean contraseñas existentes');

    // 4. Cross-Team IDOR & BOLA (Coolify CVE-2026-27881, CVE-2026-34037, Portainer GHSA-q2w9-v7hg-hvh3)
    const teamBOnlyInv = tm.createInvite(ownerPrincipal, { teamId: teamB.id, email: 'bravo@example.com', role: 'admin' });
    const bravoAcc = tm.acceptInvite({ token: teamBOnlyInv.inviteToken, email: 'bravo@example.com', password: 'BravoPassword!2026' });
    const bravoPrincipal = tm.verifySessionToken(bravoAcc.sessionToken).principal;

    const projDefaultA = {
      id: 'proj_alpha',
      name: 'Alpha API',
      teamId: DEFAULT_TEAM_ID,
      envVars: { DATABASE_URL: 'postgres://secret:pass@db/app', STRIPE_KEY: 'sk_live_123' },
      buildArgs: { NPM_TOKEN: 'npm_secret_xyz' },
      webhookSecret: 'whsec_super_secret',
      deployHookToken: 'dh_super_secret'
    };
    const projDefaultB = {
      id: 'proj_beta',
      name: 'Beta Web',
      teamId: DEFAULT_TEAM_ID,
      envVars: { API_SECRET: 'beta_secret' }
    };
    const projBravo = {
      id: 'proj_bravo_1',
      name: 'Bravo Service',
      teamId: teamB.id,
      envVars: { BRAVO_KEY: 'bravo_secret' }
    };
    const allProjects = [projDefaultA, projDefaultB, projBravo];

    // Bravo Admin NO ve proyectos de team_default (404 anti-oráculo, jamás 403 en equipo ajeno)
    const crossCheck = tm.authorizeProject(bravoPrincipal, projDefaultA.id, 'projects:read', projDefaultA);
    assert.strictEqual(crossCheck.allowed, false);
    assert.strictEqual(crossCheck.status, 404, 'Acceso cross-team debe devolver 404 para no crear oráculo de IDs');

    // Dual-scope check (Coolify CVE-2026-34037 cloneTo/moveTo): bloquea mover recurso entre equipos
    const dualDeny = tm.authorizeDualProjectAction(bravoPrincipal, projBravo, projDefaultA, 'projects:read', 'projects:write');
    assert.strictEqual(dualDeny.allowed, false);
    assert.strictEqual(dualDeny.status, 404);

    // listTeams & listMembers estrictamente acotados al equipo del llamador
    const bravoTeams = tm.listTeams(bravoPrincipal);
    assert.deepStrictEqual(bravoTeams.map((t) => t.id), [teamB.id]);
    assert.throws(() => tm.listMembers(bravoPrincipal, DEFAULT_TEAM_ID), (err) => err.status === 404);

    // filterProjects aísla equipos y respeta ACL overrides ('none' gana al rol del equipo)
    assert.deepStrictEqual(tm.filterProjects(bravoPrincipal, allProjects).map((p) => p.id), ['proj_bravo_1']);

    tm.setProjectAcl(ownerPrincipal, projDefaultB.id, { teamId: DEFAULT_TEAM_ID, userId: devAcc.user.id, role: 'none' });
    // Nota: cambiar ACL revoca sesiones antiguas del dev; iniciamos sesión fresca para probar la ACL
    assert.strictEqual(tm.verifySessionToken(devAcc.sessionToken).ok, false, 'Cambiar ACL debe revocar sesión previa inmediatamente');
    const devFreshLogin = tm.login({ email: 'dev@example.com', password: 'DevPassword!2026', teamId: DEFAULT_TEAM_ID });
    const devFreshPrincipal = tm.verifySessionToken(devFreshLogin.sessionToken).principal;

    const devVisible = tm.filterProjects(devFreshPrincipal, allProjects);
    assert.deepStrictEqual(devVisible.map((p) => p.id), ['proj_alpha'], 'Override ACL "none" debe ocultar proj_beta al developer');
    assert.strictEqual(tm.authorizeProject(devFreshPrincipal, projDefaultB.id, 'projects:read', projDefaultB).status, 404);
    console.log('  ✓ 4. Aislamiento cross-team (404 anti-IDOR), verificación dual y ACL override "none"');

    // 5. Viewer secret/write block + Redacción de envVars + Developer host-route block (Portainer CVE-2026-44848)
    const viewerFiltered = tm.filterProjects(viewerPrincipal, allProjects);
    assert.deepStrictEqual(viewerFiltered.map((p) => p.id), ['proj_alpha', 'proj_beta']);
    assert.strictEqual(viewerFiltered[0].envVars.DATABASE_URL, '[REDACTED]', 'Viewer nunca debe ver valores envVars');
    assert.strictEqual(viewerFiltered[0].envVars.STRIPE_KEY, '[REDACTED]');
    assert.strictEqual(viewerFiltered[0].buildArgs.NPM_TOKEN, '[REDACTED]');
    assert.strictEqual(viewerFiltered[0].webhookSecret, '[REDACTED]');
    assert.strictEqual(viewerFiltered[0].deployHookToken, '[REDACTED]');
    // Objeto original intacto en memoria
    assert.strictEqual(projDefaultA.envVars.DATABASE_URL, 'postgres://secret:pass@db/app');

    // Developer SÍ ve envVars de proyectos permitidos, pero NO puede tocar rutas de host ni borrar proyectos
    const devRedacted = tm.redactProjectForPrincipal(devFreshPrincipal, projDefaultA);
    assert.strictEqual(devRedacted.envVars.DATABASE_URL, 'postgres://secret:pass@db/app');

    // Viewer bloqueado en mutaciones, secretos y exec
    assert.strictEqual(tm.authorizeHttpRoute(viewerPrincipal, 'POST', '/api/projects').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(viewerPrincipal, 'GET', '/api/databases/db1/credentials').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(viewerPrincipal, 'GET', '/api/projects/proj_alpha/secrets').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(viewerPrincipal, 'POST', '/api/projects/proj_alpha/runtime/exec').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(viewerPrincipal, 'GET', '/api/projects').allowed, true);

    // Developer bloqueado en rutas de host/instancia (Portainer CVE-2026-44848) y en DELETE project
    const hostRoutesBlockedForDev = [
      ['POST', '/api/auth/rotate'],
      ['POST', '/api/system/panel-domain'],
      ['PATCH', '/api/system/config'],
      ['POST', '/api/docker/prune'],
      ['POST', '/api/ingress/reload'],
      ['POST', '/api/ssl/wildcard'],
      ['POST', '/api/cloudflare/zones'],
      ['POST', '/api/backup/instance/import'],
      ['POST', '/api/fleet/keys'],
      ['DELETE', '/api/projects/proj_alpha']
    ];
    for (const [m, routePath] of hostRoutesBlockedForDev) {
      const r = tm.authorizeHttpRoute(devFreshPrincipal, m, routePath);
      assert.strictEqual(r.allowed, false, `Developer debe estar bloqueado en ${m} ${routePath}`);
      assert.strictEqual(r.status, 403);
    }
    // Owner sí puede en rutas de host
    assert.strictEqual(tm.authorizeHttpRoute(ownerPrincipal, 'POST', '/api/auth/rotate').allowed, true);
    assert.strictEqual(tm.authorizeHttpRoute(ownerPrincipal, 'POST', '/api/docker/prune').allowed, true);
    console.log('  ✓ 5. Viewer secret/write redaction & block + Developer host-route block (Portainer CVE-2026-44848)');

    // 6. Scoped API/MCP Tokens (`ckp_<id8>_<secret32>`) + Dynamic Clamping al degradar rol (Dokploy GHSA-6g88-x4hx-9837)
    // Developer NO puede crear token con scopes superiores a su rol (`projects:delete`, `*`, `auth:rotate`)
    assert.throws(
      () => tm.createApiToken(devFreshPrincipal, { name: 'Evil Escalation', scopes: ['projects:delete'] }),
      (err) => err.status === 403 && err.code === 'SCOPE_EXCEEDS_CALLER'
    );
    assert.throws(
      () => tm.createApiToken(devFreshPrincipal, { name: 'Wildcard Attempt', scopes: ['*'] }),
      (err) => err.status === 403 && err.code === 'SCOPE_EXCEEDS_ROLE'
    );

    // Developer crea token acotado a `proj_alpha` con lectura + despliegue + secretos
    const devTokRes = tm.createApiToken(devFreshPrincipal, {
      name: 'CI Alpha Deploy',
      scopes: ['projects:read', 'deployments:write', 'secrets:read'],
      projectIds: ['proj_alpha'],
      expiresInDays: 30
    });
    assert.ok(devTokRes.token.startsWith('ckp_'), 'API token debe tener prefijo ckp_');
    const diskAfterApiTok = fs.readFileSync(path.join(tmpDir, 'teams.json'), 'utf8');
    assert.ok(!diskAfterApiTok.includes(devTokRes.token), 'El secreto ckp_ jamás debe guardarse en claro en disco');

    // Verificación inicial: permitido en proj_alpha, bloqueado en proj_beta y en team:write
    const tokAuth1 = tm.verifyApiToken(devTokRes.token);
    assert.strictEqual(tokAuth1.ok, true);
    assert.strictEqual(tm.authorizeProject(tokAuth1.principal, 'proj_alpha', 'deployments:write', projDefaultA).allowed, true);
    assert.strictEqual(tm.authorizeProject(tokAuth1.principal, 'proj_beta', 'projects:read', projDefaultB).status, 404);
    assert.strictEqual(tm.authorizeAction(tokAuth1.principal, 'team:write').status, 403);

    // Degradación dinámica: Owner degrada a Developer -> Viewer
    revokedEvents.length = 0;
    tm.updateMemberRole(ownerPrincipal, DEFAULT_TEAM_ID, devAcc.user.id, 'viewer');
    assert.ok(revokedEvents.some((e) => e.userId === devAcc.user.id && e.reason === 'role_changed'), 'Degradar rol debe emitir principal_revoked');

    // Sesión previa del developer revocada al instante (tokenVersion / tokensValidAfter)
    assert.strictEqual(tm.verifySessionToken(devFreshLogin.sessionToken).ok, false, 'Sesión cks_ debe invalidarse al instante tras degradación');

    // Token API ckp_ queda RECORTADO dinámicamente al nuevo rol `viewer`
    const tokAuthAfterDemote = tm.verifyApiToken(devTokRes.token);
    assert.strictEqual(tokAuthAfterDemote.ok, true);
    assert.strictEqual(tokAuthAfterDemote.principal.role, 'viewer');
    assert.strictEqual(tokAuthAfterDemote.principal.clamped, true);
    assert.deepStrictEqual(tokAuthAfterDemote.principal.scopes, ['projects:read']);
    assert.strictEqual(tm.authorizeProject(tokAuthAfterDemote.principal, 'proj_alpha', 'projects:read', projDefaultA).allowed, true);
    assert.strictEqual(
      tm.authorizeProject(tokAuthAfterDemote.principal, 'proj_alpha', 'deployments:write', projDefaultA).allowed,
      false,
      'Tras degradar a viewer, el API token no puede ejecutar deployments:write'
    );
    assert.strictEqual(
      tm.authorizeProject(tokAuthAfterDemote.principal, 'proj_alpha', 'secrets:read', projDefaultA).allowed,
      false,
      'Tras degradar a viewer, el API token no puede leer secrets:read'
    );
    assert.strictEqual(
      tm.redactProjectForPrincipal(tokAuthAfterDemote.principal, projDefaultA).envVars.DATABASE_URL,
      '[REDACTED]'
    );

    // Revocar token API -> rechazo inmediato
    tm.revokeApiToken(ownerPrincipal, devTokRes.tokenRecord.id);
    assert.strictEqual(tm.verifyApiToken(devTokRes.token).ok, false);
    console.log('  ✓ 6. Tokens API/MCP ckp_ con recorte dinámico tras degradación y revocación inmediata');

    // 7. Triple-Layer Revocation (PocketBase tokenKey + tokenVersion + bounded sessions[25] + WS Ticket Revalidation)
    const viewerSess1 = tm.login({ email: 'viewer@example.com', password: 'ViewerPassword!2026' });
    const viewerSess2 = tm.login({ email: 'viewer@example.com', password: 'ViewerPassword!2026' });
    assert.strictEqual(tm.verifySessionToken(viewerSess1.sessionToken).ok, true);
    assert.strictEqual(tm.verifySessionToken(viewerSess2.sessionToken).ok, true);

    // Emitir WS ticket ligado a viewerSess2 y luego cerrar esa sesión -> ticket WS debe rechazarse al consumir
    const wsReqForViewer = {
      headers: { host: 'panel.example.com', authorization: `Bearer ${viewerSess2.sessionToken}` },
      socket: { remoteAddress: '203.0.113.88' },
      auth: { method: 'session', principal: tm.verifySessionToken(viewerSess2.sessionToken).principal }
    };
    const wsTicketObj = auth.createWsTicket(wsReqForViewer);

    // Logout individual (capa 3: sid) solo revoca viewerSess2, viewerSess1 sigue viva
    tm.logoutSession(viewerAcc.user.id, viewerSess2.sessionId);
    assert.strictEqual(tm.verifySessionToken(viewerSess2.sessionToken).ok, false);
    assert.strictEqual(tm.verifySessionToken(viewerSess1.sessionToken).ok, true);
    assert.strictEqual(
      auth.consumeWsTicket(wsTicketObj.ticket, { socket: { remoteAddress: '203.0.113.88' }, headers: {} }),
      false,
      'consumeWsTicket debe revalidar isPrincipalStillValid() y rechazar tickets de sesiones revocadas'
    );

    // Cambio de contraseña (capa 1: rotación de tokenKey PocketBase) invalida TODAS las sesiones previas
    const prevTokenKey = tm._findUserById(viewerAcc.user.id).tokenKey;
    revokedEvents.length = 0;
    const pwdChange = tm.changePassword(viewerAcc.user.id, {
      currentPassword: 'ViewerPassword!2026',
      newPassword: 'ViewerNewStrongPwd!2026',
      issueNewSession: true,
      teamId: DEFAULT_TEAM_ID
    });
    assert.notStrictEqual(tm._findUserById(viewerAcc.user.id).tokenKey, prevTokenKey, 'tokenKey debe rotar al cambiar contraseña');
    assert.strictEqual(tm.verifySessionToken(viewerSess1.sessionToken).ok, false, 'Sesiones antiguas deben fallar firma inmediatamente');
    assert.strictEqual(tm.verifySessionToken(pwdChange.sessionToken).ok, true, 'Nueva sesión emitida tras cambio debe funcionar');
    assert.ok(revokedEvents.some((e) => e.userId === viewerAcc.user.id && e.reason === 'password_changed'));

    // Límite acotado de 25 sesiones (evicción LRU de la más antigua)
    const issuedTokens = [pwdChange.sessionToken];
    for (let i = 0; i < 25; i++) {
      const s = tm.login({ email: 'viewer@example.com', password: 'ViewerNewStrongPwd!2026' });
      issuedTokens.push(s.sessionToken);
    }
    assert.strictEqual(tm._findUserById(viewerAcc.user.id).sessions.length, 25, 'Máximo 25 sesiones activas por usuario');
    assert.strictEqual(tm.verifySessionToken(issuedTokens[0]).ok, false, 'La sesión #1 debe haber sido desalojada por LRU');
    assert.strictEqual(tm.verifySessionToken(issuedTokens[issuedTokens.length - 1]).ok, true);
    console.log('  ✓ 7. Revocación triple capa (tokenKey, tokenVersion, sid LRU-25) + revalidación de tickets WS');

    // 8. Integración auth.js: cks_ Bearer/Cookie + CSRF guard + ckp_ Header/WS + No WS cookies + Express Middlewares
    const freshAdminTok = tm.createApiToken(adminPrincipal, {
      name: 'MCP Admin Bot',
      scopes: ['projects:read', 'projects:write', 'deployments:write'],
      projectIds: ['proj_alpha']
    });
    const viewerLiveTok = issuedTokens[issuedTokens.length - 1];

    // 8a. cks_ Bearer
    const bearerReq = {
      method: 'GET',
      originalUrl: '/api/projects',
      headers: { host: 'panel.example.com', authorization: `Bearer ${viewerLiveTok}` },
      socket: { remoteAddress: '203.0.113.10' }
    };
    const bearerMw = await runMiddleware(auth.authMiddleware, bearerReq);
    assert.strictEqual(bearerMw.nextCalled, true);
    assert.strictEqual(bearerReq.auth.method, 'session');
    assert.strictEqual(bearerReq.auth.principal.role, 'viewer');

    // 8b. cks_ Cookie: GET permitido; POST sin Origin/Sec-Fetch-Site bloqueado (403 CSRF); POST con same-site bloqueado (403); POST con Origin o same-origin permitido
    const cookieGet = auth.authorizeRequest({
      method: 'GET',
      headers: { host: 'panel.example.com', cookie: `culkibo_session=${viewerLiveTok}` },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(cookieGet.ok, true);
    assert.strictEqual(cookieGet.method, 'session_cookie');

    const cookiePostNoOrigin = auth.authorizeRequest({
      method: 'POST',
      headers: { host: 'panel.example.com', cookie: `culkibo_session=${viewerLiveTok}` },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(cookiePostNoOrigin.ok, false);
    assert.strictEqual(cookiePostNoOrigin.status, 403, 'Mutación con cookie sin Origin ni Sec-Fetch-Site: same-origin debe dar 403');

    const cookiePostSiblingSubdomain = auth.authorizeRequest({
      method: 'POST',
      headers: { host: 'panel.example.com', 'sec-fetch-site': 'same-site', cookie: `culkibo_session=${viewerLiveTok}` },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(cookiePostSiblingSubdomain.ok, false);
    assert.strictEqual(cookiePostSiblingSubdomain.status, 403, 'same-site (subdominio hermano) no satisface CSRF en cookie');

    const cookiePostValidOrigin = auth.authorizeRequest({
      method: 'POST',
      headers: {
        host: 'panel.example.com',
        origin: 'https://panel.example.com',
        cookie: `__Host-culkibo_session=${viewerLiveTok}`
      },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(cookiePostValidOrigin.ok, true);

    const cookiePostSameOrigin = auth.authorizeRequest({
      method: 'POST',
      headers: {
        host: 'panel.example.com',
        'sec-fetch-site': 'same-origin',
        cookie: `culkibo_session=${viewerLiveTok}`
      },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(cookiePostSameOrigin.ok, true);

    // 8c. Cookies NUNCA autentican upgrades WS
    const wsCookieAttempt = auth.authorizeRequest(
      {
        headers: {
          host: 'panel.example.com',
          upgrade: 'websocket',
          cookie: `culkibo_session=${viewerLiveTok}`
        },
        socket: { remoteAddress: '203.0.113.10' }
      },
      { allowWsSubprotocol: true }
    );
    assert.strictEqual(wsCookieAttempt.ok, false);
    assert.strictEqual(wsCookieAttempt.status, 401, 'WS upgrade jamás puede autenticarse por cookie');

    // 8d. ckp_ vía X-Culkibo-Token y vía WS subprotocol (`culkibo-token.<tok>`)
    const ckpHeaderAuth = auth.authorizeRequest({
      headers: { host: 'panel.example.com', 'x-culkibo-token': freshAdminTok.token },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(ckpHeaderAuth.ok, true);
    assert.strictEqual(ckpHeaderAuth.method, 'api_token');
    assert.deepStrictEqual(ckpHeaderAuth.principal.projectIds, ['proj_alpha']);

    const ckpWsAuth = auth.authorizeRequest(
      {
        headers: {
          host: 'panel.example.com',
          upgrade: 'websocket',
          'sec-websocket-protocol': `culkibo-token.${freshAdminTok.token}`
        },
        socket: { remoteAddress: '203.0.113.10' }
      },
      { allowWsSubprotocol: true }
    );
    assert.strictEqual(ckpWsAuth.ok, true);
    assert.strictEqual(ckpWsAuth.method, 'api_token');

    // Query-param `?token=` NUNCA aceptado
    const queryParamAttempt = auth.authorizeRequest({
      originalUrl: `/api/projects?token=${freshAdminTok.token}`,
      headers: { host: 'panel.example.com' },
      socket: { remoteAddress: '203.0.113.10' }
    });
    assert.strictEqual(queryParamAttempt.ok, false);

    // 8e. Express middlewares `requirePerm`, `requireRole`, `requireRouteRbac` (default-deny, return inmediato)
    const permWriteMw = auth.requirePerm('deployments:write');
    const viewerBlocked = await runMiddleware(permWriteMw, bearerReq);
    assert.strictEqual(viewerBlocked.nextCalled, false, 'Middleware 403 jamás puede llamar a next()');
    assert.strictEqual(viewerBlocked.statusCode, 403);

    const roleAdminMw = auth.requireRole('admin');
    const viewerRoleBlocked = await runMiddleware(roleAdminMw, bearerReq);
    assert.strictEqual(viewerRoleBlocked.nextCalled, false);
    assert.strictEqual(viewerRoleBlocked.statusCode, 403);

    // Rol desconocido en requireRole -> default-deny 403
    const unknownRoleBlocked = await runMiddleware(auth.requireRole(/** @type {any} */ ('superroot')), bearerReq);
    assert.strictEqual(unknownRoleBlocked.nextCalled, false);
    assert.strictEqual(unknownRoleBlocked.statusCode, 403);

    // requirePerm con ámbito de proyecto: ckp_ limitado a proj_alpha -> permite proj_alpha, bloquea proj_beta (404)
    const projDeployMw = auth.requirePerm('deployments:write', { projectParam: 'id' });
    const ckpOkProj = await runMiddleware(projDeployMw, {
      auth: { method: 'api_token', principal: ckpHeaderAuth.principal },
      params: { id: 'proj_alpha' }
    });
    assert.strictEqual(ckpOkProj.nextCalled, true);

    const ckpDeniedProj = await runMiddleware(projDeployMw, {
      auth: { method: 'api_token', principal: ckpHeaderAuth.principal },
      params: { id: 'proj_beta' }
    });
    assert.strictEqual(ckpDeniedProj.nextCalled, false);
    assert.strictEqual(ckpDeniedProj.statusCode, 404);
    console.log('  ✓ 8. auth.js: Bearer/Cookie/CSRF/WS-subprotocol/No-WS-Cookie y middlewares requirePerm/requireRole');

    // 9. 100% Backwards Compatibility con Master CULKIBO_TOKEN y modo desarrollo Loopback
    const masterToken = auth.resolveToken();
    const masterReq = {
      method: 'POST',
      originalUrl: '/api/auth/rotate',
      headers: { host: 'panel.example.com', authorization: `Bearer ${masterToken}` },
      socket: { remoteAddress: '203.0.113.10' }
    };
    const masterRes = await runMiddleware(auth.authMiddleware, masterReq);
    assert.strictEqual(masterRes.nextCalled, true);
    assert.strictEqual(masterReq.auth.method, 'token');
    assert.strictEqual(masterReq.auth.principal.isSuperAdmin, true);
    assert.strictEqual(masterReq.auth.principal.role, 'owner');
    assert.strictEqual(masterReq.auth.principal.teamId, DEFAULT_TEAM_ID);
    assert.strictEqual(masterReq.auth.principal.projectIds, null);
    assert.strictEqual((await runMiddleware(roleAdminMw, masterReq)).nextCalled, true);
    assert.strictEqual((await runMiddleware(auth.requireRouteRbac(), masterReq)).nextCalled, true);

    const loopbackReq = {
      method: 'GET',
      originalUrl: '/api/projects',
      headers: { host: 'localhost:3030' },
      socket: { remoteAddress: '127.0.0.1' }
    };
    const loopbackRes = await runMiddleware(auth.authMiddleware, loopbackReq);
    assert.strictEqual(loopbackRes.nextCalled, true);
    assert.strictEqual(loopbackReq.auth.method, 'loopback');
    assert.strictEqual(loopbackReq.auth.principal.isSuperAdmin, true);
    assert.strictEqual(loopbackReq.auth.principal.role, 'owner');
    assert.strictEqual(loopbackReq.auth.principal.teamId, DEFAULT_TEAM_ID);
    assert.strictEqual(loopbackReq.auth.principal.projectIds, null);

    // Persistencia y recuperación en reinicio (recarga desde disco con teams.json + .rbac.key)
    const tmReloaded = new TeamManager({ dataDir: tmpDir, bcryptCost: 4 });
    assert.strictEqual(tmReloaded.isMultiUserEnabled(), true);
    assert.strictEqual(tmReloaded.verifySessionToken(ownerBoot.sessionToken).ok, true);
    assert.strictEqual(tmReloaded.verifyApiToken(freshAdminTok.token).ok, true);
    console.log('  ✓ 9. 100% compatibilidad hacia atrás (Master Token + Loopback SuperAdmin) y recarga desde disco');

    // 10. Regresiones de auditoría (@sec-advisor #36):
    // 10a. requireRole() NO permite que un ckp_ solo-lectura de un owner pase requireRole('admin'|'owner')
    const ownerReadOnlyTok = tm.createApiToken(ownerPrincipal, {
      name: 'Owner ReadOnly Token',
      scopes: ['projects:read']
    });
    const ownerRoPrincipal = tm.verifyApiToken(ownerReadOnlyTok.token).principal;
    const ownerRoReq = { auth: { method: 'api_token', principal: ownerRoPrincipal }, params: {} };
    assert.strictEqual((await runMiddleware(auth.requireRole('owner'), ownerRoReq)).statusCode, 403);
    assert.strictEqual((await runMiddleware(auth.requireRole('admin'), ownerRoReq)).statusCode, 403);
    assert.strictEqual((await runMiddleware(auth.requireRole('developer'), ownerRoReq)).statusCode, 403);
    assert.strictEqual((await runMiddleware(auth.requireRole('viewer'), ownerRoReq)).statusCode, 403);

    const ownerAdminRoleTok = tm.createApiToken(ownerPrincipal, { name: 'Owner Admin Scoped', role: 'admin' });
    const ownerAdminRolePrincipal = tm.verifyApiToken(ownerAdminRoleTok.token).principal;
    assert.strictEqual(
      (await runMiddleware(auth.requireRole('admin'), { auth: { method: 'api_token', principal: ownerAdminRolePrincipal }, params: {} })).nextCalled,
      true
    );
    assert.strictEqual(
      (await runMiddleware(auth.requireRole('owner'), { auth: { method: 'api_token', principal: ownerAdminRolePrincipal }, params: {} })).statusCode,
      403
    );

    const ownerWildcardTok = tm.createApiToken(ownerPrincipal, { name: 'Owner Wildcard', scopes: ['*'] });
    const ownerWildcardPrincipal = tm.verifyApiToken(ownerWildcardTok.token).principal;
    assert.strictEqual(
      (await runMiddleware(auth.requireRole('owner'), { auth: { method: 'api_token', principal: ownerWildcardPrincipal }, params: {} })).nextCalled,
      true
    );

    // 10b. removeProjectAcl() bloquea auto-desbloqueo ('none') y techo de rol
    tm.setProjectAcl(ownerPrincipal, projDefaultA.id, { teamId: DEFAULT_TEAM_ID, userId: adminAcc.user.id, role: 'none' });
    const adminAfterBlockLogin = tm.login({ email: 'admin@example.com', password: 'AdminPassword!2026', teamId: DEFAULT_TEAM_ID });
    const adminBlockedPrincipal = tm.verifySessionToken(adminAfterBlockLogin.sessionToken).principal;
    assert.strictEqual(tm.authorizeProject(adminBlockedPrincipal, projDefaultA.id, 'projects:read', projDefaultA).status, 404);
    assert.throws(
      () => tm.removeProjectAcl(adminBlockedPrincipal, projDefaultA.id, adminAcc.user.id, DEFAULT_TEAM_ID),
      (err) => err.status === 403 && err.code === 'SELF_ESCALATION_BLOCKED',
      'Admin bloqueado con "none" no puede eliminar su propia ACL para auto-desbloquearse'
    );
    assert.throws(
      () => tm.removeProjectAcl(adminBlockedPrincipal, projDefaultA.id, ownerBoot.user.id, DEFAULT_TEAM_ID),
      (err) => err.status === 403 && err.code === 'ROLE_CEILING_EXCEEDED'
    );
    tm.removeProjectAcl(ownerPrincipal, projDefaultA.id, adminAcc.user.id, DEFAULT_TEAM_ID);

    // 10c. authorizeHttpRoute() default-deny: /vault write exige environments:write, rutas v2 admin bloquean developer,
    //      mutaciones desconocidas fallan cerradas (instance:admin), y password/logout-all rechazan api_token!
    const devSecretsReadOnlyTok = tm.createApiToken(ownerPrincipal, {
      name: 'Secrets ReadOnly Token',
      scopes: ['secrets:read']
    });
    const secretsRoPrincipal = tm.verifyApiToken(devSecretsReadOnlyTok.token).principal;
    assert.strictEqual(tm.authorizeHttpRoute(secretsRoPrincipal, 'GET', '/api/vault').allowed, true);
    assert.strictEqual(tm.authorizeHttpRoute(secretsRoPrincipal, 'PUT', '/api/vault/DB_PASS').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(secretsRoPrincipal, 'POST', '/api/vault').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(secretsRoPrincipal, 'DELETE', '/api/vault/DB_PASS').allowed, false);

    // Re-promover dev a developer temporalmente para probar bloqueo en rutas admin/v2/desconocidas
    tm.updateMemberRole(ownerPrincipal, DEFAULT_TEAM_ID, devAcc.user.id, 'developer');
    const devAgainLogin = tm.login({ email: 'dev@example.com', password: 'DevPassword!2026', teamId: DEFAULT_TEAM_ID });
    const devAgainPrincipal = tm.verifySessionToken(devAgainLogin.sessionToken).principal;
    const blockedV2DevRoutes = [
      ['POST', '/api/servers'],
      ['DELETE', '/api/servers/srv_1'],
      ['POST', '/api/gitops/apply'],
      ['POST', '/api/catalog/install'],
      ['POST', '/api/deploy/freeze-windows'],
      ['POST', '/api/teams'],
      ['POST', '/api/unlisted-future-admin-action']
    ];
    for (const [m, routePath] of blockedV2DevRoutes) {
      const dec = tm.authorizeHttpRoute(devAgainPrincipal, m, routePath);
      assert.strictEqual(dec.allowed, false, `Developer debe estar bloqueado por default-deny en ${m} ${routePath}`);
      assert.strictEqual(dec.status, 403);
    }

    // Tokens API (incluso wildcard owner) NUNCA pueden usar /api/auth/password ni /api/auth/logout-all
    assert.strictEqual(tm.authorizeHttpRoute(ownerWildcardPrincipal, 'POST', '/api/auth/password').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(ownerWildcardPrincipal, 'POST', '/api/auth/logout-all').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(ownerWildcardPrincipal, 'POST', '/api/auth/logout').allowed, false);
    assert.strictEqual(tm.authorizeHttpRoute(ownerPrincipal, 'POST', '/api/auth/password').allowed, true);

    // 10d. disableUser() bloquea deshabilitación global cross-team por un owner de un equipo secundario
    const teamC = tm.createTeam(ownerPrincipal, { name: 'Team Charlie', slug: 'charlie' });
    const charlieInv = tm.createInvite(ownerPrincipal, { teamId: teamC.id, email: 'charlie-owner@example.com', role: 'admin' });
    const charlieAcc = tm.acceptInvite({ token: charlieInv.inviteToken, email: 'charlie-owner@example.com', password: 'CharliePassword!2026' });
    tm.transferOwnership(ownerPrincipal, teamC.id, charlieAcc.user.id, { demoteSelf: true });
    // Ahora charlie es owner SOLO de teamC (no es owner de team_default)
    const charlieLogin = tm.login({ email: 'charlie-owner@example.com', password: 'CharliePassword!2026', teamId: teamC.id });
    const charlieOwnerPrincipal = tm.verifySessionToken(charlieLogin.sessionToken).principal;

    // Intentar deshabilitar a adminAcc (que NO está en teamC) -> 404 MEMBER_NOT_FOUND
    assert.throws(
      () => tm.disableUser(charlieOwnerPrincipal, adminAcc.user.id, teamC.id),
      (err) => err.status === 404 && err.code === 'MEMBER_NOT_FOUND'
    );
    // Invitar a adminAcc a teamC (pertenece a team_default y teamC) -> charlie aún NO puede deshabilitarlo globalmente (403)
    const adminTeamCInv = tm.createInvite(charlieOwnerPrincipal, { teamId: teamC.id, email: 'admin@example.com', role: 'viewer' });
    tm.acceptInvite({ token: adminTeamCInv.inviteToken, email: 'admin@example.com', password: 'AdminPassword!2026' });
    assert.throws(
      () => tm.disableUser(charlieOwnerPrincipal, adminAcc.user.id, teamC.id),
      (err) => err.status === 403 && err.code === 'CROSS_TEAM_USER_DISABLE_FORBIDDEN'
    );
    assert.strictEqual(tm._findUserById(adminAcc.user.id).status, 'active', 'La cuenta en team_default debe seguir activa');

    // Un usuario que pertenece exclusivamente a teamC SÍ puede ser deshabilitado por el owner de teamC
    const charlieOnlyInv = tm.createInvite(charlieOwnerPrincipal, { teamId: teamC.id, email: 'only-charlie@example.com', role: 'viewer' });
    const charlieOnlyAcc = tm.acceptInvite({ token: charlieOnlyInv.inviteToken, email: 'only-charlie@example.com', password: 'OnlyCharlie!2026' });
    const disRes = tm.disableUser(charlieOwnerPrincipal, charlieOnlyAcc.user.id, teamC.id);
    assert.strictEqual(disRes.disabled, true);
    assert.strictEqual(tm.verifySessionToken(charlieOnlyAcc.sessionToken).ok, false);

    // 10e. CULKIBO_DATA_DIR respetado por defecto en TeamManager
    const envDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-rbac-envdir-'));
    const prevEnvDir = process.env.CULKIBO_DATA_DIR;
    try {
      process.env.CULKIBO_DATA_DIR = envDataDir;
      const tmEnv = new TeamManager();
      assert.strictEqual(path.resolve(tmEnv.dataDir), path.resolve(envDataDir));
      assert.strictEqual(path.resolve(tmEnv.keyFile), path.resolve(path.join(envDataDir, '.rbac.key')));
    } finally {
      if (prevEnvDir === undefined) delete process.env.CULKIBO_DATA_DIR;
      else process.env.CULKIBO_DATA_DIR = prevEnvDir;
      fs.rmSync(envDataDir, { recursive: true, force: true });
    }
    console.log('  ✓ 10. Regresiones de auditoría (#36): requireRole API-token scopes, removeProjectAcl self-unblock, route fail-closed, cross-team disableUser & CULKIBO_DATA_DIR');

    // 11. P0 Case-Sensitivity, Trailing-Slash, Double-Slash, Dot-Traversal & Audit Route RBAC Bypass Proofs (Real Express!)
    {
      const testApp = express();
      testApp.use('/api', auth.authMiddleware, auth.requireRouteRbac({ teamManager: tm }));
      testApp.get('/api/databases/:id/credentials', (_req, res) => res.json({ password: 'leaked' }));
      testApp.get('/api/catalog/installations/:id/secrets', (_req, res) => res.json({ secret: 'leaked' }));
      testApp.get('/api/vault', (_req, res) => res.json({ secrets: [] }));
      testApp.post('/api/projects/:id/runtime/exec', (_req, res) => res.json({ executed: true }));
      testApp.delete('/api/projects/:id', (_req, res) => res.json({ deleted: true }));
      testApp.post('/api/projects/:id/acl', (_req, res) => res.json({ updated: true }));
      testApp.post('/api/projects/:id/freeze-windows', (_req, res) => res.json({ frozen: true }));
      testApp.get('/api/system/audit', (_req, res) => res.json({ events: [] }));
      testApp.get('/api/system/audit/verify', (_req, res) => res.json({ valid: true }));
      testApp.get('/api/system/health-summary', (_req, res) => res.json({ recentAudit: [] }));
      testApp.get('/api/audit', (_req, res) => res.json({ events: [] }));

      const srv = await new Promise((resolve) => {
        const s = testApp.listen(0, '127.0.0.1', () => resolve(s));
      });
      const port = /** @type {any} */ (srv.address()).port;

      const rawReq = (method, rawPath, token) => new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port,
          method,
          path: rawPath,
          headers: {
            host: 'panel.example.com',
            authorization: `Bearer ${token}`
          }
        }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            let parsed = null;
            try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) {}
            resolve({ status: res.statusCode, body: parsed });
          });
        });
        req.on('error', reject);
        req.end();
      });

      try {
        const freshAdminLogin = tm.login({ email: 'admin@example.com', password: 'AdminPassword!2026', teamId: DEFAULT_TEAM_ID });
        const devWriteOnlyTok = tm.createApiToken(devAgainPrincipal, {
          name: 'Dev Write No Exec',
          scopes: ['projects:read', 'projects:write']
        });

        // Viewer bloqueado en TODOS los intentos de bypass por mayúsculas, doble barra, traversal y rutas reales de auditoría
        const viewerForbiddenPaths = [
          ['GET', '/api/databases/db1/CREDENTIALS'],
          ['GET', '/api/Databases/db1/Credentials'],
          ['GET', '/api/catalog/installations/1/SECRETS'],
          ['GET', '/api/projects/p1/SECRETS'],
          ['GET', '/api/Vault'],
          ['GET', '/api/system/audit'],
          ['GET', '/api/SYSTEM/AUDIT'],
          ['GET', '/api/system/audit/verify'],
          ['GET', '/api/system/health-summary'],
          ['GET', '/api/AUDIT'],
          ['GET', '/api/projects/x/..%2F..%2Fdatabases/db1/credentials'],
          ['GET', '/api/projects/..%2fsystem/audit']
        ];
        for (const [m, pth] of viewerForbiddenPaths) {
          const r = await rawReq(m, pth, viewerLiveTok);
          assert.strictEqual(r.status, 403, `Viewer debe recibir 403 en ${m} ${pth} (recibió ${r.status})`);
        }

        // Developer bloqueado en trailing-slash DELETE, double-slash ACL, uppercase ACL/FREEZE-WINDOWS y audit
        const devForbiddenPaths = [
          ['DELETE', '/api/projects/proj_alpha/'],
          ['DELETE', '/api/projects//proj_alpha'],
          ['POST', '/api/projects/proj_alpha/ACL'],
          ['POST', '/api/projects//proj_alpha/acl'],
          ['POST', '/api/projects/proj_alpha/FREEZE-WINDOWS'],
          ['GET', '/api/system/audit'],
          ['GET', '/api/system/health-summary']
        ];
        for (const [m, pth] of devForbiddenPaths) {
          const r = await rawReq(m, pth, devAgainLogin.sessionToken);
          assert.strictEqual(r.status, 403, `Developer debe recibir 403 en ${m} ${pth} (recibió ${r.status})`);
        }

        // Token projects:write sin runtime:exec bloqueado en Exec con mayúsculas o barra final
        const execUpper = await rawReq('POST', '/api/projects/proj_alpha/runtime/Exec', devWriteOnlyTok.token);
        assert.strictEqual(execUpper.status, 403, 'runtime/Exec en mayúsculas no debe degradar a projects:write');
        const execSlash = await rawReq('POST', '/api/projects/proj_alpha/runtime/exec/', devWriteOnlyTok.token);
        assert.strictEqual(execSlash.status, 403);

        // Codificación URL malformada -> 400 INVALID_PATH (fail-closed)
        const badEnc = await rawReq('GET', '/api/projects/%ZZinvalid', viewerLiveTok);
        assert.strictEqual(badEnc.status, 400);

        // Admin SÍ puede leer /api/system/audit, /api/system/audit/verify y /api/system/health-summary
        assert.strictEqual((await rawReq('GET', '/api/system/audit', freshAdminLogin.sessionToken)).status, 200);
        assert.strictEqual((await rawReq('GET', '/api/system/audit/verify', freshAdminLogin.sessionToken)).status, 200);
        assert.strictEqual((await rawReq('GET', '/api/system/health-summary', freshAdminLogin.sessionToken)).status, 200);
      } finally {
        await new Promise((resolve) => srv.close(resolve));
      }
      console.log('  ✓ 11. Express HTTP real: bypasses case-sensitivity/trailing-slash/double-slash/traversal y /api/system/audit bloqueados');
    }

    // 12. SHA-256 constant-time equality sin fuga de longitud + CULKIBO_DATA_DIR en auth.js
    {
      const isolatedAuthDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-auth-envdir-'));
      const prevEnvDataDir = process.env.CULKIBO_DATA_DIR;
      const prevEnvTok = process.env.CULKIBO_TOKEN;
      try {
        delete process.env.CULKIBO_TOKEN;
        process.env.CULKIBO_DATA_DIR = isolatedAuthDir;
        auth._resetTokenCacheForTest();
        const isoTok = auth.resolveToken();
        assert.ok(fs.existsSync(path.join(isolatedAuthDir, 'auth.json')), 'auth.js debe respetar CULKIBO_DATA_DIR al crear auth.json');
        assert.strictEqual(auth.tokenMatches(isoTok), true);
        assert.strictEqual(auth.tokenMatches(''), false);
        assert.strictEqual(auth.tokenMatches('x'), false);
        assert.strictEqual(auth.tokenMatches(`${isoTok}extra`), false);
        assert.strictEqual(auth.tokenMatches('a'.repeat(512)), false);
        assert.strictEqual(auth.timingSafeEqualString('abc', 'abc'), true);
        assert.strictEqual(auth.timingSafeEqualString('abc', 'abcdef'), false);
        const rot = auth.rotateToken();
        assert.strictEqual(rot.rotated, true);
        assert.strictEqual(auth.tokenMatches(isoTok), false);
        assert.strictEqual(auth.tokenMatches(rot.token), true);
      } finally {
        if (prevEnvDataDir === undefined) delete process.env.CULKIBO_DATA_DIR;
        else process.env.CULKIBO_DATA_DIR = prevEnvDataDir;
        if (prevEnvTok === undefined) delete process.env.CULKIBO_TOKEN;
        else process.env.CULKIBO_TOKEN = prevEnvTok;
        auth._resetTokenCacheForTest();
        fs.rmSync(isolatedAuthDir, { recursive: true, force: true });
      }
      console.log('  ✓ 12. auth.js: comparación constante HMAC-SHA256 (0 length leak) + aislamiento CULKIBO_DATA_DIR');
    }

    // 13. TOTP 2FA (RFC 6238 pure Node crypto) + 10 Recovery Codes HMAC + Anti-Replay + Team Policy
    {
      // Nota: 10d transfirió teamC y subió tokenVersion del owner; iniciamos sesión fresca de owner
      const ownerFreshLogin = tm.login({ email: 'owner@example.com', password: 'OwnerSuperPassword!2026', teamId: DEFAULT_TEAM_ID });
      const ownerFreshPrincipal = tm.verifySessionToken(ownerFreshLogin.sessionToken).principal;

      // Vector oficial RFC 6238 Apéndice B (SHA-1, secreto ASCII "12345678901234567890", T=59s -> 94287082)
      const rfcSecret = Buffer.from('12345678901234567890', 'ascii');
      assert.strictEqual(generateTotpCode(rfcSecret, { timestampMs: 59000, digits: 8, algorithm: 'sha1' }).code, '94287082');
      assert.strictEqual(generateTotpCode(rfcSecret, { timestampMs: 59000, digits: 6, algorithm: 'sha1' }).code, '287082');

      // Setup TOTP para owner (semilla cifrada con AES-256-GCM en teams.json, jamás en claro)
      const setup = tm.setupTotp(ownerFreshPrincipal, { issuer: 'CulkiboTest' });
      assert.ok(setup.secretBase32.length >= 32);
      assert.ok(setup.otpauthUri.startsWith('otpauth://totp/CulkiboTest%3Aowner%40example.com?secret='));
      const diskAfterSetup = fs.readFileSync(path.join(tmpDir, 'teams.json'), 'utf8');
      assert.ok(!diskAfterSetup.includes(setup.secretBase32), 'La semilla TOTP jamás debe persistirse en claro en teams.json');

      const t0 = 1700000010000; // paso fijo determinista
      const codeT0 = generateTotpCode(setup.secretBase32, { timestampMs: t0 }).code;
      const enabled = tm.enableTotp(ownerFreshPrincipal, { code: codeT0, timestampMs: t0 });
      assert.strictEqual(enabled.enabled, true);
      assert.strictEqual(enabled.recoveryCodes.length, 10);
      const diskAfterEnable = fs.readFileSync(path.join(tmpDir, 'teams.json'), 'utf8');
      for (const rc of enabled.recoveryCodes) {
        assert.ok(!diskAfterEnable.includes(rc), 'Los códigos de recuperación en claro jamás deben persistirse en disco');
      }

      // Login paso 1 -> exige MFA sin emitir cks_
      const step1 = tm.login({ email: 'owner@example.com', password: 'OwnerSuperPassword!2026' });
      assert.strictEqual(step1.mfaRequired, true);
      assert.ok(step1.mfaChallengeToken.startsWith('ckm_'));
      assert.strictEqual(step1.sessionToken, undefined);

      // Anti-replay: reutilizar el mismo código TOTP usado en enableTotp dentro del mismo paso -> RECHAZADO
      assert.throws(
        () => tm.verifyMfaLogin({ mfaChallengeToken: step1.mfaChallengeToken, code: codeT0, timestampMs: t0 }),
        (err) => err.status === 401 && err.code === 'TOTP_REPLAY_DETECTED'
      );

      // Siguiente intervalo (+30s): código fresco funciona y emite cks_
      const t1 = t0 + 30000;
      const codeT1 = generateTotpCode(setup.secretBase32, { timestampMs: t1 }).code;
      const step2 = tm.verifyMfaLogin({ mfaChallengeToken: step1.mfaChallengeToken, code: codeT1, timestampMs: t1 });
      assert.ok(step2.sessionToken.startsWith('cks_'));
      assert.strictEqual(step2.usedRecoveryCode, false);
      assert.strictEqual(tm.verifySessionToken(step2.sessionToken).ok, true);

      // Replay del mismo challenge token ckm_ -> RECHAZADO
      assert.throws(
        () => tm.verifyMfaLogin({ mfaChallengeToken: step1.mfaChallengeToken, code: codeT1, timestampMs: t1 }),
        (err) => err.status === 401 && err.code === 'MFA_CHALLENGE_REUSED'
      );

      // Código de recuperación single-use: funciona una vez y se consume (9 restantes)
      const step1Rec = tm.login({ email: 'owner@example.com', password: 'OwnerSuperPassword!2026' });
      const recRes = tm.verifyMfaLogin({ mfaChallengeToken: step1Rec.mfaChallengeToken, recoveryCode: enabled.recoveryCodes[0] });
      assert.strictEqual(recRes.usedRecoveryCode, true);
      assert.strictEqual(recRes.recoveryCodesRemaining, 9);

      // Segundo uso del mismo código de recuperación -> RECHAZADO
      const step1Rec2 = tm.login({ email: 'owner@example.com', password: 'OwnerSuperPassword!2026' });
      assert.throws(
        () => tm.verifyMfaLogin({ mfaChallengeToken: step1Rec2.mfaChallengeToken, recoveryCode: enabled.recoveryCodes[0] }),
        (err) => err.status === 401 && err.code === 'INVALID_MFA_CODE'
      );

      // Política de equipo: exigir 2FA a admins -> admin sin 2FA recibe mfaEnrollmentRequired: true
      tm.setTeamSecurityPolicy(ownerFreshPrincipal, DEFAULT_TEAM_ID, { require2faForAdmins: true });
      const adminEnforceLogin = tm.login({ email: 'admin@example.com', password: 'AdminPassword!2026' });
      assert.strictEqual(adminEnforceLogin.mfaEnrollmentRequired, true);
      const adminEnforcePrincipal = tm.verifySessionToken(adminEnforceLogin.sessionToken).principal;
      assert.strictEqual(tm.getTotpStatus(adminEnforcePrincipal).enrollmentRequired, true);

      // API token (incluso wildcard owner) bloqueado en rutas /api/auth/2fa/*
      assert.strictEqual(tm.authorizeHttpRoute(ownerWildcardPrincipal, 'POST', '/api/auth/2fa/setup').status, 403);

      // Desactivar 2FA requiere contraseña + código válido
      const t2 = t1 + 30000;
      const codeT2 = generateTotpCode(setup.secretBase32, { timestampMs: t2 }).code;
      assert.throws(
        () => tm.disableTotp(ownerFreshPrincipal, { password: 'WrongPassword!', code: codeT2, timestampMs: t2 }),
        (err) => err.status === 401
      );
      const disTotp = tm.disableTotp(ownerFreshPrincipal, { password: 'OwnerSuperPassword!2026', code: codeT2, timestampMs: t2 });
      assert.strictEqual(disTotp.disabled, true);
      console.log('  ✓ 13. TOTP 2FA (RFC 6238 vector + AES-256-GCM + 10 HMAC recovery codes + anti-replay + team enforcement)');
    }

    // 14. OIDC / OAuth2 PKCE + Pure Node JWKS RSA (RS256) & ECDSA (ES256) SSO
    {
      const tmpOidcDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-oidc-test-'));
      try {
        const rsaPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const ecPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const rsaPubJwk = { ...rsaPair.publicKey.export({ format: 'jwk' }), kid: 'rsa-key-1', use: 'sig', alg: 'RS256' };
        const ecPubJwk = { ...ecPair.publicKey.export({ format: 'jwk' }), kid: 'ec-key-1', use: 'sig', alg: 'ES256' };

        const signJwt = (headerObj, payloadObj, keyObj, alg) => {
          const h = Buffer.from(JSON.stringify(headerObj), 'utf8').toString('base64url');
          const p = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
          const input = Buffer.from(`${h}.${p}`, 'ascii');
          const sig = alg === 'ES256'
            ? crypto.sign('sha256', input, { key: keyObj, dsaEncoding: 'ieee-p1363' })
            : crypto.sign('sha256', input, keyObj);
          return `${h}.${p}.${sig.toString('base64url')}`;
        };

        const oidc = new OidcService({ dataDir: tmpOidcDir });
        // Jamás permitir defaultRole: 'owner'
        assert.throws(
          () => oidc.configureProvider({
            id: 'evil-owner',
            type: 'oidc',
            issuerUrl: 'https://idp.example.com',
            clientId: 'cid',
            redirectUri: 'https://panel.example.com/api/auth/oidc/callback',
            defaultRole: 'owner'
          }),
          (err) => err.status === 403 && err.code === 'OWNER_PROVISION_FORBIDDEN'
        );

        oidc.configureProvider({
          id: 'authentik',
          type: 'authentik',
          name: 'Authentik Corp',
          issuerUrl: 'https://auth.corp.example',
          clientId: 'culkibo-client',
          clientSecret: 'super_oidc_secret_xyz',
          redirectUri: 'https://panel.example.com/api/auth/oidc/callback',
          autoProvision: true,
          defaultRole: 'developer',
          allowedDomains: ['corp.example']
        });

        // Verificar clientSecret cifrado en disco (jamás en claro)
        const oidcDisk = fs.readFileSync(path.join(tmpOidcDir, 'oidc.json'), 'utf8');
        assert.ok(!oidcDisk.includes('super_oidc_secret_xyz'), 'clientSecret OIDC jamás debe guardarse en claro');
        assert.ok(oidcDisk.includes('"v1:'), 'clientSecret OIDC debe cifrarse con AES-256-GCM');

        const nowSec = Math.floor(Date.now() / 1000);
        const makeMockFetch = (jwtFactory) => async (url, opts) => {
          if (String(url).endsWith('/.well-known/openid-configuration')) {
            return {
              ok: true,
              status: 200,
              json: async () => ({
                issuer: 'https://auth.corp.example',
                authorization_endpoint: 'https://auth.corp.example/authorize',
                token_endpoint: 'https://auth.corp.example/token',
                jwks_uri: 'https://auth.corp.example/jwks'
              })
            };
          }
          if (String(url).endsWith('/jwks')) {
            return { ok: true, status: 200, json: async () => ({ keys: [rsaPubJwk, ecPubJwk] }) };
          }
          if (String(url).endsWith('/token')) {
            const params = new URLSearchParams(String(opts.body || ''));
            assert.ok(params.get('code_verifier'), 'El intercambio OIDC debe enviar PKCE code_verifier');
            return { ok: true, status: 200, json: async () => ({ id_token: jwtFactory(), access_token: 'at_1' }) };
          }
          throw new Error(`Unexpected fetch URL: ${url}`);
        };

        // Flujo RS256 completo + auto-aprovisionamiento + loginWithOidc
        const startRsa = await oidc.createAuthorizationUrl('authentik', {
          ip: '203.0.113.10',
          fetchImpl: makeMockFetch(() => '')
        });
        const startUrl = new URL(startRsa.url);
        assert.strictEqual(startUrl.searchParams.get('code_challenge_method'), 'S256');
        const rsaNonce = startUrl.searchParams.get('nonce');
        assert.ok(rsaNonce && rsaNonce.length >= 20);

        const idTokenRsa = signJwt(
          { alg: 'RS256', typ: 'JWT', kid: 'rsa-key-1' },
          {
            iss: 'https://auth.corp.example',
            sub: 'sub-alice-rs256',
            aud: 'culkibo-client',
            exp: nowSec + 300,
            iat: nowSec,
            nonce: rsaNonce,
            email: 'sso-alice@corp.example',
            email_verified: true,
            name: 'Alice SSO'
          },
          rsaPair.privateKey,
          'RS256'
        );
        const identRsa = await oidc.handleCallback({
          state: startRsa.state,
          code: 'auth_code_123',
          ip: '203.0.113.10',
          nowSec,
          fetchImpl: makeMockFetch(() => idTokenRsa)
        });
        assert.strictEqual(identRsa.email, 'sso-alice@corp.example');
        const oidcSess = tm.loginWithOidc(identRsa, { autoProvision: true, defaultRole: identRsa.defaultRole });
        assert.strictEqual(oidcSess.provisioned, true);
        assert.strictEqual(oidcSess.role, 'developer');
        assert.ok(oidcSess.sessionToken.startsWith('cks_'));

        // Replay de state -> 401 OIDC_INVALID_STATE
        await assert.rejects(
          () => oidc.handleCallback({ state: startRsa.state, code: 'auth_code_123', ip: '203.0.113.10', fetchImpl: makeMockFetch(() => idTokenRsa) }),
          (err) => err.status === 401 && err.code === 'OIDC_INVALID_STATE'
        );

        // Flujo ES256 válido (ECDSA P-256 ieee-p1363)
        const startEc = await oidc.createAuthorizationUrl('authentik', { fetchImpl: makeMockFetch(() => '') });
        const ecNonce = new URL(startEc.url).searchParams.get('nonce');
        const idTokenEc = signJwt(
          { alg: 'ES256', typ: 'JWT', kid: 'ec-key-1' },
          {
            iss: 'https://auth.corp.example',
            sub: 'sub-bob-es256',
            aud: 'culkibo-client',
            exp: nowSec + 300,
            iat: nowSec,
            nonce: ecNonce,
            email: 'sso-bob@corp.example',
            email_verified: true
          },
          ecPair.privateKey,
          'ES256'
        );
        const identEc = await oidc.handleCallback({
          state: startEc.state,
          code: 'auth_code_ec',
          nowSec,
          fetchImpl: makeMockFetch(() => idTokenEc)
        });
        assert.strictEqual(identEc.email, 'sso-bob@corp.example');

        // Ataques adversarios contra verifyIdToken: alg:none, alg:HS256 (key confusion), tampered, wrong nonce, expired
        const jwksObj = { keys: [rsaPubJwk, ecPubJwk] };
        const fakeNone = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'https://auth.corp.example', sub: 'x', aud: 'culkibo-client', exp: nowSec + 300 })).toString('base64url')}.sig`;
        assert.throws(() => verifyIdToken(fakeNone, { jwks: jwksObj, expectedIssuer: 'https://auth.corp.example', expectedAudience: 'culkibo-client', nowSec }), (e) => e.code === 'OIDC_UNSUPPORTED_ALG');

        const fakeHs256 = `${Buffer.from('{"alg":"HS256","kid":"rsa-key-1"}').toString('base64url')}.${Buffer.from(JSON.stringify({ iss: 'https://auth.corp.example', sub: 'x', aud: 'culkibo-client', exp: nowSec + 300 })).toString('base64url')}.sig`;
        assert.throws(() => verifyIdToken(fakeHs256, { jwks: jwksObj, expectedIssuer: 'https://auth.corp.example', expectedAudience: 'culkibo-client', nowSec }), (e) => e.code === 'OIDC_UNSUPPORTED_ALG');

        const tamperedParts = idTokenRsa.split('.');
        const tamperedPayload = Buffer.from(JSON.stringify({ iss: 'https://auth.corp.example', sub: 'evil', aud: 'culkibo-client', exp: nowSec + 300, nonce: rsaNonce })).toString('base64url');
        assert.throws(() => verifyIdToken(`${tamperedParts[0]}.${tamperedPayload}.${tamperedParts[2]}`, { jwks: jwksObj, expectedIssuer: 'https://auth.corp.example', expectedAudience: 'culkibo-client', expectedNonce: rsaNonce, nowSec }), (e) => e.code === 'OIDC_INVALID_SIGNATURE');

        assert.throws(() => verifyIdToken(idTokenRsa, { jwks: jwksObj, expectedIssuer: 'https://auth.corp.example', expectedAudience: 'culkibo-client', expectedNonce: 'wrong-nonce', nowSec }), (e) => e.code === 'OIDC_NONCE_MISMATCH');
        assert.throws(() => verifyIdToken(idTokenRsa, { jwks: jwksObj, expectedIssuer: 'https://auth.corp.example', expectedAudience: 'culkibo-client', expectedNonce: rsaNonce, nowSec: nowSec + 9999 }), (e) => e.code === 'OIDC_TOKEN_EXPIRED');

        // Rechazar email_verified: false y dominio fuera de allowedDomains
        const startUnver = await oidc.createAuthorizationUrl('authentik', { fetchImpl: makeMockFetch(() => '') });
        const unverNonce = new URL(startUnver.url).searchParams.get('nonce');
        const idTokenUnver = signJwt(
          { alg: 'RS256', kid: 'rsa-key-1' },
          { iss: 'https://auth.corp.example', sub: 'sub-unver', aud: 'culkibo-client', exp: nowSec + 300, nonce: unverNonce, email: 'unver@corp.example', email_verified: false },
          rsaPair.privateKey,
          'RS256'
        );
        await assert.rejects(
          () => oidc.handleCallback({ state: startUnver.state, code: 'c', nowSec, fetchImpl: makeMockFetch(() => idTokenUnver) }),
          (err) => err.status === 403 && err.code === 'OIDC_EMAIL_NOT_VERIFIED'
        );

        const startForeignDom = await oidc.createAuthorizationUrl('authentik', { fetchImpl: makeMockFetch(() => '') });
        const fdNonce = new URL(startForeignDom.url).searchParams.get('nonce');
        const idTokenForeign = signJwt(
          { alg: 'RS256', kid: 'rsa-key-1' },
          { iss: 'https://auth.corp.example', sub: 'sub-fd', aud: 'culkibo-client', exp: nowSec + 300, nonce: fdNonce, email: 'attacker@evil.org', email_verified: true },
          rsaPair.privateKey,
          'RS256'
        );
        await assert.rejects(
          () => oidc.handleCallback({ state: startForeignDom.state, code: 'c', nowSec, fetchImpl: makeMockFetch(() => idTokenForeign) }),
          (err) => err.status === 403 && err.code === 'OIDC_DOMAIN_NOT_ALLOWED'
        );

        // GitHub OAuth2 preset con selección exclusiva de correo verificado
        oidc.configureProvider({
          id: 'github',
          type: 'github',
          clientId: 'gh-cid',
          clientSecret: 'gh-csec',
          redirectUri: 'https://panel.example.com/api/auth/oidc/callback'
        });
        const ghStart = await oidc.createAuthorizationUrl('github');
        const ghIdent = await oidc.handleCallback({
          state: ghStart.state,
          code: 'gh_code',
          fetchImpl: async (url) => {
            if (String(url).includes('/access_token')) return { ok: true, status: 200, json: async () => ({ access_token: 'gho_123' }) };
            if (String(url).endsWith('/user')) return { ok: true, status: 200, json: async () => ({ id: 42, login: 'octodev', name: 'Octo Dev' }) };
            if (String(url).endsWith('/user/emails')) {
              return {
                ok: true,
                status: 200,
                json: async () => [
                  { email: 'unverified@evil.test', primary: true, verified: false },
                  { email: 'octo@verified.dev', primary: false, verified: true }
                ]
              };
            }
            throw new Error(`Unexpected GH URL: ${url}`);
          }
        });
        assert.strictEqual(ghIdent.email, 'octo@verified.dev');
        assert.strictEqual(ghIdent.emailVerified, true);
      } finally {
        fs.rmSync(tmpOidcDir, { recursive: true, force: true });
      }
      console.log('  ✓ 14. OIDC/OAuth2 PKCE + JWKS RS256/ES256 + anti-confusion alg:none/HS256 + email_verified + GitHub');
    }

    // 15. ACL API compatibility (`getProjectAcl` + `setProjectAcl` objeto y firma posicional)
    {
      const ownerAclLogin = tm.login({ email: 'owner@example.com', password: 'OwnerSuperPassword!2026', teamId: DEFAULT_TEAM_ID });
      const ownerAclPrincipal = tm.verifySessionToken(ownerAclLogin.sessionToken).principal;
      tm.setProjectAcl(ownerAclPrincipal, projDefaultA.id, devAcc.user.id, 'viewer', DEFAULT_TEAM_ID);
      const aclRead = tm.getProjectAcl(ownerAclPrincipal, projDefaultA.id, DEFAULT_TEAM_ID);
      assert.strictEqual(aclRead.overrides[devAcc.user.id], 'viewer');
      assert.strictEqual(tm.state.projectAcls[projDefaultA.id].overrides[devAcc.user.id], 'viewer');
      tm.removeProjectAcl(ownerAclPrincipal, projDefaultA.id, devAcc.user.id, DEFAULT_TEAM_ID);
      console.log('  ✓ 15. getProjectAcl() + setProjectAcl() (objeto y posicional) verificados');
    }

    console.log('✅ RBAC, Teams & Multi-Tenant Auth Suite PASSED!\n');
  } finally {
    unsubAuthRevoked();
    auth._setTeamManagerForTest(null);
    auth.resetAuthRateLimit();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

module.exports = testRbac;

if (require.main === module) {
  testRbac()
    .then(() => { setTimeout(() => process.exit(0), 50); })
    .catch((err) => {
      console.error('❌ RBAC test suite failed:', err);
      process.exit(1);
    });
}
