import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  UserPlus,
  KeyRound,
  ShieldCheck,
  Shield,
  Trash2,
  Copy,
  Check,
  Loader2,
  AlertTriangle,
  FolderLock,
  RefreshCw,
  Clock,
} from 'lucide-react';
import {
  api,
  type RbacIdentity,
  type RbacRole,
  type TeamSummary,
  type TeamMember,
  type TeamInvite,
  type ScopedApiToken,
  type Project,
} from '../lib/api';
import { copyToClipboard } from '../lib/clipboard';
import { Modal } from './Modal';
import { HelpTip } from './HelpTip';

interface TeamAccessPanelProps {
  onNotify?: (msg: string, type?: 'info' | 'success' | 'error') => void;
}

type SubTab = 'members' | 'acls' | 'tokens';

const ROLE_META: Record<RbacRole, { label: string; desc: string; badge: string }> = {
  owner: {
    label: 'Propietario',
    desc: 'Control total de la instancia, flota, backups DR y transferencia de propiedad.',
    badge: 'bg-slate-900 text-white border-slate-900',
  },
  admin: {
    label: 'Administrador',
    desc: 'Gestiona proyectos, catálogo, flota, equipo (dev/lector) y auditoría.',
    badge: 'bg-slate-100 text-slate-900 border-slate-300',
  },
  developer: {
    label: 'Desarrollador',
    desc: 'Despliega, sincroniza con Live Sync, gestiona dominios, crons y BD de sus proyectos.',
    badge: 'bg-emerald-50 text-emerald-800 border-emerald-200',
  },
  viewer: {
    label: 'Lector',
    desc: 'Solo lectura de métricas, estado y registros. Secretos y envVars siempre redactados.',
    badge: 'bg-slate-50 text-slate-600 border-slate-200',
  },
};

const AVAILABLE_SCOPES: Array<{ id: string; label: string; group: string }> = [
  { id: 'projects:read', label: 'Proyectos (lectura)', group: 'Proyectos' },
  { id: 'projects:write', label: 'Proyectos (escritura)', group: 'Proyectos' },
  { id: 'deployments:read', label: 'Despliegues (lectura)', group: 'Despliegues' },
  { id: 'deployments:write', label: 'Despliegues y rollback', group: 'Despliegues' },
  { id: 'sync:write', label: 'Live Sync (CLI/IDE)', group: 'Despliegues' },
  { id: 'domains:read', label: 'Dominios (lectura)', group: 'Red' },
  { id: 'domains:write', label: 'Dominios y TLS', group: 'Red' },
  { id: 'databases:read', label: 'Bases de datos (lectura)', group: 'Datos' },
  { id: 'databases:write', label: 'Bases de datos y copias', group: 'Datos' },
  { id: 'mcp:read', label: 'MCP 2.0 (lectura)', group: 'IA / MCP' },
  { id: 'mcp:write', label: 'MCP 2.0 (acciones)', group: 'IA / MCP' },
  { id: 'fleet:read', label: 'Flota SSH (lectura)', group: 'Infra' },
  { id: 'uptime:read', label: 'Uptime y estado', group: 'Infra' },
];

function formatDateShort(raw?: string | null): string {
  if (!raw) return '—';
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' });
}

export const TeamAccessPanel: React.FC<TeamAccessPanelProps> = ({ onNotify }) => {
  const [subTab, setSubTab] = useState<SubTab>('members');
  const [loading, setLoading] = useState(true);
  const [me, setMe] = useState<RbacIdentity | null>(null);
  const [teams, setTeams] = useState<TeamSummary[]>([]);
  const [activeTeamId, setActiveTeamId] = useState<string>('team_default');
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [invites, setInvites] = useState<TeamInvite[]>([]);
  const [tokens, setTokens] = useState<ScopedApiToken[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Project ACL state
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [aclOverrides, setAclOverrides] = useState<Record<string, string>>({});
  const [aclLoadedFor, setAclLoadedFor] = useState<string | null>(null);
  const aclLoading = subTab === 'acls' && Boolean(selectedProjectId) && aclLoadedFor !== selectedProjectId;

  // Invite modal + Copy-once modal
  const [inviteModalOpen, setInviteModalOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<RbacRole>('developer');
  const [inviteTtl, setInviteTtl] = useState('48');
  const [inviteAllProjects, setInviteAllProjects] = useState(true);
  const [inviteProjectIds, setInviteProjectIds] = useState<string[]>([]);
  const [createdInviteSecret, setCreatedInviteSecret] = useState<{
    email: string;
    role: RbacRole;
    token: string;
    url: string;
    expiresAt?: string;
  } | null>(null);

  // Scoped token modal + Copy-once modal
  const [tokenModalOpen, setTokenModalOpen] = useState(false);
  const [tokName, setTokName] = useState('');
  const [tokRole, setTokRole] = useState<RbacRole>('developer');
  const [tokScopes, setTokScopes] = useState<string[]>(['projects:read', 'deployments:write', 'mcp:read']);
  const [tokAllProjects, setTokAllProjects] = useState(true);
  const [tokProjectIds, setTokProjectIds] = useState<string[]>([]);
  const [tokExpiresDays, setTokExpiresDays] = useState('90');
  const [createdApiSecret, setCreatedApiSecret] = useState<{
    name: string;
    token: string;
    scopes: string[];
  } | null>(null);

  // Confirmations
  const [confirmRemoveMember, setConfirmRemoveMember] = useState<TeamMember | null>(null);
  const [confirmRevokeToken, setConfirmRevokeToken] = useState<ScopedApiToken | null>(null);

  const loadAll = useCallback(async (teamIdOverride?: string) => {
    try {
      const [meRes, teamsRes, tokensRes, projRes] = await Promise.all([
        api.getRbacMe().catch(() => null),
        api.getTeams().catch(() => ({ teams: [] })),
        api.getScopedTokens().catch(() => ({ tokens: [] })),
        api.getProjects().catch(() => []),
      ]);
      setMe(meRes);
      const teamList = teamsRes.teams || [];
      setTeams(teamList);
      const targetTeam = teamIdOverride || teamList[0]?.id || 'team_default';
      setActiveTeamId(targetTeam);
      setTokens(tokensRes.tokens || []);
      setProjects(Array.isArray(projRes) ? projRes : []);
      if (Array.isArray(projRes) && projRes.length > 0) {
        setSelectedProjectId((prev) => prev || projRes[0].id);
      }

      if (teamList.length === 0) {
        setMembers([]);
        setInvites([]);
      } else {
        const [memRes, invRes] = await Promise.all([
          api.getTeamMembers(targetTeam).catch(() => ({ members: [], invites: [] })),
          api.getTeamInvites(targetTeam).catch(() => ({ invites: [] })),
        ]);
        setMembers(memRes.members || []);
        setInvites(invRes.invites?.length ? invRes.invites : (memRes.invites || []));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  useEffect(() => {
    if (subTab !== 'acls' || !selectedProjectId) return;
    let active = true;
    api.getProjectAcl(selectedProjectId)
      .then((res) => {
        if (!active) return;
        setAclOverrides(res?.overrides || {});
        setAclLoadedFor(selectedProjectId);
      })
      .catch(() => {
        if (!active) return;
        setAclOverrides({});
        setAclLoadedFor(selectedProjectId);
      });
    return () => { active = false; };
  }, [subTab, selectedProjectId]);

  const copy = async (text: string, id: string, label = 'Copiado al portapapeles') => {
    const ok = await copyToClipboard(text);
    if (!ok) {
      onNotify?.('No se pudo copiar al portapapeles', 'error');
      return;
    }
    setCopiedKey(id);
    window.setTimeout(() => setCopiedKey(null), 1800);
    onNotify?.(label, 'success');
  };

  const handleSelectTeam = async (teamId: string) => {
    setActiveTeamId(teamId);
    const [memRes, invRes] = await Promise.all([
      api.getTeamMembers(teamId).catch(() => ({ members: [], invites: [] })),
      api.getTeamInvites(teamId).catch(() => ({ invites: [] })),
    ]);
    setMembers(memRes.members || []);
    setInvites(invRes.invites?.length ? invRes.invites : (memRes.invites || []));
  };

  const handleRoleChange = async (member: TeamMember, nextRole: RbacRole) => {
    const memberId = member.userId || member.id;
    setBusyId(`role-${memberId}`);
    try {
      await api.updateTeamMember(memberId, { teamId: activeTeamId, role: nextRole });
      onNotify?.(`Rol de ${member.email} actualizado a ${ROLE_META[nextRole].label}`, 'success');
      await loadAll(activeTeamId);
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo cambiar el rol', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleRemoveMember = async () => {
    if (!confirmRemoveMember) return;
    const memberId = confirmRemoveMember.userId || confirmRemoveMember.id;
    setBusyId(`rm-${memberId}`);
    try {
      await api.removeTeamMember(memberId, activeTeamId);
      onNotify?.(`${confirmRemoveMember.email} eliminado del equipo`, 'info');
      setConfirmRemoveMember(null);
      await loadAll(activeTeamId);
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo eliminar al miembro', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleCreateInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setBusyId('create-invite');
    try {
      const ttlHours = Math.max(1, Math.min(168, Number.parseInt(inviteTtl, 10) || 48));
      const res = await api.createTeamInvite({
        teamId: activeTeamId,
        email: inviteEmail.trim().toLowerCase(),
        role: inviteRole,
        ttlHours,
        projectIds: inviteAllProjects ? null : inviteProjectIds,
      });
      const rawToken = res.token || res.inviteToken || '';
      const inviteUrl = res.inviteUrl || `${window.location.origin}/#/accept-invite?token=${encodeURIComponent(rawToken)}`;
      setInviteModalOpen(false);
      setInviteEmail('');
      setInviteProjectIds([]);
      setInviteAllProjects(true);
      setCreatedInviteSecret({
        email: res.invite?.email || inviteEmail.trim().toLowerCase(),
        role: res.invite?.role || inviteRole,
        token: rawToken,
        url: inviteUrl,
        expiresAt: res.invite?.expiresAt,
      });
      onNotify?.('Enlace de invitación de un solo uso generado', 'success');
      await loadAll(activeTeamId);
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo generar la invitación', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleRevokeInvite = async (inv: TeamInvite) => {
    setBusyId(`inv-${inv.id}`);
    try {
      await api.revokeTeamInvite(inv.id, inv.teamId || activeTeamId);
      onNotify?.(`Invitación para ${inv.email} revocada`, 'info');
      await loadAll(activeTeamId);
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo revocar la invitación', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleUpdateProjectAcl = async (member: TeamMember, nextOverride: string) => {
    if (!selectedProjectId) return;
    const userId = member.userId || member.id;
    setBusyId(`acl-${userId}`);
    try {
      if (nextOverride === 'inherit') {
        await api.removeProjectAcl(selectedProjectId, userId);
      } else {
        await api.setProjectAcl(selectedProjectId, { userId, role: nextOverride });
      }
      setAclOverrides((prev) => {
        const next = { ...prev };
        if (nextOverride === 'inherit') delete next[userId];
        else next[userId] = nextOverride;
        return next;
      });
      onNotify?.(`Permiso de ${member.email} actualizado en el proyecto`, 'success');
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo actualizar el ACL del proyecto', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const toggleScope = (scopeId: string) => {
    setTokScopes((prev) =>
      prev.includes(scopeId) ? prev.filter((s) => s !== scopeId) : [...prev, scopeId]
    );
  };

  const toggleProjectChoice = (id: string, list: string[], setter: (next: string[]) => void) => {
    setter(list.includes(id) ? list.filter((x) => x !== id) : [...list, id]);
  };

  const handleCreateToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokName.trim() || tokScopes.length === 0) return;
    setBusyId('create-token');
    try {
      const days = Number.parseInt(tokExpiresDays, 10);
      const res = await api.createScopedToken({
        name: tokName.trim(),
        role: tokRole,
        scopes: tokScopes,
        projectIds: tokAllProjects ? '*' : tokProjectIds,
        expiresInDays: Number.isFinite(days) && days > 0 ? days : null,
        teamId: activeTeamId,
      });
      setTokenModalOpen(false);
      setCreatedApiSecret({
        name: tokName.trim(),
        token: res.token,
        scopes: [...tokScopes],
      });
      setTokName('');
      setTokProjectIds([]);
      setTokAllProjects(true);
      onNotify?.('Token con alcance generado correctamente', 'success');
      await loadAll(activeTeamId);
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo crear el token', 'error');
    } finally {
      setBusyId(null);
    }
  };

  const handleRevokeToken = async () => {
    if (!confirmRevokeToken) return;
    setBusyId(`tok-${confirmRevokeToken.id}`);
    try {
      await api.revokeScopedToken(confirmRevokeToken.id);
      onNotify?.(`Token «${confirmRevokeToken.name}» revocado inmediatamente`, 'info');
      setConfirmRevokeToken(null);
      await loadAll(activeTeamId);
    } catch (err) {
      onNotify?.(err instanceof Error ? err.message : 'No se pudo revocar el token', 'error');
    } finally {
      setBusyId(null);
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-10 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Cargando equipos, roles y tokens…</span>
      </div>
    );
  }

  const currentRole: RbacRole = me?.role || 'owner';
  const canManageTeam = currentRole === 'owner' || currentRole === 'admin' || Boolean(me?.isSuperAdmin);

  return (
    <div className="space-y-5">
      {/* Cabecera e identidad activa */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            <div className="w-9 h-9 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 flex items-center justify-center shrink-0">
              <Users className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-sm font-semibold text-slate-900">Equipo, Roles (RBAC) y Tokens con alcance</h2>
                <HelpTip title="Control de acceso y revocación inmediata">
                  <p>Los roles siguen una jerarquía estricta: Propietario &gt; Administrador &gt; Desarrollador &gt; Lector.</p>
                  <p>Cada invitación es de un solo uso y los tokens API/MCP intersecan sus permisos con el rol vigente del usuario en tiempo real.</p>
                </HelpTip>
                <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${ROLE_META[currentRole].badge}`}>
                  Tu rol: {ROLE_META[currentRole].label}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                {me?.email
                  ? `Sesión activa como ${me.email} (${me.method || 'sesión'}).`
                  : 'Modo administrador único compatible con CULKIBO_TOKEN activo; puedes emitir invitaciones y tokens con alcance.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap shrink-0">
            {teams.length > 1 && (
              <select
                aria-label="Seleccionar espacio de trabajo"
                value={activeTeamId}
                onChange={(e) => void handleSelectTeam(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs text-slate-800"
              >
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            )}
            <button
              type="button"
              onClick={() => void loadAll(activeTeamId)}
              aria-label="Actualizar miembros y tokens"
              className="p-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Sub-pestañas */}
        <div className="flex items-center gap-1 p-1 bg-slate-100 border border-slate-200 rounded-lg text-xs overflow-x-auto no-scrollbar">
          {([
            { id: 'members', label: `Miembros e invitaciones (${members.length})`, icon: Users },
            { id: 'acls', label: 'ACL por proyecto', icon: FolderLock },
            { id: 'tokens', label: `Tokens API / MCP (${tokens.length})`, icon: KeyRound },
          ] as const).map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setSubTab(t.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium whitespace-nowrap transition-colors cursor-pointer ${
                  subTab === t.id ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* SUBTAB 1: Miembros e invitaciones */}
      {subTab === 'members' && (
        <div className="space-y-4">
          {/* Matriz de roles compacta */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {(['owner', 'admin', 'developer', 'viewer'] as const).map((role) => (
              <div key={role} className="bg-white border border-slate-200 rounded-xl p-3 space-y-1">
                <span className={`inline-block px-2 py-0.5 rounded-md text-[10px] font-semibold border ${ROLE_META[role].badge}`}>
                  {ROLE_META[role].label}
                </span>
                <p className="text-[11px] text-slate-500 leading-relaxed">{ROLE_META[role].desc}</p>
              </div>
            ))}
          </div>

          {/* Lista de miembros */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-semibold text-slate-800">
                Miembros activos ({members.length})
              </div>
              {canManageTeam && (
                <button
                  type="button"
                  onClick={() => setInviteModalOpen(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Invitar miembro</span>
                </button>
              )}
            </div>

            {members.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 space-y-2">
                <p className="font-medium text-slate-700">Todavía no hay cuentas multiusuario creadas.</p>
                <p>Genera una invitación de un solo uso para añadir desarrolladores, administradores o lectores con acceso aislado.</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {members.map((m) => {
                  const mid = m.userId || m.id;
                  return (
                    <div key={mid} className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-slate-900 truncate">{m.name || m.email}</span>
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${ROLE_META[m.role]?.badge || ROLE_META.viewer.badge}`}>
                            {ROLE_META[m.role]?.label || m.role}
                          </span>
                          {Array.isArray(m.projectIds) && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px] font-mono tabular-nums">
                              {m.projectIds.length} proyectos
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono truncate mt-0.5">{m.email}</div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {canManageTeam && m.role !== 'owner' && (
                          <select
                            aria-label={`Rol de ${m.email}`}
                            value={m.role}
                            disabled={busyId === `role-${mid}`}
                            onChange={(e) => void handleRoleChange(m, e.target.value as RbacRole)}
                            className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs text-slate-800"
                          >
                            {currentRole === 'owner' && <option value="admin">Administrador</option>}
                            <option value="developer">Desarrollador</option>
                            <option value="viewer">Lector</option>
                          </select>
                        )}
                        {canManageTeam && m.role !== 'owner' && (
                          <button
                            type="button"
                            aria-label={`Eliminar a ${m.email}`}
                            onClick={() => setConfirmRemoveMember(m)}
                            className="p-1.5 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-slate-500 hover:text-red-700 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Invitaciones pendientes */}
          {invites.length > 0 && (
            <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
              <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-800">
                Invitaciones pendientes ({invites.length})
              </div>
              <div className="divide-y divide-slate-100">
                {invites.map((inv) => (
                  <div key={inv.id} className="px-5 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-medium text-slate-900 truncate">{inv.email}</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${ROLE_META[inv.role]?.badge || ROLE_META.viewer.badge}`}>
                          {ROLE_META[inv.role]?.label || inv.role}
                        </span>
                        {inv.tokenPrefix && (
                          <code className="text-[10px] font-mono text-slate-400">{inv.tokenPrefix}••••</code>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5 tabular-nums">
                        <Clock className="w-3 h-3" />
                        <span>Caduca el {formatDateShort(inv.expiresAt)}</span>
                      </div>
                    </div>
                    {canManageTeam && !inv.usedAt && !inv.revokedAt && (
                      <button
                        type="button"
                        disabled={busyId === `inv-${inv.id}`}
                        onClick={() => void handleRevokeInvite(inv)}
                        className="px-2.5 py-1 rounded-lg border border-red-200 bg-white hover:bg-red-50 text-red-700 text-[11px] font-medium cursor-pointer self-start sm:self-auto"
                      >
                        Revocar
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 2: Project ACLs */}
      {subTab === 'acls' && (
        <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-4 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Permisos específicos por proyecto (ACL)</h3>
              <p className="text-slate-500 mt-0.5">
                Sobrescribe el rol de equipo de un miembro para un proyecto concreto o bloquéale el acceso con «Sin acceso».
              </p>
            </div>
            <select
              aria-label="Seleccionar proyecto para ACL"
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              className="px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900 min-w-[200px]"
            >
              {projects.length === 0 && <option value="">Sin proyectos disponibles</option>}
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>

          {projects.length === 0 ? (
            <div className="p-6 text-center text-slate-500 bg-slate-50 rounded-xl border border-slate-200">
              Crea un proyecto primero para configurar excepciones de acceso por proyecto.
            </div>
          ) : aclLoading ? (
            <div className="p-6 text-center text-slate-500 flex items-center justify-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> Cargando reglas ACL…
            </div>
          ) : members.length === 0 ? (
            <div className="p-6 text-center text-slate-500 bg-slate-50 rounded-xl border border-slate-200">
              No hay miembros en este equipo todavía. Invita miembros desde la pestaña anterior.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden">
              {members.map((m) => {
                const uid = m.userId || m.id;
                const currentOverride = aclOverrides[uid] || 'inherit';
                return (
                  <div key={uid} className="px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-white">
                    <div className="min-w-0">
                      <div className="font-semibold text-slate-900 truncate">{m.name || m.email}</div>
                      <div className="text-[11px] text-slate-500 font-mono truncate">
                        {m.email} · Rol equipo: {ROLE_META[m.role]?.label || m.role}
                      </div>
                    </div>
                    <select
                      aria-label={`Permiso de ${m.email} en proyecto`}
                      disabled={!canManageTeam || m.role === 'owner' || busyId === `acl-${uid}`}
                      value={currentOverride}
                      onChange={(e) => void handleUpdateProjectAcl(m, e.target.value)}
                      className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-slate-800"
                    >
                      <option value="inherit">Heredar del equipo ({ROLE_META[m.role]?.label})</option>
                      <option value="admin">Administrador en este proyecto</option>
                      <option value="developer">Desarrollador en este proyecto</option>
                      <option value="viewer">Solo lectura (Lector)</option>
                      <option value="none">Sin acceso (denegar)</option>
                    </select>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 3: Scoped API / MCP Tokens */}
      {subTab === 'tokens' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs font-semibold text-slate-800">Tokens API y MCP con alcance reducido</div>
              <p className="text-[11px] text-slate-500">
                Ideales para CI/CD, Cursor, Claude Code o CLI sin compartir el token maestro de la instancia.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setTokenModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer"
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Crear token</span>
            </button>
          </div>

          {tokens.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 space-y-2">
              <Shield className="w-7 h-7 text-slate-300 mx-auto" />
              <p className="font-medium text-slate-700">No hay tokens con alcance creados.</p>
              <p>Crea tokens limitados a proyectos y permisos específicos (ej. solo despliegue o solo lectura MCP).</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {tokens.map((tok) => (
                <div key={tok.id} className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-start justify-between gap-3 text-xs">
                  <div className="min-w-0 space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-slate-900">{tok.name}</span>
                      <code className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[10px] text-slate-700">
                        {tok.tokenPrefix}••••
                      </code>
                      <span className="px-2 py-0.5 rounded bg-slate-50 border border-slate-200 text-[10px] text-slate-600 tabular-nums">
                        {tok.projectIds === '*' || !tok.projectIds
                          ? 'Todos los proyectos'
                          : `${tok.projectIds.length} ${tok.projectIds.length === 1 ? 'proyecto' : 'proyectos'}`}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {(tok.scopes || []).map((sc) => (
                        <span key={sc} className="px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 font-mono text-[10px] text-slate-600">
                          {sc}
                        </span>
                      ))}
                    </div>
                    <div className="text-[11px] text-slate-400 tabular-nums">
                      Creado: {formatDateShort(tok.createdAt)}
                      {tok.expiresAt ? ` · Caduca: ${formatDateShort(tok.expiresAt)}` : ' · Sin caducidad'}
                      {tok.lastUsedAt ? ` · Último uso: ${formatDateShort(tok.lastUsedAt)}` : ''}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setConfirmRevokeToken(tok)}
                    className="px-3 py-1.5 rounded-lg border border-red-200 bg-white hover:bg-red-50 text-red-700 font-medium text-xs cursor-pointer shrink-0 self-start"
                  >
                    Revocar
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modal: Invitar miembro */}
      <Modal
        open={inviteModalOpen}
        onClose={() => setInviteModalOpen(false)}
        title="Generar invitación de un solo uso"
        subtitle="El enlace se vincula al correo indicado, caduca automáticamente y nunca modifica contraseñas existentes."
        maxWidthClass="max-w-lg"
      >
        <form onSubmit={handleCreateInvite} className="p-5 space-y-4 text-xs">
          <label className="block">
            <span className="font-medium text-slate-700">Correo electrónico del miembro</span>
            <input
              type="email"
              required
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="dev@empresa.com"
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
            />
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="font-medium text-slate-700">Rol asignado</span>
              <select
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as RbacRole)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
              >
                {currentRole === 'owner' && <option value="admin">Administrador</option>}
                <option value="developer">Desarrollador</option>
                <option value="viewer">Lector (solo lectura)</option>
              </select>
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Caducidad (horas, máx. 168)</span>
              <input
                type="number"
                min={1}
                max={168}
                value={inviteTtl}
                onChange={(e) => setInviteTtl(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
              />
            </label>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <label className="inline-flex items-center gap-2 font-medium text-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={inviteAllProjects}
                onChange={(e) => setInviteAllProjects(e.target.checked)}
                className="accent-slate-900"
              />
              <span>Acceso a todos los proyectos del espacio de trabajo</span>
            </label>
            {!inviteAllProjects && projects.length > 0 && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 max-h-36 overflow-y-auto">
                {projects.map((p) => (
                  <label key={p.id} className="inline-flex items-center gap-1.5 text-slate-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={inviteProjectIds.includes(p.id)}
                      onChange={() => toggleProjectChoice(p.id, inviteProjectIds, setInviteProjectIds)}
                      className="accent-slate-900"
                    />
                    <span className="truncate">{p.name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setInviteModalOpen(false)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyId === 'create-invite'}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {busyId === 'create-invite' ? 'Generando…' : 'Crear invitación'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal COPY-ONCE: Invitación creada */}
      <Modal
        open={Boolean(createdInviteSecret)}
        onClose={() => setCreatedInviteSecret(null)}
        title="Enlace de invitación listo (mostrar una sola vez)"
        subtitle="Copia este enlace ahora. Por seguridad solo se guarda su hash HMAC y no volverá a mostrarse."
        maxWidthClass="max-w-lg"
      >
        {createdInviteSecret && (
          <div className="p-5 space-y-4 text-xs">
            <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <span>
                Válido únicamente para <strong className="font-mono">{createdInviteSecret.email}</strong> con rol{' '}
                <strong>{ROLE_META[createdInviteSecret.role]?.label}</strong>. Al cerrar esta ventana no podrá recuperarse.
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="font-medium text-slate-700">Enlace de invitación</div>
              <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                <code className="flex-1 font-mono text-[11px] text-slate-800 break-all">{createdInviteSecret.url}</code>
                <button
                  type="button"
                  onClick={() => void copy(createdInviteSecret.url, 'copy-inv-url', 'Enlace de invitación copiado')}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-slate-900 text-white font-medium shrink-0 cursor-pointer"
                >
                  {copiedKey === 'copy-inv-url' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copiar</span>
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="font-medium text-slate-700">Token de invitación (CLI / API)</div>
              <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                <code className="flex-1 font-mono text-[11px] text-slate-800 break-all">{createdInviteSecret.token}</code>
                <button
                  type="button"
                  onClick={() => void copy(createdInviteSecret.token, 'copy-inv-tok', 'Token de invitación copiado')}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-white border border-slate-200 text-slate-700 font-medium shrink-0 cursor-pointer"
                >
                  {copiedKey === 'copy-inv-tok' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copiar</span>
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setCreatedInviteSecret(null)}
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer"
              >
                He guardado el enlace
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Modal: Crear Token API / MCP con alcance */}
      <Modal
        open={tokenModalOpen}
        onClose={() => setTokenModalOpen(false)}
        title="Crear token API / MCP con alcance"
        subtitle="El token nunca podrá superar los permisos efectivos de tu rol actual."
        maxWidthClass="max-w-xl"
      >
        <form onSubmit={handleCreateToken} className="p-5 space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="block sm:col-span-2">
              <span className="font-medium text-slate-700">Nombre descriptivo</span>
              <input
                required
                value={tokName}
                onChange={(e) => setTokName(e.target.value)}
                placeholder="GitHub Actions CI o Agente Cursor"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 text-slate-900"
              />
            </label>
            <label className="block">
              <span className="font-medium text-slate-700">Caducidad (días)</span>
              <input
                type="number"
                min={1}
                max={365}
                value={tokExpiresDays}
                onChange={(e) => setTokExpiresDays(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 font-mono text-slate-900 tabular-nums"
              />
            </label>
          </div>

          <label className="block">
            <span className="font-medium text-slate-700">Techo de rol del token</span>
            <select
              value={tokRole}
              onChange={(e) => setTokRole(e.target.value as RbacRole)}
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-900"
            >
              {(currentRole === 'owner' || me?.isSuperAdmin) && <option value="admin">Administrador</option>}
              <option value="developer">Desarrollador</option>
              <option value="viewer">Lector (solo lectura)</option>
            </select>
          </label>

          <div className="space-y-2">
            <div className="font-medium text-slate-700">Permisos (scopes) seleccionados ({tokScopes.length})</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 p-3 rounded-xl bg-slate-50 border border-slate-200 max-h-48 overflow-y-auto">
              {AVAILABLE_SCOPES.map((sc) => (
                <label key={sc.id} className="inline-flex items-center gap-2 text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={tokScopes.includes(sc.id)}
                    onChange={() => toggleScope(sc.id)}
                    className="accent-slate-900"
                  />
                  <span className="truncate">{sc.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <label className="inline-flex items-center gap-2 font-medium text-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={tokAllProjects}
                onChange={(e) => setTokAllProjects(e.target.checked)}
                className="accent-slate-900"
              />
              <span>Permitir en todos los proyectos</span>
            </label>
            {!tokAllProjects && projects.length > 0 && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 max-h-32 overflow-y-auto">
                {projects.map((p) => (
                  <label key={p.id} className="inline-flex items-center gap-1.5 text-slate-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={tokProjectIds.includes(p.id)}
                      onChange={() => toggleProjectChoice(p.id, tokProjectIds, setTokProjectIds)}
                      className="accent-slate-900"
                    />
                    <span className="truncate">{p.name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
            <button type="button" onClick={() => setTokenModalOpen(false)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyId === 'create-token' || tokScopes.length === 0}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              {busyId === 'create-token' ? 'Generando…' : 'Emitir token'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal COPY-ONCE: Token API / MCP emitido */}
      <Modal
        open={Boolean(createdApiSecret)}
        onClose={() => setCreatedApiSecret(null)}
        title="Token API / MCP generado (copiar ahora)"
        subtitle="Esta es la única vez que se muestra el secreto sin cifrar. No se almacena en el navegador."
        maxWidthClass="max-w-lg"
      >
        {createdApiSecret && (
          <div className="p-5 space-y-4 text-xs">
            <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-900 flex items-start gap-2.5">
              <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <span>
                Token <strong>{createdApiSecret.name}</strong> listo para usar en cabecera{' '}
                <code className="font-mono">Authorization: Bearer &lt;token&gt;</code> o clientes MCP.
              </span>
            </div>

            <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg p-3">
              <code className="flex-1 font-mono text-[11px] text-slate-900 break-all">{createdApiSecret.token}</code>
              <button
                type="button"
                onClick={() => void copy(createdApiSecret.token, 'copy-api-tok', 'Token API copiado')}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-slate-900 text-white font-medium shrink-0 cursor-pointer"
              >
                {copiedKey === 'copy-api-tok' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copiar</span>
              </button>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setCreatedApiSecret(null)}
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer"
              >
                Cerrar y ocultar secreto
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Modal: Confirmar baja de miembro */}
      <Modal
        open={Boolean(confirmRemoveMember)}
        onClose={() => setConfirmRemoveMember(null)}
        title={`Eliminar a ${confirmRemoveMember?.email || ''}`}
        subtitle="Sus sesiones activas y tickets WebSocket se revocarán al instante."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4 text-xs">
          <p className="text-slate-600">
            El usuario perderá el acceso a este equipo de forma inmediata. Podrás volver a invitarlo más adelante si es necesario.
          </p>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setConfirmRemoveMember(null)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="button"
              disabled={busyId !== null}
              onClick={() => void handleRemoveMember()}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              Eliminar miembro
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal: Confirmar revocación de token */}
      <Modal
        open={Boolean(confirmRevokeToken)}
        onClose={() => setConfirmRevokeToken(null)}
        title={`Revocar token «${confirmRevokeToken?.name || ''}»`}
        subtitle="Cualquier agente MCP, CLI o pipeline CI/CD que use este token dejará de autenticar de inmediato."
        maxWidthClass="max-w-md"
      >
        <div className="p-5 space-y-4 text-xs">
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setConfirmRevokeToken(null)} className="px-3.5 py-2 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50 cursor-pointer">
              Cancelar
            </button>
            <button
              type="button"
              disabled={busyId !== null}
              onClick={() => void handleRevokeToken()}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium cursor-pointer disabled:opacity-50"
            >
              Revocar token
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
