const crypto = require('crypto');

/**
 * Runtime-Tailored Least-Privilege OCI Seccomp Profile Generator & `runc` CVE Guard
 * (guards against `runc CVE-2025-31133`, `CVE-2025-52565`, `CVE-2025-52881` and
 * `io_uring` / `ptrace` / `bpf` / `mount` kernel escape primitives).
 *
 * 0 dependencias npm externas, 0 invocaciones de shell, 0 mutaciones en disco.
 */

const SUPPORTED_STACKS = Object.freeze(['node', 'python', 'go', 'rust', 'static-caddy']);

const BLOCKED_SYSCALLS = Object.freeze([
  'io_uring_setup',
  'io_uring_enter',
  'io_uring_register',
  'ptrace',
  'mount',
  'umount2',
  'pivot_root',
  'unshare',
  'setns',
  'keyctl',
  'bpf',
  'kexec_load',
  'kexec_file_load',
  'init_module',
  'finit_module',
  'delete_module',
  'reboot',
  'swapon',
  'swapoff',
  'acct',
  'settimeofday',
  'clock_settime',
  'add_key',
  'request_key',
  'userfaultfd',
  'perf_event_open',
  'open_by_handle_at'
]);

const BLOCKED_SET = new Set(BLOCKED_SYSCALLS);

const RUNC_2025_CVES = Object.freeze([
  'CVE-2025-31133',
  'CVE-2025-52565',
  'CVE-2025-52881'
]);

/** Minimal common POSIX + epoll/socket syscalls required by static web/runtime binaries. */
const BASE_SYSCALLS = Object.freeze([
  'read', 'write', 'openat', 'close', 'fstat', 'newfstatat', 'statx', 'lseek',
  'mmap', 'mprotect', 'munmap', 'brk', 'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
  'ioctl', 'pread64', 'pwrite64', 'readv', 'writev', 'access', 'pipe2',
  'sched_yield', 'mremap', 'madvise', 'dup', 'dup2', 'dup3',
  'nanosleep', 'clock_nanosleep', 'clock_gettime', 'clock_getres', 'gettimeofday',
  'getpid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid', 'getppid', 'getgroups',
  'socket', 'connect', 'accept', 'accept4', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg',
  'shutdown', 'bind', 'listen', 'getsockname', 'getpeername', 'socketpair',
  'setsockopt', 'getsockopt', 'epoll_create1', 'epoll_ctl', 'epoll_pwait', 'epoll_wait',
  'poll', 'ppoll', 'eventfd2', 'timerfd_create', 'timerfd_settime', 'timerfd_gettime',
  'futex', 'set_tid_address', 'set_robust_list', 'rseq', 'prlimit64', 'getrlimit',
  'getrandom', 'uname', 'getcwd', 'chdir', 'fcntl', 'flock', 'fsync', 'fdatasync',
  'readlinkat', 'getdents64', 'mkdirat', 'unlinkat', 'renameat2', 'fchmod', 'ftruncate',
  'sigaltstack', 'arch_prctl', 'prctl', 'exit', 'exit_group', 'tgkill', 'tkill', 'kill',
  'sched_getaffinity', 'sysinfo', 'umask', 'statfs', 'fstatfs'
]);

/** Stack-specific minimal additive syscalls (never overlapping BLOCKED_SYSCALLS). */
const STACK_ADDONS = Object.freeze({
  'static-caddy': Object.freeze(['sendfile', 'splice', 'inotify_init1', 'inotify_add_watch', 'inotify_rm_watch']),
  go: Object.freeze(['clone', 'clone3', 'execve', 'wait4', 'mincore', 'mlock', 'munlock', 'sched_getparam', 'sched_getscheduler', 'membarrier']),
  rust: Object.freeze(['clone', 'clone3', 'execve', 'wait4', 'memfd_create', 'copy_file_range', 'splice', 'sendfile']),
  node: Object.freeze(['clone', 'clone3', 'execve', 'wait4', 'vfork', 'membarrier', 'inotify_init1', 'inotify_add_watch', 'inotify_rm_watch', 'sendfile', 'copy_file_range', 'utimensat', 'chmod', 'chown', 'fchown', 'symlinkat', 'linkat']),
  python: Object.freeze(['clone', 'clone3', 'execve', 'wait4', 'vfork', 'fork', 'utimensat', 'chmod', 'fchmodat', 'symlinkat', 'linkat', 'getrusage', 'times', 'select', 'pselect6', 'sendfile', 'copy_file_range'])
});

/**
 * Genera un perfil OCI `seccomp.json` de mínimo privilegio adaptado al stack indicado.
 * Rechaza terminantemente `unconfined` (`SECCOMP_UNCONFINED_FORBIDDEN`).
 *
 * @param {string | { stack?: string, mode?: string, extraAllowed?: string[] }} [stack]
 * @param {{ mode?: string, extraAllowed?: string[] }} [options]
 */
function generateSeccompProfile(stack = 'node', options = {}) {
  const opts = (stack && typeof stack === 'object') ? stack : (options || {});
  const rawStack = (stack && typeof stack === 'object') ? (stack.stack || 'node') : stack;
  const cleanStack = String(rawStack || 'node').trim().toLowerCase();
  const mode = String((opts && opts.mode) || '').trim().toLowerCase();

  if (cleanStack === 'unconfined' || mode === 'unconfined') {
    const err = new Error('seccomp=unconfined está estrictamente prohibido en Culkibo (usa un perfil de mínimo privilegio por stack)');
    /** @type {any} */ (err).status = 400;
    /** @type {any} */ (err).code = 'SECCOMP_UNCONFINED_FORBIDDEN';
    throw err;
  }

  if (!SUPPORTED_STACKS.includes(cleanStack)) {
    const err = new Error(`Stack seccomp no soportado: "${cleanStack}" (usa ${SUPPORTED_STACKS.join(', ')})`);
    /** @type {any} */ (err).status = 400;
    /** @type {any} */ (err).code = 'UNSUPPORTED_SECCOMP_STACK';
    throw err;
  }

  const stackExtra = STACK_ADDONS[/** @type {keyof typeof STACK_ADDONS} */ (cleanStack)] || [];
  const rawCallerExtra = opts && opts.extraAllowed;
  /** @type {string[]} */
  const callerExtra = Array.isArray(rawCallerExtra) ? rawCallerExtra : [];

  /** @type {Set<string>} */
  const allowSet = new Set();
  for (const name of [...BASE_SYSCALLS, ...stackExtra, ...callerExtra]) {
    const clean = String(name || '').trim();
    if (!clean || !/^[a-z0-9_]+$/.test(clean)) continue;
    // Invariante matemática: JAMÁS incluir una syscall bloqueada en la lista permitida
    if (BLOCKED_SET.has(clean)) continue;
    allowSet.add(clean);
  }

  const allowedSyscalls = Array.from(allowSet).sort();
  const blockedList = [...BLOCKED_SYSCALLS];

  const profile = {
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: 1,
    architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_AARCH64'],
    syscalls: [
      {
        names: blockedList,
        action: 'SCMP_ACT_ERRNO',
        errnoRet: 1,
        comment: 'Culkibo hardened kernel attack-surface deny list (io_uring/ptrace/mount/bpf/unshare blocked)'
      },
      {
        names: allowedSyscalls,
        action: 'SCMP_ACT_ALLOW',
        comment: `Tailored minimal syscall allowlist for stack "${cleanStack}"`
      }
    ]
  };

  const sha256 = crypto.createHash('sha256').update(JSON.stringify(profile), 'utf8').digest('hex');

  return {
    ok: true,
    stack: cleanStack,
    profile,
    allowedCount: allowedSyscalls.length,
    blockedSyscalls: blockedList,
    dockerSecurityOpt: [
      '--security-opt', 'no-new-privileges:true',
      '--security-opt', `seccomp=/etc/culkibo/seccomp-${cleanStack}.json`
    ],
    sha256
  };
}

/**
 * Valida un perfil o especificación seccomp (string o JSON OCI) rechazando `unconfined`,
 * `defaultAction` permisivos y cualquier syscall bloqueada dentro de `SCMP_ACT_ALLOW`.
 *
 * @param {any} spec
 * @returns {{ safe: boolean, violations: string[] }}
 */
function validateSeccompSpec(spec) {
  /** @type {string[]} */
  const violations = [];

  if (spec == null) {
    violations.push('SECCOMP_SPEC_MISSING: Seccomp profile/spec is missing.');
    return { safe: false, violations };
  }

  if (typeof spec === 'string') {
    const trimmed = spec.trim();
    if (/unconfined/i.test(trimmed)) {
      violations.push('SECCOMP_UNCONFINED_FORBIDDEN: seccomp=unconfined disables kernel syscall filtering.');
      return { safe: false, violations };
    }
    try {
      spec = JSON.parse(trimmed);
    } catch (e) {
      violations.push('SECCOMP_INVALID_JSON: Seccomp spec string is not valid JSON.');
      return { safe: false, violations };
    }
  }

  if (typeof spec !== 'object' || Array.isArray(spec)) {
    violations.push('SECCOMP_INVALID_OBJECT: Seccomp profile must be a JSON object.');
    return { safe: false, violations };
  }

  if (String(spec.mode || '').toLowerCase() === 'unconfined' || String(spec.seccomp || '').toLowerCase() === 'unconfined') {
    violations.push('SECCOMP_UNCONFINED_FORBIDDEN: mode=unconfined is strictly forbidden.');
  }

  if (spec.defaultAction !== 'SCMP_ACT_ERRNO' && spec.defaultAction !== 'SCMP_ACT_KILL' && spec.defaultAction !== 'SCMP_ACT_KILL_PROCESS') {
    violations.push(`DEFAULT_ACTION_NOT_DENY: defaultAction must be SCMP_ACT_ERRNO (got "${String(spec.defaultAction || 'missing')}").`);
  }

  const rules = Array.isArray(spec.syscalls) ? spec.syscalls : [];
  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') continue;
    if (rule.action === 'SCMP_ACT_ALLOW' && Array.isArray(rule.names)) {
      for (const name of rule.names) {
        if (BLOCKED_SET.has(String(name))) {
          violations.push(`BLOCKED_SYSCALL_ALLOWED: Dangerous syscall "${name}" must not be granted SCMP_ACT_ALLOW.`);
        }
      }
    }
  }

  return {
    safe: violations.length === 0,
    violations
  };
}

/**
 * Audita una cadena de versión de `runc` frente a la tríada crítica de noviembre 2025
 * (`CVE-2025-31133`, `CVE-2025-52565`, `CVE-2025-52881` — container escape vía maskedPaths/procfs):
 *  - Vulnerable (`CRITICAL`): `<= 1.2.7`, `1.3.0..1.3.2`, `1.4.0-rc.1..1.4.0-rc.2`
 *  - Seguro (`PASS`): `>= 1.2.8` (1.2.x), `>= 1.3.3` (1.3.x), `>= 1.4.0-rc.3` / `>= 1.4.0`
 *  - No parseable: `UNKNOWN`
 *
 * @param {string | null | undefined} versionStr
 */
function auditRuncVersion(versionStr) {
  const raw = String(versionStr || '').trim();
  const m = raw.match(/\b(?:runc\s+version\s*:?\s*)?v?(\d+)\.(\d+)\.(\d+)(?:-rc\.?(\d+))?/i);
  if (!m) {
    return {
      ok: true,
      status: 'UNKNOWN',
      vulnerable: false,
      parsedVersion: null,
      cves: /** @type {string[]} */ ([]),
      fixedIn: '1.2.8 / 1.3.3 / 1.4.0-rc.3',
      message: 'Could not parse runc semver string.'
    };
  }

  const major = parseInt(m[1], 10);
  const minor = parseInt(m[2], 10);
  const patch = parseInt(m[3], 10);
  const rc = m[4] !== undefined ? parseInt(m[4], 10) : null;
  const parsedVersion = rc !== null ? `${major}.${minor}.${patch}-rc.${rc}` : `${major}.${minor}.${patch}`;

  let vulnerable = false;
  /** @type {string | null} */
  let fixedIn = null;

  if (major < 1) {
    vulnerable = true;
    fixedIn = '1.2.8';
  } else if (major === 1) {
    if (minor < 2) {
      vulnerable = true;
      fixedIn = '1.2.8';
    } else if (minor === 2 && patch <= 7) {
      vulnerable = true;
      fixedIn = '1.2.8';
    } else if (minor === 3 && patch <= 2) {
      vulnerable = true;
      fixedIn = '1.3.3';
    } else if (minor === 4 && patch === 0 && rc !== null && rc <= 2) {
      vulnerable = true;
      fixedIn = '1.4.0-rc.3';
    }
  }

  if (vulnerable) {
    return {
      ok: true,
      status: 'CRITICAL',
      vulnerable: true,
      parsedVersion,
      cves: [...RUNC_2025_CVES],
      fixedIn,
      message: `runc ${parsedVersion} is vulnerable to container escape (${RUNC_2025_CVES.join(', ')}). Upgrade immediately to >= ${fixedIn}.`
    };
  }

  return {
    ok: true,
    status: 'PASS',
    vulnerable: false,
    parsedVersion,
    cves: /** @type {string[]} */ ([]),
    fixedIn: null,
    message: `runc ${parsedVersion} is patched against CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881.`
  };
}

module.exports = {
  SUPPORTED_STACKS,
  BLOCKED_SYSCALLS,
  generateSeccompProfile,
  validateSeccompSpec,
  auditRuncVersion
};
