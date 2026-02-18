import type { Rule } from "../types.js";

/**
 * Container Security Rules
 * Detects container escape attempts, privileged containers, dangerous mounts,
 * and misconfigurations that compromise container isolation.
 */

export const rules: Rule[] = [
  // ============================================
  // Container Escape & Privilege Escalation
  // ============================================
  {
    id: 'container-privileged-mode',
    severity: 'critical',
    description: 'Container running in privileged mode (full host access)',
    pattern: /(?:--privileged|privileged:\s*true)/gi,
    recommendation: 'Never run containers in privileged mode. Use specific capabilities with --cap-add instead.',
    category: 'container',
    cwe: 'CWE-250',
  },
  {
    id: 'container-host-pid',
    severity: 'critical',
    description: 'Container shares host PID namespace',
    pattern: /(?:--pid\s*=\s*host|pid:\s*["']?host["']?)/gi,
    recommendation: 'Sharing host PID namespace allows container to see and signal host processes. Remove unless required.',
    category: 'container',
    cwe: 'CWE-668',
  },
  {
    id: 'container-host-network',
    severity: 'high',
    description: 'Container shares host network namespace',
    pattern: /(?:--net(?:work)?\s*=\s*host|network_mode:\s*["']?host["']?)/gi,
    recommendation: 'Host network mode bypasses network isolation. Use bridge networking with port mapping instead.',
    category: 'container',
    cwe: 'CWE-668',
  },
  {
    id: 'container-host-ipc',
    severity: 'high',
    description: 'Container shares host IPC namespace',
    pattern: /(?:--ipc\s*=\s*host|ipc:\s*["']?host["']?)/gi,
    recommendation: 'Sharing host IPC namespace allows shared memory access. Remove unless required.',
    category: 'container',
    cwe: 'CWE-668',
  },
  {
    id: 'container-docker-socket-mount',
    severity: 'critical',
    description: 'Docker socket mounted into container (container escape vector)',
    pattern: /(?:-v|--volume|--mount)\s+[^\n]*\/var\/run\/docker\.sock/gi,
    recommendation: 'Mounting Docker socket gives full Docker control from within container. This is a container escape vector.',
    category: 'container',
    cwe: 'CWE-269',
  },
  {
    id: 'container-docker-socket-compose',
    severity: 'critical',
    description: 'Docker socket mounted in docker-compose (container escape vector)',
    pattern: /\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/gi,
    recommendation: 'Mounting Docker socket gives full Docker control from within container. This is a container escape vector.',
    category: 'container',
    cwe: 'CWE-269',
  },
  {
    id: 'container-cap-sys-admin',
    severity: 'critical',
    description: 'Container granted SYS_ADMIN capability',
    pattern: /(?:--cap-add\s*=?\s*SYS_ADMIN|cap_add:[\s\S]*?SYS_ADMIN)/gi,
    recommendation: 'SYS_ADMIN capability is extremely broad and enables container escape. Use more specific capabilities.',
    category: 'container',
    cwe: 'CWE-250',
  },
  {
    id: 'container-cap-sys-ptrace',
    severity: 'high',
    description: 'Container granted SYS_PTRACE capability',
    pattern: /(?:--cap-add\s*=?\s*SYS_PTRACE|cap_add:[\s\S]*?SYS_PTRACE)/gi,
    recommendation: 'SYS_PTRACE allows process tracing and can be used for container escape. Remove unless debugging.',
    category: 'container',
    cwe: 'CWE-250',
  },

  // ============================================
  // Dangerous Volume Mounts
  // ============================================
  {
    id: 'container-mount-root',
    severity: 'critical',
    description: 'Host root filesystem mounted into container',
    pattern: /(?:-v|--volume|--mount)\s+[^\n]*(?:\/:\/)(?!var)/gi,
    recommendation: 'Mounting host root filesystem into container gives full host access. Never mount / into containers.',
    category: 'container',
    cwe: 'CWE-269',
  },
  {
    id: 'container-mount-etc',
    severity: 'high',
    description: 'Host /etc directory mounted into container',
    pattern: /(?:-v|--volume|--mount)\s+[^\n]*\/etc(?:\/|:)/gi,
    recommendation: 'Mounting /etc exposes host configuration including passwd, shadow, and sudoers.',
    category: 'container',
    cwe: 'CWE-538',
  },
  {
    id: 'container-mount-proc-sys',
    severity: 'critical',
    description: 'Host /proc or /sys mounted writable in container',
    pattern: /(?:-v|--volume|--mount)\s+[^\n]*\/(?:proc|sys)(?:\/|:)[^\n]*(?!:ro\b)/gi,
    recommendation: 'Writable /proc or /sys mounts can be used for container escape. Mount read-only if needed.',
    category: 'container',
    cwe: 'CWE-269',
  },

  // ============================================
  // Insecure Container Configuration
  // ============================================
  {
    id: 'container-no-seccomp',
    severity: 'high',
    description: 'Seccomp profile disabled for container',
    pattern: /(?:--security-opt\s+seccomp[=:]unconfined|security_opt:[\s\S]*?seccomp[=:]unconfined)/gi,
    recommendation: 'Disabling seccomp removes syscall filtering. Use default or custom seccomp profiles.',
    category: 'container',
    cwe: 'CWE-693',
  },
  {
    id: 'container-no-apparmor',
    severity: 'high',
    description: 'AppArmor profile disabled for container',
    pattern: /(?:--security-opt\s+apparmor[=:]unconfined|security_opt:[\s\S]*?apparmor[=:]unconfined)/gi,
    recommendation: 'Disabling AppArmor removes mandatory access controls. Use default or custom AppArmor profiles.',
    category: 'container',
    cwe: 'CWE-693',
  },
  {
    id: 'container-run-as-root',
    severity: 'warning',
    description: 'Container explicitly runs as root user',
    pattern: /(?:USER\s+root|user:\s*["']?root["']?|--user\s+(?:0|root))/gi,
    recommendation: 'Run containers as non-root user. Use USER directive in Dockerfile to set a non-root user.',
    category: 'container',
    cwe: 'CWE-250',
  },
  {
    id: 'container-no-new-privileges-missing',
    severity: 'warning',
    description: 'Container may gain new privileges via setuid/setgid',
    pattern: /(?:--security-opt\s+no-new-privileges\s*=\s*false)/gi,
    recommendation: 'Set --security-opt=no-new-privileges:true to prevent privilege escalation via setuid binaries.',
    category: 'container',
    cwe: 'CWE-250',
  },

  // ============================================
  // Kubernetes-Specific
  // ============================================
  {
    id: 'k8s-host-path-root',
    severity: 'critical',
    description: 'Kubernetes hostPath volume mounting root or sensitive path',
    pattern: /hostPath:[\s\S]*?path:\s*["']?\/(?:etc|var|proc|sys|root)?["']?\s/gi,
    recommendation: 'Avoid hostPath volumes mounting sensitive host directories. Use PersistentVolumeClaims instead.',
    category: 'container',
    cwe: 'CWE-269',
  },
  {
    id: 'k8s-service-account-token',
    severity: 'warning',
    description: 'Kubernetes service account token auto-mounted',
    pattern: /automountServiceAccountToken:\s*true/gi,
    recommendation: 'Disable service account token auto-mounting unless required. Set automountServiceAccountToken: false.',
    category: 'container',
    cwe: 'CWE-269',
  },
];

// CommonJS compatibility
module.exports = { rules };
