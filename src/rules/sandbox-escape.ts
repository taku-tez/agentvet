import type { Rule } from "../types.js";

/**
 * Sandbox Escape Detection Rules
 * Detects attempts by AI agents to escape sandboxed/containerized environments.
 *
 * AI agents are increasingly run in sandboxed environments (Docker containers,
 * VMs, browser sandboxes, E2B sandboxes). Malicious prompts or compromised
 * tools may attempt to break out of these boundaries.
 *
 * Attack surfaces:
 * - Docker container escape (mount host filesystem, privileged mode abuse)
 * - Kubernetes pod escape (node access, service account abuse)
 * - Browser sandbox escape (DevTools protocol, extension exploitation)
 * - chroot/namespace escape (proc/sys abuse)
 * - E2B/Modal/Fly sandbox escape (metadata service, host network)
 *
 * References:
 * - CWE-284: Improper Access Control
 * - MITRE ATT&CK T1611: Escape to Host
 * - "Container Escape Techniques" (Trail of Bits, 2024)
 * - "AI Sandbox Escape" (OWASP LLM Top 10 2025)
 */

export const rules: Rule[] = [
  // ============================================
  // Docker Container Escape
  // ============================================
  {
    id: 'sandbox-docker-socket-mount',
    severity: 'critical',
    description: 'Docker socket access detected (container escape via Docker-in-Docker)',
    pattern: /(?:\/var\/run\/docker\.sock|docker\.sock|DOCKER_HOST\s*=\s*(?:unix|tcp):\/\/|new\s+Docker\s*\(\s*\{[^}]*socketPath)/gi,
    recommendation: 'CRITICAL: Access to Docker socket allows full host control. An agent with Docker socket access can escape the container by creating a privileged container with host mounts.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-docker-privileged',
    severity: 'critical',
    description: 'Privileged container or dangerous capabilities requested',
    pattern: /(?:--privileged|--cap-add\s*=?\s*(?:SYS_ADMIN|SYS_PTRACE|SYS_RAWIO|DAC_READ_SEARCH|ALL)|--security-opt\s*=?\s*(?:apparmor=unconfined|seccomp=unconfined|label=disable))/gi,
    recommendation: 'CRITICAL: Privileged containers or dangerous capabilities enable container escape. SYS_ADMIN allows mount namespace manipulation; SYS_PTRACE enables process injection.',
    category: 'sandbox-escape',
    cwe: 'CWE-250',
  },
  {
    id: 'sandbox-docker-host-mount',
    severity: 'critical',
    description: 'Host filesystem mounted into container (escape via host path access)',
    pattern: /(?:-v\s+\/(?:etc|root|home|var|proc|sys|dev)(?:\/[^\s:]*)?:|--mount\s+[^\n]*source=\/(?:etc|root|home|var|proc|sys|dev)|volumes:\s*\n\s*-\s+\/(?:etc|root|home|var|proc|sys|dev))/gi,
    recommendation: 'CRITICAL: Mounting sensitive host directories into containers allows reading host credentials, SSH keys, and system configuration. Restrict volume mounts.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-docker-host-network',
    severity: 'high',
    description: 'Container using host network namespace (bypasses network isolation)',
    pattern: /(?:--net(?:work)?=host|network_mode:\s*["']?host|hostNetwork:\s*true)/gi,
    recommendation: 'Host network mode bypasses container network isolation. The container can access all host network interfaces, including localhost services and metadata endpoints.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-docker-host-pid',
    severity: 'critical',
    description: 'Container using host PID namespace (can see/signal host processes)',
    pattern: /(?:--pid=host|pid_mode:\s*["']?host|hostPID:\s*true)/gi,
    recommendation: 'CRITICAL: Host PID namespace allows the container to see and interact with all host processes, enabling process injection and credential theft.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },

  // ============================================
  // Kubernetes Pod Escape
  // ============================================
  {
    id: 'sandbox-k8s-service-account-token',
    severity: 'high',
    description: 'Kubernetes service account token access (potential pod escape)',
    pattern: /(?:\/var\/run\/secrets\/kubernetes\.io\/serviceaccount|KUBERNETES_SERVICE_HOST|kube-apiserver|kubectl\s+(?:exec|run|create|apply)|ServiceAccount)/gi,
    recommendation: 'Accessing Kubernetes service account tokens from within a pod can enable cluster-level privilege escalation. Ensure automountServiceAccountToken is false for agent pods.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-k8s-node-shell',
    severity: 'critical',
    description: 'Kubernetes node shell access attempt (escape from pod to node)',
    pattern: /(?:nsenter\s+(?:-t\s*1|-m|-u|-i|-n|-p)|kubectl\s+(?:debug|exec)\s+node\/|chroot\s+\/host)/gi,
    recommendation: 'CRITICAL: nsenter or node debug commands allow escaping from a pod to the underlying Kubernetes node. This is a direct container escape technique.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },

  // ============================================
  // Linux Namespace / chroot Escape
  // ============================================
  {
    id: 'sandbox-proc-escape',
    severity: 'critical',
    description: 'Proc filesystem abuse for container/sandbox escape',
    pattern: /(?:\/proc\/(?:1\/root|self\/(?:root|ns|cgroup)|sys\/kernel\/core_pattern)|mount\s+-t\s+proc|cat\s+\/proc\/1\/(?:environ|maps|cmdline|root)|ls\s+(?:-la?\s+)?\/proc\/1\/root)/gi,
    recommendation: 'CRITICAL: Accessing /proc/1/root or /proc/self/ns can enable container escape. The agent may be trying to access the host filesystem through proc.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-cgroup-escape',
    severity: 'critical',
    description: 'Cgroup-based container escape attempt (CVE-2022-0492 pattern)',
    pattern: /(?:mount\s+-t\s+cgroup|mkdir\s+\/tmp\/cgrp[\s;]|echo\s+1\s*>\s*\/tmp\/cgrp\/[^\s]*notify_on_release|\/sys\/fs\/cgroup\/[^\s]*release_agent)/gi,
    recommendation: 'CRITICAL: Cgroup manipulation is a well-known container escape technique (CVE-2022-0492). The release_agent can execute arbitrary code on the host.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-sysfs-abuse',
    severity: 'high',
    description: 'Sysfs manipulation for privilege escalation or escape',
    pattern: /(?:mount\s+-t\s+sysfs|echo\s+[^\n]*>\s*\/sys\/(?:class|bus|devices|kernel)|cat\s+\/sys\/kernel\/(?:security|keys)|modprobe|insmod\s+)/gi,
    recommendation: 'Sysfs manipulation can enable privilege escalation within containers. Loading kernel modules (modprobe/insmod) from within a container is a strong escape indicator.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },

  // ============================================
  // Cloud Metadata Service Access (VM/Sandbox Escape)
  // ============================================
  {
    id: 'sandbox-cloud-metadata',
    severity: 'high',
    description: 'Cloud metadata service access from sandbox (credential theft / escape)',
    pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)(?:\/[^\s'"]*)?/gi,
    recommendation: 'Cloud metadata endpoints expose IAM credentials, instance identity, and network configuration. An agent accessing metadata from a sandbox can steal cloud credentials for lateral movement.',
    category: 'sandbox-escape',
    cwe: 'CWE-918',
  },
  {
    id: 'sandbox-imds-v1-exploit',
    severity: 'critical',
    description: 'IMDSv1 credential theft (no token required)',
    pattern: /(?:curl|wget|fetch|http\.get|requests\.get)[^\n]*169\.254\.169\.254\/latest\/(?:meta-data\/iam\/security-credentials|dynamic\/instance-identity|user-data)/gi,
    recommendation: 'CRITICAL: Direct access to IMDSv1 credential endpoint. IMDSv1 does not require tokens and is trivially exploitable from within containers. Enforce IMDSv2 with hop limit of 1.',
    category: 'sandbox-escape',
    cwe: 'CWE-918',
  },

  // ============================================
  // Browser Sandbox Escape
  // ============================================
  {
    id: 'sandbox-chrome-devtools-protocol',
    severity: 'high',
    description: 'Chrome DevTools Protocol remote debugging (browser sandbox bypass)',
    pattern: /(?:--remote-debugging-(?:port|address|pipe)|chrome-devtools:\/\/|ws:\/\/[^\s]*\/devtools\/|CDP\.connect|chrome\.debugger\.attach|page\.createCDPSession)/gi,
    recommendation: 'Chrome DevTools Protocol gives full browser control bypassing sandbox restrictions. An agent with CDP access can read all browser data, cookies, and credentials across all tabs.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
  {
    id: 'sandbox-browser-extension-install',
    severity: 'high',
    description: 'Browser extension installation from agent (persistent browser compromise)',
    pattern: /(?:--load-extension=|chrome\.management\.install|browser\.management\.install|webExtension\.load|installExtension|--install-extension)/gi,
    recommendation: 'Installing browser extensions from an agent context enables persistent browser compromise. Extensions can access all browsing data, modify page content, and exfiltrate credentials.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },

  // ============================================
  // E2B / Modal / Fly.io Sandbox Escape
  // ============================================
  {
    id: 'sandbox-e2b-breakout',
    severity: 'high',
    description: 'E2B sandbox escape attempt (filesystem or network boundary probing)',
    pattern: /(?:E2B_SANDBOX|e2b\.sandbox|\.sandbox\.e2b|e2b-data-dir)[\s\S]{0,200}(?:\/proc|\/sys|mount|nsenter|chroot|escape)/gi,
    recommendation: 'E2B sandbox escape attempt detected. The agent is probing sandbox boundaries. Review E2B sandbox configuration and network policies.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },

  // ============================================
  // General Sandbox Probing
  // ============================================
  {
    id: 'sandbox-environment-fingerprint',
    severity: 'medium',
    description: 'Sandbox environment detection / fingerprinting',
    pattern: /(?:cat\s+\/proc\/1\/cgroup|systemd-detect-virt|hostnamectl|dmidecode|lscpu\s*\|\s*grep\s+(?:Hypervisor|Virtual)|virt-what|facter\s+(?:virtual|is_virtual)|\/proc\/self\/status\s*.*\s*NSpid)/gi,
    recommendation: 'The agent is fingerprinting the execution environment to detect sandbox/container/VM. This is a common precursor to sandbox escape attempts.',
    category: 'sandbox-escape',
    cwe: 'CWE-200',
  },
  {
    id: 'sandbox-capability-probe',
    severity: 'medium',
    description: 'Linux capability probing (assessing escape feasibility)',
    pattern: /(?:capsh\s+--print|getpcaps\s+|cat\s+\/proc\/self\/status\s*\|\s*grep\s+Cap|grep\s+Cap\s+\/proc\/self\/status|\/proc\/\d+\/status\s*\|\s*grep\s+Cap)/gi,
    recommendation: 'The agent is checking available Linux capabilities. This is typically done to assess which container escape techniques are viable.',
    category: 'sandbox-escape',
    cwe: 'CWE-200',
  },
  {
    id: 'sandbox-seccomp-probe',
    severity: 'medium',
    description: 'Seccomp profile probing (checking syscall restrictions)',
    pattern: /(?:cat\s+\/proc\/self\/status\s*\|\s*grep\s+Seccomp|grep\s+Seccomp\s+\/proc\/self|seccomp-bpf|prctl\s*\(\s*PR_GET_SECCOMP|strace\s+-e\s+trace=)/gi,
    recommendation: 'The agent is probing seccomp restrictions to determine which system calls are available. This indicates sandbox escape reconnaissance.',
    category: 'sandbox-escape',
    cwe: 'CWE-200',
  },

  // ============================================
  // Firecracker / gVisor / Kata Escape
  // ============================================
  {
    id: 'sandbox-microvm-escape',
    severity: 'high',
    description: 'MicroVM / gVisor / Kata container escape attempt',
    pattern: /(?:\/dev\/vsock|VSOCK|virtio-vsock|\/run\/kata-containers|runsc\s+debug|\/proc\/sys\/net\/core\/bpf_jit_enable)/gi,
    recommendation: 'VSOCK or Kata/gVisor-specific escape vectors detected. While microVMs provide strong isolation, VSOCK can potentially be abused for host communication.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },

  // ============================================
  // Reverse Shell from Sandbox
  // ============================================
  {
    id: 'sandbox-reverse-shell',
    severity: 'critical',
    description: 'Reverse shell attempt from sandboxed environment',
    pattern: /(?:bash\s+-i\s+>&\s*\/dev\/tcp|nc\s+-e\s+\/bin\/(?:sh|bash)|python[23]?\s+-c\s+['"]import\s+(?:socket|os|subprocess)[\s\S]{0,200}connect|socat\s+(?:exec|TCP)[\s\S]{0,100}(?:EXEC|exec)|mkfifo\s+\/tmp\/[^\s;]+;\s*(?:nc|cat))/gi,
    recommendation: 'CRITICAL: Reverse shell from sandbox detected. The agent is attempting to establish an outbound interactive shell, likely to communicate with an attacker-controlled server.',
    category: 'sandbox-escape',
    cwe: 'CWE-78',
  },

  // ============================================
  // iptables / Network Policy Bypass
  // ============================================
  {
    id: 'sandbox-network-policy-bypass',
    severity: 'high',
    description: 'Network policy or firewall manipulation from within sandbox',
    pattern: /(?:iptables\s+-[AIDP]|ip6tables\s+-[AIDP]|nft\s+(?:add|delete|flush)|ufw\s+(?:disable|allow|delete)|firewall-cmd\s+--(?:add|remove|zone))/gi,
    recommendation: 'Firewall/iptables manipulation from within a sandbox indicates an attempt to bypass network isolation policies. Agents should not have CAP_NET_ADMIN.',
    category: 'sandbox-escape',
    cwe: 'CWE-284',
  },
];

// CommonJS compatibility
module.exports = { rules };
