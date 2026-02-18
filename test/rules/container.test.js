import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rules } from '../../dist/rules/container.js';

describe('Container Security Rules', () => {
  it('should have 18 container rules', () => {
    assert.equal(rules.length, 17);
  });

  describe('container-privileged-mode', () => {
    const rule = rules.find(r => r.id === 'container-privileged-mode');

    it('detects --privileged flag', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --privileged nginx', rule.pattern);
    });

    it('detects privileged: true in compose', () => {
      rule.pattern.lastIndex = 0;
      assert.match('privileged: true', rule.pattern);
    });

    it('does not match unprivileged', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch('docker run nginx', rule.pattern);
    });
  });

  describe('container-host-pid', () => {
    const rule = rules.find(r => r.id === 'container-host-pid');

    it('detects --pid=host', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --pid=host nginx', rule.pattern);
    });

    it('detects pid: host in compose', () => {
      rule.pattern.lastIndex = 0;
      assert.match('pid: host', rule.pattern);
    });
  });

  describe('container-host-network', () => {
    const rule = rules.find(r => r.id === 'container-host-network');

    it('detects --network=host', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --network=host nginx', rule.pattern);
    });

    it('detects --net=host', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --net=host nginx', rule.pattern);
    });

    it('detects network_mode: host', () => {
      rule.pattern.lastIndex = 0;
      assert.match('network_mode: host', rule.pattern);
    });
  });

  describe('container-docker-socket-mount', () => {
    const rule = rules.find(r => r.id === 'container-docker-socket-mount');

    it('detects -v /var/run/docker.sock', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run -v /var/run/docker.sock:/var/run/docker.sock nginx', rule.pattern);
    });
  });

  describe('container-docker-socket-compose', () => {
    const rule = rules.find(r => r.id === 'container-docker-socket-compose');

    it('detects docker socket in compose volumes', () => {
      rule.pattern.lastIndex = 0;
      assert.match('/var/run/docker.sock:/var/run/docker.sock', rule.pattern);
    });
  });

  describe('container-cap-sys-admin', () => {
    const rule = rules.find(r => r.id === 'container-cap-sys-admin');

    it('detects --cap-add=SYS_ADMIN', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --cap-add=SYS_ADMIN nginx', rule.pattern);
    });

    it('detects --cap-add SYS_ADMIN', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --cap-add SYS_ADMIN nginx', rule.pattern);
    });
  });

  describe('container-cap-sys-ptrace', () => {
    const rule = rules.find(r => r.id === 'container-cap-sys-ptrace');

    it('detects --cap-add=SYS_PTRACE', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --cap-add=SYS_PTRACE nginx', rule.pattern);
    });
  });

  describe('container-mount-etc', () => {
    const rule = rules.find(r => r.id === 'container-mount-etc');

    it('detects -v /etc:/etc', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run -v /etc:/etc nginx', rule.pattern);
    });
  });

  describe('container-no-seccomp', () => {
    const rule = rules.find(r => r.id === 'container-no-seccomp');

    it('detects seccomp=unconfined', () => {
      rule.pattern.lastIndex = 0;
      assert.match('--security-opt seccomp=unconfined', rule.pattern);
    });
  });

  describe('container-no-apparmor', () => {
    const rule = rules.find(r => r.id === 'container-no-apparmor');

    it('detects apparmor=unconfined', () => {
      rule.pattern.lastIndex = 0;
      assert.match('--security-opt apparmor=unconfined', rule.pattern);
    });
  });

  describe('container-run-as-root', () => {
    const rule = rules.find(r => r.id === 'container-run-as-root');

    it('detects USER root in Dockerfile', () => {
      rule.pattern.lastIndex = 0;
      assert.match('USER root', rule.pattern);
    });

    it('detects --user root', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --user root nginx', rule.pattern);
    });

    it('detects --user 0', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --user 0 nginx', rule.pattern);
    });
  });

  describe('container-host-ipc', () => {
    const rule = rules.find(r => r.id === 'container-host-ipc');

    it('detects --ipc=host', () => {
      rule.pattern.lastIndex = 0;
      assert.match('docker run --ipc=host nginx', rule.pattern);
    });
  });

  describe('k8s-service-account-token', () => {
    const rule = rules.find(r => r.id === 'k8s-service-account-token');

    it('detects automountServiceAccountToken: true', () => {
      rule.pattern.lastIndex = 0;
      assert.match('automountServiceAccountToken: true', rule.pattern);
    });
  });
});
