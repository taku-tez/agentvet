/**
 * CI/CD Security Pattern Detection Rules
 * Detects container escapes, build-time attacks, secrets exfiltration, and CI-specific risks
 * 
 * Inspired by feedback from cinch_ci on Moltbook
 */

const rules = [
  // ============================================
  // Container Escape Patterns
  // ============================================
  {
    id: 'cicd-docker-socket',
    severity: 'critical',
    description: 'Docker socket mounting detected (container escape risk)',
    pattern: /\/var\/run\/docker\.sock|docker\.sock:/gi,
    recommendation: 'Docker socket access allows container escape to host. Remove unless absolutely necessary.',
  },
  {
    id: 'cicd-privileged-container',
    severity: 'critical',
    description: 'Privileged container or dangerous capabilities',
    pattern: /--privileged|--cap-add=ALL|--cap-add=SYS_ADMIN|privileged:\s*true/gi,
    recommendation: 'Privileged containers can escape to host. Use minimal capabilities.',
  },
  {
    id: 'cicd-host-network',
    severity: 'warning',
    description: 'Host network mode detected',
    pattern: /--network=host|--net=host|network_mode:\s*["']?host/gi,
    recommendation: 'Host network mode bypasses container network isolation.',
  },
  {
    id: 'cicd-host-pid',
    severity: 'critical',
    description: 'Host PID namespace detected',
    pattern: /--pid=host|pid:\s*["']?host/gi,
    recommendation: 'Host PID namespace allows process inspection and signaling on host.',
  },
  {
    id: 'cicd-sensitive-mount',
    severity: 'critical',
    description: 'Sensitive directory mounted into container',
    pattern: /-v\s+[^:]*(?:~\/\.aws|~\/\.ssh|~\/\.config\/gh|~\/\.gnupg|~\/\.docker|\/root)[^:]*:/gi,
    recommendation: 'Mounting sensitive directories exposes credentials to container.',
  },
  {
    id: 'cicd-sensitive-mount-compose',
    severity: 'critical',
    description: 'Sensitive directory in docker-compose volume',
    pattern: /volumes:\s*\n(?:[^\n]*\n)*?[^\n]*(?:~\/\.aws|~\/\.ssh|~\/\.config|\/root|\.env)/gi,
    recommendation: 'Mounting sensitive directories exposes credentials to container.',
  },

  // ============================================
  // Secrets Exfiltration Patterns
  // ============================================
  {
    id: 'cicd-env-dump',
    severity: 'critical',
    description: 'Environment variable dump to external URL',
    pattern: /(?:env|printenv|set)\s*\|[^|]*(?:curl|wget|nc|http)/gi,
    recommendation: 'Dumping environment variables can leak secrets. Remove this pattern.',
  },
  {
    id: 'cicd-env-to-file',
    severity: 'warning',
    description: 'Environment variables written to file',
    pattern: /(?:env|printenv)\s*>\s*[^\s]+|export\s+>\s*[^\s]+/gi,
    recommendation: 'Writing env to files may expose secrets. Ensure file is protected.',
  },
  {
    id: 'cicd-secret-file-read',
    severity: 'critical',
    description: 'Reading common secret files',
    pattern: /cat\s+[^\s]*(?:\.env|\.git-credentials|\.netrc|\.npmrc|\.pypirc|credentials|secrets?\.(?:json|ya?ml|txt))/gi,
    recommendation: 'Accessing secret files directly may indicate exfiltration attempt.',
  },
  {
    id: 'cicd-git-credential-helper',
    severity: 'warning',
    description: 'Git credential helper manipulation',
    pattern: /git\s+config\s+[^\n]*credential\.helper|git\s+credential\s+(?:fill|approve)/gi,
    recommendation: 'Review git credential helper usage for potential abuse.',
  },
  {
    id: 'cicd-aws-metadata',
    severity: 'critical',
    description: 'Cloud metadata endpoint access',
    pattern: /169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/g,
    recommendation: 'Accessing cloud metadata endpoints can steal instance credentials.',
  },
  {
    id: 'cicd-dns-exfil',
    severity: 'warning',
    description: 'Potential DNS exfiltration pattern',
    pattern: /\$\([^)]+\)\..*\.(?:com|net|io|org)|`[^`]+`\..*\.(?:com|net|io|org)|nslookup\s+\$|dig\s+\$/gi,
    recommendation: 'Data embedded in DNS queries can bypass network filters.',
  },

  // ============================================
  // Build-time Attack Patterns
  // ============================================
  {
    id: 'cicd-postinstall-suspicious',
    severity: 'critical',
    description: 'Suspicious postinstall script in package.json',
    pattern: /"(?:postinstall|preinstall|install)"\s*:\s*"[^"]*(?:curl|wget|nc|bash|sh|eval|node\s+-e)/gi,
    recommendation: 'Package install scripts can execute arbitrary code. Review carefully.',
  },
  {
    id: 'cicd-postinstall-network',
    severity: 'warning',
    description: 'Network call in npm lifecycle script',
    pattern: /"(?:postinstall|preinstall|prepare|prepublish)"\s*:\s*"[^"]*(?:https?:|fetch|axios|request)/gi,
    recommendation: 'Network calls during install may indicate supply chain attack.',
  },
  {
    id: 'cicd-makefile-hidden',
    severity: 'warning',
    description: 'Makefile target with suspicious commands',
    pattern: /^(?:install|build|all|default):\s*\n(?:[^\n]*\n)*?[^\n]*(?:curl|wget|nc\s|bash\s+-c)/gim,
    recommendation: 'Review Makefile targets for hidden malicious commands.',
  },
  {
    id: 'cicd-setup-py-backdoor',
    severity: 'warning',
    description: 'Suspicious code in setup.py',
    pattern: /setup\.py[^]*(?:subprocess|os\.system|urllib|requests\.(?:get|post)|socket)/gi,
    recommendation: 'setup.py can execute code during pip install. Review carefully.',
  },

  // ============================================
  // GitHub Actions Specific
  // ============================================
  {
    id: 'cicd-gha-expression-injection',
    severity: 'critical',
    description: 'GitHub Actions expression injection risk',
    pattern: /\$\{\{\s*github\.event\.(?:comment|issue|pull_request|discussion)\.(?:body|title)|github\.event\.(?:head_commit|commits\[\d+\])\.message\s*\}\}/gi,
    recommendation: 'User-controlled data in run blocks enables code injection. Use environment variables.',
  },
  {
    id: 'cicd-gha-pull-request-target',
    severity: 'warning',
    description: 'pull_request_target with checkout of PR code',
    pattern: /pull_request_target[^]*?(?:ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:ref|sha)|actions\/checkout[^]*?ref:)/gi,
    recommendation: 'pull_request_target with PR checkout can expose secrets to malicious PRs.',
  },
  {
    id: 'cicd-gha-artifact-poisoning',
    severity: 'warning',
    description: 'Artifact download without verification',
    pattern: /download-artifact[^]*?(?:run:|script:)[^]*?(?:bash|sh|node|python|chmod\s+\+x)/gi,
    recommendation: 'Artifacts can be poisoned. Verify integrity before execution.',
  },
  {
    id: 'cicd-gha-secrets-in-logs',
    severity: 'warning',
    description: 'Secrets potentially exposed in logs',
    pattern: /echo\s+[^\n]*\$\{\{\s*secrets\./gi,
    recommendation: 'Echoing secrets may expose them in workflow logs.',
  },

  // ============================================
  // CI Environment Detection (Meta-pattern)
  // ============================================
  {
    id: 'cicd-env-detection',
    severity: 'warning',
    description: 'CI environment detection (behavior may differ)',
    pattern: /(?:process\.env\.|os\.environ\[|getenv\(|ENV\[)\s*['"]?(?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS|TRAVIS|CIRCLECI|BITBUCKET_PIPELINE|BUILDKITE)['"]?\]?/gi,
    recommendation: 'Code that detects CI may behave differently in CI vs local. Review for hidden behavior.',
  },
  {
    id: 'cicd-conditional-behavior',
    severity: 'warning',
    description: 'Conditional behavior based on CI environment',
    pattern: /if\s*\(?.*(?:CI|GITHUB_ACTIONS|JENKINS|TRAVIS).*\)?.*(?:\{|then|:)/gi,
    recommendation: 'Conditional logic based on CI environment may hide malicious behavior from local testing.',
  },

  // ============================================
  // Kubernetes/Cloud Patterns
  // ============================================
  {
    id: 'cicd-k8s-service-account',
    severity: 'warning',
    description: 'Kubernetes service account token access',
    pattern: /\/var\/run\/secrets\/kubernetes\.io|\/run\/secrets\/kubernetes\.io/g,
    recommendation: 'Accessing K8s service account tokens enables cluster API access.',
  },
  {
    id: 'cicd-k8s-configmap-secrets',
    severity: 'warning',
    description: 'Kubernetes secrets mounted as files',
    pattern: /secretKeyRef|configMapKeyRef|secretName:\s*["']?[^\s]+/gi,
    recommendation: 'Review mounted secrets for necessity and access control.',
  },
  {
    id: 'cicd-helm-insecure',
    severity: 'warning',
    description: 'Insecure Helm chart patterns',
    pattern: /--set\s+[^\s]*(?:password|secret|key|token)=[^\s]+/gi,
    recommendation: 'Passing secrets via --set exposes them in shell history and process list.',
  },

  // ============================================
  // Terraform/IaC Patterns
  // ============================================
  {
    id: 'cicd-terraform-sensitive',
    severity: 'warning',
    description: 'Hardcoded sensitive value in Terraform',
    pattern: /(?:password|secret|api_key|access_key)\s*=\s*"[^"$]+"/gi,
    recommendation: 'Use Terraform variables or Vault for sensitive values.',
  },
  {
    id: 'cicd-terraform-remote-exec',
    severity: 'warning',
    description: 'Terraform remote-exec provisioner',
    pattern: /provisioner\s*["']remote-exec["']/gi,
    recommendation: 'remote-exec can run arbitrary code. Prefer configuration management tools.',
  },

  // ============================================
  // Registry/Artifact Patterns
  // ============================================
  {
    id: 'cicd-npm-publish-public',
    severity: 'warning',
    description: 'npm publish without access restriction',
    pattern: /npm\s+publish(?!\s+--access\s+restricted)/gi,
    recommendation: 'Consider using --access restricted for private packages.',
  },
  {
    id: 'cicd-docker-push-latest',
    severity: 'info',
    description: 'Docker push with latest tag',
    pattern: /docker\s+push\s+[^\s]+:latest/gi,
    recommendation: 'Using :latest tag makes rollbacks difficult. Use versioned tags.',
  },
];

module.exports = { rules };
