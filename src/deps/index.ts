// @ts-nocheck
/**
 * Dependency Vulnerability Scanner
 * Integrates npm audit, pip-audit, and additional security checks
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Known malicious packages (supply chain attacks)
const MALICIOUS_PACKAGES = new Set([
  // npm
  'event-stream', 'flatmap-stream', 'ua-parser-js', 'coa', 'rc',
  // Typosquatting examples
  'crossenv', 'cross-env.js', 'mongose', 'mariadb', 'mysqljs',
  'node-fabric', 'fabric-js', 'gruntcli', 'http-proxy.js',
  'proxy.js', 'shadowsock', 'smb', 'nodesass', 'nodefabric',
  // Recent attacks
  'colors', 'faker', // Intentionally corrupted by author
]);

// Suspicious package patterns
const SUSPICIOUS_PATTERNS = [
  /^@[a-z]+-[a-z]+\//, // Typosquatting scoped packages
  /-js$/, // foo-js instead of foo
  /^node-/, // node-foo instead of foo
  /\d{10,}/, // Random numbers (auto-generated names)
];

class DependencyScanner {
  constructor(options = {}) {
    this.options = {
      timeout: 120000, // 2 minutes
      deep: false, // Deep analysis mode
      checkMalicious: true,
      checkOutdated: false,
      checkLicenses: false,
      ...options,
    };
  }

  /**
   * Check if a command is available
   */
  commandExists(cmd) {
    try {
      execSync(`which ${cmd}`, { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Scan a directory for dependency vulnerabilities
   */
  async scan(targetPath) {
    const results = {
      npm: null,
      pip: null,
      malicious: [],
      suspicious: [],
      outdated: [],
      findings: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
      },
    };

    const resolvedPath = path.resolve(targetPath);

    // Check for package.json (npm)
    const packageJsonPath = path.join(resolvedPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      results.npm = await this.runNpmAudit(resolvedPath);
      this.processNpmResults(results);
      
      // Additional checks
      if (this.options.checkMalicious || this.options.deep) {
        await this.checkMaliciousPackages(resolvedPath, results);
      }
      
      if (this.options.checkOutdated || this.options.deep) {
        await this.checkOutdatedPackages(resolvedPath, results);
      }
      
      if (this.options.deep) {
        await this.analyzePackageScripts(resolvedPath, results);
      }
    }

    // Check for requirements.txt or pyproject.toml (pip)
    const requirementsPath = path.join(resolvedPath, 'requirements.txt');
    const pyprojectPath = path.join(resolvedPath, 'pyproject.toml');
    if (fs.existsSync(requirementsPath) || fs.existsSync(pyprojectPath)) {
      results.pip = await this.runPipAudit(resolvedPath);
      this.processPipResults(results);
      
      if (this.options.deep) {
        await this.analyzePythonDeps(resolvedPath, results);
      }
    }

    return results;
  }

  /**
   * Run npm audit
   */
  async runNpmAudit(targetPath) {
    if (!this.commandExists('npm')) {
      return { error: 'npm not found', available: false };
    }

    const nodeModulesPath = path.join(targetPath, 'node_modules');
    const packageLockPath = path.join(targetPath, 'package-lock.json');
    
    try {
      let result;
      
      if (fs.existsSync(packageLockPath)) {
        result = execSync('npm audit --json --package-lock-only 2>/dev/null', {
          cwd: targetPath,
          timeout: this.options.timeout,
          maxBuffer: 10 * 1024 * 1024,
        });
      } else if (fs.existsSync(nodeModulesPath)) {
        result = execSync('npm audit --json 2>/dev/null', {
          cwd: targetPath,
          timeout: this.options.timeout,
          maxBuffer: 10 * 1024 * 1024,
        });
      } else {
        return { 
          available: true, 
          skipped: true, 
          reason: 'No package-lock.json or node_modules found' 
        };
      }

      return {
        available: true,
        data: JSON.parse(result.toString()),
      };
    } catch (error) {
      if (error.stdout) {
        try {
          return {
            available: true,
            data: JSON.parse(error.stdout.toString()),
          };
        } catch {
          return { available: true, error: 'Failed to parse npm audit output' };
        }
      }
      return { available: true, error: error.message };
    }
  }

  /**
   * Check for known malicious packages
   */
  async checkMaliciousPackages(targetPath, results) {
    const packageJsonPath = path.join(targetPath, 'package.json');
    const packageLockPath = path.join(targetPath, 'package-lock.json');

    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
        ...packageJson.optionalDependencies,
      };

      // Check direct dependencies
      for (const [name, version] of Object.entries(allDeps)) {
        // Check against known malicious packages
        if (MALICIOUS_PACKAGES.has(name)) {
          results.malicious.push({
            package: name,
            version,
            reason: 'Known malicious or compromised package',
          });
          
          results.findings.push({
            source: 'supply-chain',
            package: name,
            severity: 'critical',
            title: `Potentially malicious package: ${name}`,
            description: 'This package has been flagged as malicious or compromised',
            recommendation: 'Remove immediately and audit your system',
          });
          results.summary.critical++;
          results.summary.total++;
        }

        // Check for suspicious patterns
        for (const pattern of SUSPICIOUS_PATTERNS) {
          if (pattern.test(name)) {
            results.suspicious.push({
              package: name,
              version,
              reason: `Matches suspicious pattern: ${pattern}`,
            });
          }
        }
      }

      // Deep scan: check transitive dependencies in lock file
      if (this.options.deep && fs.existsSync(packageLockPath)) {
        const lockFile = JSON.parse(fs.readFileSync(packageLockPath, 'utf-8'));
        const packages = lockFile.packages || lockFile.dependencies || {};
        
        for (const [pkgPath, info] of Object.entries(packages)) {
          const name = pkgPath.replace(/^node_modules\//, '').split('/').pop();
          if (name && MALICIOUS_PACKAGES.has(name)) {
            // Avoid duplicates
            if (!results.malicious.some(m => m.package === name)) {
              results.malicious.push({
                package: name,
                version: info.version,
                reason: 'Known malicious package (transitive dependency)',
                path: pkgPath,
              });
              
              results.findings.push({
                source: 'supply-chain',
                package: name,
                severity: 'critical',
                title: `Malicious transitive dependency: ${name}`,
                description: `Found in: ${pkgPath}`,
                recommendation: 'Update parent package or override resolution',
              });
              results.summary.critical++;
              results.summary.total++;
            }
          }
        }
      }
    } catch (error) {
      // Ignore parse errors
    }
  }

  /**
   * Check for outdated packages (security risk)
   */
  async checkOutdatedPackages(targetPath, results) {
    if (!this.commandExists('npm')) return;

    try {
      const output = execSync('npm outdated --json 2>/dev/null || true', {
        cwd: targetPath,
        timeout: this.options.timeout,
        maxBuffer: 10 * 1024 * 1024,
      });

      const outdated = JSON.parse(output.toString() || '{}');
      
      for (const [name, info] of Object.entries(outdated)) {
        const majorBehind = this.getMajorVersionDiff(info.current, info.latest);
        
        if (majorBehind >= 2) {
          results.outdated.push({
            package: name,
            current: info.current,
            wanted: info.wanted,
            latest: info.latest,
            majorsBehind: majorBehind,
          });

          if (majorBehind >= 3) {
            results.findings.push({
              source: 'outdated',
              package: name,
              severity: 'warning',
              title: `Severely outdated: ${name}`,
              description: `Current: ${info.current}, Latest: ${info.latest} (${majorBehind} major versions behind)`,
              recommendation: 'Update to latest version for security patches',
            });
            results.summary.moderate++;
            results.summary.total++;
          }
        }
      }
    } catch {
      // Ignore errors
    }
  }

  /**
   * Analyze package.json scripts for suspicious commands
   */
  async analyzePackageScripts(targetPath, results) {
    const packageJsonPath = path.join(targetPath, 'package.json');
    
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const scripts = packageJson.scripts || {};
      
      const suspiciousPatterns = [
        { pattern: /curl\s+[^|]+\|\s*(bash|sh)/, reason: 'Downloads and executes remote script' },
        { pattern: /wget\s+[^;]+;\s*(bash|sh)/, reason: 'Downloads and executes remote script' },
        { pattern: /eval\s*\(/, reason: 'Uses eval()' },
        { pattern: /rm\s+-rf\s+[\/~]/, reason: 'Dangerous file deletion' },
        { pattern: />(\/dev\/tcp|\/dev\/udp)/, reason: 'Network redirection (reverse shell pattern)' },
        { pattern: /base64\s+-d/, reason: 'Decodes base64 (possible obfuscation)' },
        { pattern: /\$\(curl/, reason: 'Command substitution with remote fetch' },
        { pattern: /node\s+-e\s+['"]/, reason: 'Inline node execution' },
      ];

      for (const [scriptName, scriptCmd] of Object.entries(scripts)) {
        for (const { pattern, reason } of suspiciousPatterns) {
          if (pattern.test(scriptCmd)) {
            results.findings.push({
              source: 'scripts',
              package: 'package.json',
              severity: 'warning',
              title: `Suspicious npm script: ${scriptName}`,
              description: reason,
              evidence: scriptCmd.substring(0, 100),
              recommendation: 'Review script content for malicious behavior',
            });
            results.summary.moderate++;
            results.summary.total++;
            break; // One finding per script
          }
        }
      }
    } catch {
      // Ignore errors
    }
  }

  /**
   * Analyze Python dependencies
   */
  async analyzePythonDeps(targetPath, results) {
    const requirementsPath = path.join(targetPath, 'requirements.txt');
    
    if (!fs.existsSync(requirementsPath)) return;

    try {
      const content = fs.readFileSync(requirementsPath, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        // Check for git+http (insecure)
        if (trimmed.includes('git+http://')) {
          results.findings.push({
            source: 'requirements',
            package: trimmed,
            severity: 'warning',
            title: 'Insecure git URL',
            description: 'Using HTTP instead of HTTPS for git dependency',
            recommendation: 'Use git+https:// instead',
          });
          results.summary.moderate++;
          results.summary.total++;
        }

        // Check for unpinned versions
        if (!trimmed.includes('==') && !trimmed.includes('>=') && !trimmed.includes('@')) {
          const pkgName = trimmed.split(/[<>=\[]/)[0];
          if (pkgName && pkgName.length > 0) {
            results.findings.push({
              source: 'requirements',
              package: pkgName,
              severity: 'info',
              title: `Unpinned dependency: ${pkgName}`,
              description: 'Package version is not pinned',
              recommendation: 'Pin specific version for reproducibility',
            });
            // Don't count info as total for this
          }
        }
      }
    } catch {
      // Ignore errors
    }
  }

  /**
   * Get major version difference
   */
  getMajorVersionDiff(current, latest) {
    try {
      const currentMajor = parseInt(current?.split('.')[0]) || 0;
      const latestMajor = parseInt(latest?.split('.')[0]) || 0;
      return latestMajor - currentMajor;
    } catch {
      return 0;
    }
  }

  /**
   * Run pip-audit
   */
  async runPipAudit(targetPath) {
    if (!this.commandExists('pip-audit')) {
      return { 
        error: 'pip-audit not found. Install with: pip install pip-audit', 
        available: false 
      };
    }

    const requirementsPath = path.join(targetPath, 'requirements.txt');
    
    try {
      const args = ['--format', 'json'];
      
      if (fs.existsSync(requirementsPath)) {
        args.push('-r', requirementsPath);
      }

      const result = execSync(`pip-audit ${args.join(' ')} 2>/dev/null`, {
        cwd: targetPath,
        timeout: this.options.timeout,
        maxBuffer: 10 * 1024 * 1024,
      });

      return {
        available: true,
        data: JSON.parse(result.toString()),
      };
    } catch (error) {
      if (error.stdout) {
        try {
          return {
            available: true,
            data: JSON.parse(error.stdout.toString()),
          };
        } catch {
          return { available: true, error: 'Failed to parse pip-audit output' };
        }
      }
      return { available: true, error: error.message };
    }
  }

  /**
   * Process npm audit results into findings
   */
  processNpmResults(results) {
    if (!results.npm?.data?.vulnerabilities) return;

    const vulns = results.npm.data.vulnerabilities;
    
    for (const [pkgName, vuln] of Object.entries(vulns)) {
      const severity = this.normalizeSeverity(vuln.severity);
      
      results.findings.push({
        source: 'npm',
        package: pkgName,
        severity,
        title: vuln.title || `Vulnerability in ${pkgName}`,
        via: vuln.via?.map(v => typeof v === 'string' ? v : v.title).join(', ') || '',
        range: vuln.range || '',
        fixAvailable: vuln.fixAvailable ? 
          (typeof vuln.fixAvailable === 'object' ? 
            `Update ${vuln.fixAvailable.name} to ${vuln.fixAvailable.version}` : 
            'Yes') : 
          'No',
        url: vuln.via?.find(v => v.url)?.url || '',
      });

      results.summary.total++;
      results.summary[severity]++;
    }
  }

  /**
   * Process pip-audit results into findings
   */
  processPipResults(results) {
    if (!results.pip?.data) return;

    const vulns = Array.isArray(results.pip.data) ? 
      results.pip.data : 
      results.pip.data.vulnerabilities || [];

    for (const vuln of vulns) {
      const severity = this.normalizeSeverity(
        vuln.vulnerability?.severity || 
        vuln.aliases?.some(a => a.startsWith('CVE')) ? 'high' : 'moderate'
      );

      results.findings.push({
        source: 'pip',
        package: vuln.name,
        version: vuln.version,
        severity,
        title: vuln.vulnerability?.id || vuln.id || 'Unknown vulnerability',
        description: vuln.vulnerability?.description || '',
        fixVersions: vuln.fix_versions?.join(', ') || 'No fix available',
        aliases: vuln.vulnerability?.aliases?.join(', ') || vuln.aliases?.join(', ') || '',
      });

      results.summary.total++;
      results.summary[severity]++;
    }
  }

  /**
   * Normalize severity levels
   */
  normalizeSeverity(severity) {
    const normalized = (severity || '').toLowerCase();
    
    if (normalized === 'critical') return 'critical';
    if (normalized === 'high') return 'high';
    if (normalized === 'moderate' || normalized === 'medium' || normalized === 'warning') return 'moderate';
    if (normalized === 'low' || normalized === 'info') return 'low';
    
    return 'moderate';
  }

  /**
   * Get scanner status
   */
  getStatus() {
    return {
      npm: this.commandExists('npm'),
      pipAudit: this.commandExists('pip-audit'),
    };
  }
}

export { DependencyScanner };
module.exports = { DependencyScanner };
