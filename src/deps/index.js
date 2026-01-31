/**
 * Dependency Vulnerability Scanner
 * Integrates npm audit and pip-audit for dependency scanning
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class DependencyScanner {
  constructor(options = {}) {
    this.options = {
      timeout: 60000, // 60 seconds
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
    }

    // Check for requirements.txt or pyproject.toml (pip)
    const requirementsPath = path.join(resolvedPath, 'requirements.txt');
    const pyprojectPath = path.join(resolvedPath, 'pyproject.toml');
    if (fs.existsSync(requirementsPath) || fs.existsSync(pyprojectPath)) {
      results.pip = await this.runPipAudit(resolvedPath);
      this.processPipResults(results);
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

    // Check if node_modules exists, if not try to get audit without install
    const nodeModulesPath = path.join(targetPath, 'node_modules');
    const packageLockPath = path.join(targetPath, 'package-lock.json');
    
    try {
      let result;
      
      if (fs.existsSync(packageLockPath)) {
        // Use --package-lock-only if lock file exists
        result = execSync('npm audit --json --package-lock-only 2>/dev/null', {
          cwd: targetPath,
          timeout: this.options.timeout,
          maxBuffer: 10 * 1024 * 1024, // 10MB
        });
      } else if (fs.existsSync(nodeModulesPath)) {
        // Normal audit if node_modules exists
        result = execSync('npm audit --json 2>/dev/null', {
          cwd: targetPath,
          timeout: this.options.timeout,
          maxBuffer: 10 * 1024 * 1024,
        });
      } else {
        // No lock file or node_modules, skip
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
      // npm audit returns non-zero exit code when vulnerabilities found
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
      let args = ['--format', 'json'];
      
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
    if (normalized === 'moderate' || normalized === 'medium') return 'moderate';
    if (normalized === 'low') return 'low';
    
    return 'moderate'; // Default
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

module.exports = { DependencyScanner };
