/**
 * ClawdHub Integration for AgentVet
 * Safe skill installation with pre-vet security scanning
 */

import { spawn, execSync, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline';
import { scan } from './index.js';
import { printReport } from './reporter.js';

interface InstallOptions {
  workdir?: string | null;
  force?: boolean;
  version?: string | null;
  severity?: string;
  quiet?: boolean;
  skipVet?: boolean;
}

interface CheckOptions {
  severity?: string;
  quiet?: boolean;
  format?: 'text' | 'json';
}

interface ClawdhubResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Check if clawdhub CLI is installed
 */
export function checkClawdhubInstalled(): boolean {
  try {
    execSync('which clawdhub', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the workspace directory (same logic as clawdhub)
 */
export function getWorkspace(): string {
  if (process.env.CLAWDHUB_WORKDIR) {
    return process.env.CLAWDHUB_WORKDIR;
  }
  
  const configPaths = [
    path.join(os.homedir(), '.openclaw', 'openclaw.json'),
    path.join(os.homedir(), '.openclaw', 'config.json'),
  ];
  
  for (const configPath of configPaths) {
    if (fs.existsSync(configPath)) {
      try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (config.agents?.defaults?.workspace) {
          return config.agents.defaults.workspace;
        }
      } catch {
        // Ignore parse errors
      }
    }
  }
  
  return process.cwd();
}

/**
 * Install a skill from ClawdHub with security vetting
 */
export async function installSkill(slug: string, options: InstallOptions = {}): Promise<void> {
  const {
    workdir,
    force = false,
    version = null,
    severity = 'medium',
    quiet = false,
    skipVet = false,
  } = options;
  
  const targetWorkdir = workdir || getWorkspace();

  console.log(`🔍 AgentVet: Installing skill "${slug}" with security vetting...\n`);

  if (!checkClawdhubInstalled()) {
    console.error('❌ clawdhub CLI not found. Install it with: npm install -g clawdhub');
    process.exit(2);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentvet-install-'));
  const tmpSkillsDir = path.join(tmpDir, 'skills');
  fs.mkdirSync(tmpSkillsDir, { recursive: true });

  try {
    console.log('📥 Downloading skill to temporary directory...');
    const downloadArgs = ['install', slug, '--workdir', tmpDir];
    if (version) downloadArgs.push('--version', version);
    if (force) downloadArgs.push('--force');

    const downloadResult = await runClawdhub(downloadArgs);
    if (downloadResult.code !== 0) {
      console.error('❌ Failed to download skill:', downloadResult.stderr);
      process.exit(2);
    }

    const skillPath = path.join(tmpSkillsDir, slug);
    if (!fs.existsSync(skillPath)) {
      const skills = fs.readdirSync(tmpSkillsDir).filter(f => 
        fs.statSync(path.join(tmpSkillsDir, f)).isDirectory()
      );
      if (skills.length === 0) {
        console.error('❌ No skill found in download');
        process.exit(2);
      }
    }

    const actualSkillPath = fs.existsSync(skillPath) ? skillPath : path.join(tmpSkillsDir, fs.readdirSync(tmpSkillsDir)[0]);

    if (!skipVet) {
      console.log('\n🔒 Running security scan...\n');
      
      const results = await scan(actualSkillPath, {
        yara: true,
        checkPermissions: true,
      });

      if (!quiet) {
        console.log(printReport(results, actualSkillPath));
      }

      const criticalCount = results.findings.filter((f: { severity: string }) => f.severity === 'critical').length;
      const highCount = results.findings.filter((f: { severity: string }) => f.severity === 'high').length;
      
      const severityLevels = ['critical', 'high', 'medium', 'low', 'info'];
      const severityIndex = severityLevels.indexOf(severity);
      
      const blockingFindings = results.findings.filter((f: { severity: string }) => {
        const findingSeverityIndex = severityLevels.indexOf(f.severity);
        return findingSeverityIndex <= severityIndex;
      });

      if (blockingFindings.length > 0) {
        console.log('\n⚠️  Security issues found!\n');
        console.log(`   Critical: ${criticalCount}`);
        console.log(`   High: ${highCount}`);
        console.log(`   Total blocking (>=${severity}): ${blockingFindings.length}`);
        
        if (process.stdin.isTTY && !force) {
          const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
          });

          const answer = await new Promise<string>(resolve => {
            rl.question('\n❓ Install anyway? (y/N): ', resolve);
          });
          rl.close();

          if (answer.toLowerCase() !== 'y' && answer.toLowerCase() !== 'yes') {
            console.log('\n❌ Installation cancelled.');
            process.exit(1);
          }
          console.log('\n⚠️  Proceeding with installation despite security warnings...\n');
        } else if (!force) {
          console.log('\n❌ Installation blocked due to security issues.');
          console.log('   Use --force to install anyway (not recommended).');
          process.exit(1);
        }
      } else {
        console.log('\n✅ No blocking security issues found!\n');
      }
    }

    console.log('📦 Installing to workspace...');
    const destSkillsDir = path.join(targetWorkdir, 'skills');
    const destPath = path.join(destSkillsDir, path.basename(actualSkillPath));

    fs.mkdirSync(destSkillsDir, { recursive: true });

    if (fs.existsSync(destPath) && !force) {
      console.error(`❌ Skill already exists at ${destPath}`);
      console.error('   Use --force to overwrite.');
      process.exit(2);
    }

    copyDirectory(actualSkillPath, destPath);

    console.log(`\n✅ Skill "${slug}" installed successfully to ${destPath}`);
    console.log('\n💡 Restart OpenClaw to load the new skill.');

  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Run clawdhub CLI command
 */
function runClawdhub(args: string[]): Promise<ClawdhubResult> {
  return new Promise((resolve) => {
    const proc: ChildProcess = spawn('clawdhub', args, { 
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NO_COLOR: '1' }
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
    proc.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });
    
    proc.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
    
    proc.on('error', (err: Error) => {
      resolve({ code: 2, stdout: '', stderr: err.message });
    });
  });
}

/**
 * Copy directory recursively
 */
function copyDirectory(src: string, dest: string): void {
  if (fs.existsSync(dest)) {
    fs.rmSync(dest, { recursive: true });
  }
  fs.mkdirSync(dest, { recursive: true });
  
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    
    if (entry.isDirectory()) {
      copyDirectory(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Scan a local skill directory
 */
export async function checkSkill(skillPath: string, options: CheckOptions = {}): Promise<unknown> {
  const {
    quiet = false,
    format = 'text',
  } = options;

  console.log(`🔍 Scanning skill at: ${skillPath}\n`);

  if (!fs.existsSync(skillPath)) {
    console.error(`❌ Path not found: ${skillPath}`);
    process.exit(2);
  }

  const results = await scan(skillPath, {
    yara: true,
    checkPermissions: true,
  });

  if (!quiet) {
    if (format === 'json') {
      console.log(JSON.stringify(results, null, 2));
    } else {
      console.log(printReport(results, skillPath));
    }
  }

  const criticalCount = results.findings.filter((f: { severity: string }) => f.severity === 'critical').length;
  const highCount = results.findings.filter((f: { severity: string }) => f.severity === 'high').length;
  
  console.log('\n📊 Summary:');
  console.log(`   Files scanned: ${results.scannedFiles || 0}`);
  console.log(`   Total findings: ${results.findings.length}`);
  console.log(`   Critical: ${criticalCount}`);
  console.log(`   High: ${highCount}`);

  if (criticalCount > 0) {
    process.exit(1);
  }
  
  return results;
}

module.exports = { installSkill, checkSkill, checkClawdhubInstalled, getWorkspace };
