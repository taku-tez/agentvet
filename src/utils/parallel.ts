/**
 * Parallel Processing Utilities
 * Optimized for large repository scanning
 */

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';

interface CollectFilesOptions {
  excludeDirs?: string[];
  excludeFiles?: string[];
  binaryExtensions?: string[];
  maxDepth?: number;
  maxFiles?: number;
}

interface ProgressReport {
  processed: number;
  total: number;
  percent: number;
  elapsed: string;
  rate: string;
  remaining: string;
}

interface ProgressTracker {
  tick(count?: number): number;
  report(): ProgressReport;
  shouldReport(): boolean;
}

interface ReadResult {
  content?: string;
  size?: number;
  skipped?: boolean;
  reason?: string;
  error?: string;
}

/**
 * Process items in parallel with concurrency limit
 */
export async function parallelMap<T, R>(
  items: T[],
  processor: (item: T, index: number) => Promise<R>,
  concurrency: number | null = null
): Promise<(R | { error: string })[]> {
  const maxConcurrency = concurrency || Math.max(1, os.cpus().length);
  
  const results: (R | { error: string })[] = new Array(items.length);
  let index = 0;
  
  async function worker(): Promise<void> {
    while (index < items.length) {
      const currentIndex = index++;
      try {
        results[currentIndex] = await processor(items[currentIndex], currentIndex);
      } catch (error: any) {
        results[currentIndex] = { error: error.message };
      }
    }
  }
  
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(maxConcurrency, items.length); i++) {
    workers.push(worker());
  }
  
  await Promise.all(workers);
  return results;
}

/**
 * Batch items into chunks for processing
 */
export function batch<T>(items: T[], batchSize: number): T[][] {
  const batches: T[][] = [];
  for (let i = 0; i < items.length; i += batchSize) {
    batches.push(items.slice(i, i + batchSize));
  }
  return batches;
}

/**
 * Collect files from directory tree (non-recursive for performance)
 */
export function collectFiles(dirPath: string, options: CollectFilesOptions = {}): string[] {
  const {
    excludeDirs = ['node_modules', '.git', '__pycache__', 'dist', 'build', '.cache', 'vendor', 'coverage'],
    excludeFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    binaryExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico', '.pdf', '.zip', '.tar', '.gz', '.exe', '.bin', '.dll', '.so', '.mp3', '.mp4', '.woff', '.woff2', '.ttf'],
    maxDepth = 20,
    maxFiles = 10000,
  } = options;
  
  const files: string[] = [];
  const stack: { path: string; depth: number }[] = [{ path: dirPath, depth: 0 }];
  
  while (stack.length > 0 && files.length < maxFiles) {
    const item = stack.pop()!;
    const { path: currentPath, depth } = item;
    
    if (depth > maxDepth) continue;
    
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      continue;
    }
    
    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      
      if (entry.isDirectory()) {
        if (!excludeDirs.includes(entry.name)) {
          stack.push({ path: fullPath, depth: depth + 1 });
        }
      } else if (entry.isFile()) {
        if (!excludeFiles.includes(entry.name)) {
          const ext = path.extname(entry.name).toLowerCase();
          if (!binaryExtensions.includes(ext)) {
            files.push(fullPath);
          }
        }
      }
    }
  }
  
  return files;
}

/**
 * Create a progress tracker
 */
export function createProgressTracker(total: number, reportEvery: number = 100): ProgressTracker {
  let processed = 0;
  const startTime = Date.now();
  
  return {
    tick(count: number = 1): number {
      processed += count;
      return processed;
    },
    
    report(): ProgressReport {
      const elapsed = (Date.now() - startTime) / 1000;
      const rate = processed / elapsed;
      const remaining = (total - processed) / rate;
      
      return {
        processed,
        total,
        percent: Math.round((processed / total) * 100),
        elapsed: elapsed.toFixed(1),
        rate: rate.toFixed(0),
        remaining: remaining.toFixed(1),
      };
    },
    
    shouldReport(): boolean {
      return processed % reportEvery === 0;
    },
  };
}

/**
 * Memory-efficient file reader with size check
 */
export function readFileSafe(filePath: string, maxSize: number = 1024 * 1024): ReadResult {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxSize) {
      return { skipped: true, reason: 'file too large', size: stat.size };
    }
    
    const content = fs.readFileSync(filePath, 'utf8');
    return { content, size: stat.size };
  } catch (error: any) {
    return { error: error.message };
  }
}

// CommonJS compatibility
module.exports = {
  parallelMap,
  batch,
  collectFiles,
  createProgressTracker,
  readFileSafe,
};
