/**
 * Parallel Processing Utilities
 * Optimized for large repository scanning
 */

/**
 * Process items in parallel with concurrency limit
 * @param {Array} items - Items to process
 * @param {Function} processor - Async function to process each item
 * @param {number} concurrency - Max concurrent operations (default: CPU cores)
 * @returns {Promise<Array>} Results array
 */
async function parallelMap(items, processor, concurrency = null) {
  const os = require('os');
  const maxConcurrency = concurrency || Math.max(1, os.cpus().length);
  
  const results = new Array(items.length);
  let index = 0;
  
  async function worker() {
    while (index < items.length) {
      const currentIndex = index++;
      try {
        results[currentIndex] = await processor(items[currentIndex], currentIndex);
      } catch (error) {
        results[currentIndex] = { error: error.message };
      }
    }
  }
  
  // Start workers
  const workers = [];
  for (let i = 0; i < Math.min(maxConcurrency, items.length); i++) {
    workers.push(worker());
  }
  
  await Promise.all(workers);
  return results;
}

/**
 * Batch items into chunks for processing
 * @param {Array} items - Items to batch
 * @param {number} batchSize - Items per batch
 * @returns {Array<Array>} Batched arrays
 */
function batch(items, batchSize) {
  const batches = [];
  for (let i = 0; i < items.length; i += batchSize) {
    batches.push(items.slice(i, i + batchSize));
  }
  return batches;
}

/**
 * Collect files from directory tree (non-recursive for performance)
 * Returns file paths without reading content
 */
function collectFiles(dirPath, options = {}) {
  const fs = require('fs');
  const path = require('path');
  
  const {
    excludeDirs = ['node_modules', '.git', '__pycache__', 'dist', 'build', '.cache', 'vendor', 'coverage'],
    excludeFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
    binaryExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico', '.pdf', '.zip', '.tar', '.gz', '.exe', '.bin', '.dll', '.so', '.mp3', '.mp4', '.woff', '.woff2', '.ttf'],
    maxDepth = 20,
    maxFiles = 10000,
  } = options;
  
  const files = [];
  const stack = [{ path: dirPath, depth: 0 }];
  
  while (stack.length > 0 && files.length < maxFiles) {
    const { path: currentPath, depth } = stack.pop();
    
    if (depth > maxDepth) continue;
    
    let entries;
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
function createProgressTracker(total, reportEvery = 100) {
  let processed = 0;
  const startTime = Date.now();
  
  return {
    tick(count = 1) {
      processed += count;
      return processed;
    },
    
    report() {
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
    
    shouldReport() {
      return processed % reportEvery === 0;
    },
  };
}

/**
 * Memory-efficient file reader with size check
 */
function readFileSafe(filePath, maxSize = 1024 * 1024) {
  const fs = require('fs');
  
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxSize) {
      return { skipped: true, reason: 'file too large', size: stat.size };
    }
    
    const content = fs.readFileSync(filePath, 'utf8');
    return { content, size: stat.size };
  } catch (error) {
    return { error: error.message };
  }
}

module.exports = {
  parallelMap,
  batch,
  collectFiles,
  createProgressTracker,
  readFileSafe,
};
