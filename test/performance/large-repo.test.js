/**
 * Performance Tests for Large Repositories
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { scan } = require('../../src/index.js');
const { collectFiles, parallelMap, createProgressTracker } = require('../../src/utils/parallel.js');

describe('Performance: Large Repository Scanning', () => {
  let testDir;
  
  before(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentvet-perf-'));
  });
  
  after(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });
  
  function createTestFiles(count, contentGenerator) {
    for (let i = 0; i < count; i++) {
      const subdir = path.join(testDir, `dir${Math.floor(i / 100)}`);
      fs.mkdirSync(subdir, { recursive: true });
      fs.writeFileSync(
        path.join(subdir, `file${i}.js`),
        contentGenerator(i)
      );
    }
  }
  
  describe('File Collection', () => {
    test('should collect 1000 files in under 1 second', () => {
      createTestFiles(1000, i => `console.log("file ${i}");`);
      
      const start = Date.now();
      const files = collectFiles(testDir);
      const duration = Date.now() - start;
      
      assert.ok(files.length >= 1000, `Should find at least 1000 files (found ${files.length})`);
      assert.ok(duration < 1000, `Should complete in under 1s (took ${duration}ms)`);
    });
  });
  
  describe('Scanning Performance', () => {
    test('should scan 500 clean files in under 5 seconds', async () => {
      // Clean up previous test files
      fs.rmSync(testDir, { recursive: true, force: true });
      fs.mkdirSync(testDir, { recursive: true });
      
      createTestFiles(500, i => `
        // File ${i}
        const value = ${i};
        module.exports = { value };
      `);
      
      const start = Date.now();
      const results = await scan(testDir, { 
        yara: false, 
        deps: false,
        checkPermissions: false,
      });
      const duration = Date.now() - start;
      
      assert.ok(results.scannedFiles >= 500, `Should scan at least 500 files (scanned ${results.scannedFiles})`);
      assert.ok(duration < 5000, `Should complete in under 5s (took ${duration}ms)`);
      
      console.log(`Scanned ${results.scannedFiles} files in ${duration}ms (${Math.round(results.scannedFiles / (duration / 1000))} files/sec)`);
    });
    
    test('should scan 500 files with findings in under 10 seconds', async () => {
      // Clean up previous test files
      fs.rmSync(testDir, { recursive: true, force: true });
      fs.mkdirSync(testDir, { recursive: true });
      
      createTestFiles(500, i => `
        // File ${i}
        const key = "AKIAIOSFODNN7EXAMPLE";
        const password = "secret${i}";
      `);
      
      const start = Date.now();
      const results = await scan(testDir, { 
        yara: false, 
        deps: false,
        checkPermissions: false,
      });
      const duration = Date.now() - start;
      
      assert.ok(results.scannedFiles >= 500, `Should scan at least 500 files`);
      assert.ok(results.summary.total > 0, 'Should find issues');
      assert.ok(duration < 10000, `Should complete in under 10s (took ${duration}ms)`);
      
      console.log(`Scanned ${results.scannedFiles} files, found ${results.summary.total} issues in ${duration}ms`);
    });
  });
  
  describe('Parallel Processing', () => {
    test('parallelMap should process items concurrently', async () => {
      const items = Array.from({ length: 100 }, (_, i) => i);
      const delay = ms => new Promise(r => setTimeout(r, ms));
      
      const start = Date.now();
      const results = await parallelMap(
        items,
        async (item) => {
          await delay(10); // Simulate 10ms work
          return item * 2;
        },
        10 // 10 concurrent workers
      );
      const duration = Date.now() - start;
      
      assert.strictEqual(results.length, 100);
      assert.strictEqual(results[0], 0);
      assert.strictEqual(results[50], 100);
      
      // With 10 workers and 10ms each, 100 items should take ~100ms, not 1000ms
      assert.ok(duration < 500, `Parallel should be faster than sequential (took ${duration}ms)`);
    });
    
    test('progress tracker should report accurately', () => {
      const tracker = createProgressTracker(100);
      
      for (let i = 0; i < 50; i++) {
        tracker.tick();
      }
      
      const report = tracker.report();
      assert.strictEqual(report.processed, 50);
      assert.strictEqual(report.total, 100);
      assert.strictEqual(report.percent, 50);
    });
  });
  
  describe('Memory Usage', () => {
    test('should not exceed 200MB for 1000 files', async () => {
      // Clean up previous test files
      fs.rmSync(testDir, { recursive: true, force: true });
      fs.mkdirSync(testDir, { recursive: true });
      
      // Create files with substantial content
      createTestFiles(1000, i => `
        // Large file ${i}
        const data = ${JSON.stringify(Array(100).fill(`value${i}`))};
        module.exports = { data };
      `);
      
      // Force GC if available
      if (global.gc) global.gc();
      
      const memBefore = process.memoryUsage().heapUsed;
      
      await scan(testDir, { 
        yara: false, 
        deps: false,
        checkPermissions: false,
      });
      
      const memAfter = process.memoryUsage().heapUsed;
      const memUsedMB = (memAfter - memBefore) / 1024 / 1024;
      
      console.log(`Memory used: ${memUsedMB.toFixed(1)}MB`);
      
      // Allow up to 200MB memory usage
      assert.ok(memUsedMB < 200, `Memory usage should be under 200MB (used ${memUsedMB.toFixed(1)}MB)`);
    });
  });
  
});
