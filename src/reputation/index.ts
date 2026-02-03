// @ts-nocheck
/**
 * URL/IP Reputation Checker
 * Integrates with VirusTotal and other threat intelligence services
 */

const https = require('https');

// Rate limiting
const RATE_LIMITS = {
  virustotal: { requests: 4, windowMs: 60000 }, // 4 req/min for free tier
  abuseipdb: { requests: 1000, windowMs: 86400000 }, // 1000/day
};

class ReputationChecker {
  constructor(options = {}) {
    this.options = {
      virustotalKey: options.virustotalKey || process.env.VIRUSTOTAL_API_KEY,
      abuseipdbKey: options.abuseipdbKey || process.env.ABUSEIPDB_API_KEY,
      timeout: options.timeout || 10000,
      cache: options.cache !== false,
      ...options,
    };

    // Cache for results
    this.cache = new Map();
    this.cacheExpiry = options.cacheExpiry || 3600000; // 1 hour

    // Rate limiting state
    this.rateLimits = {
      virustotal: { count: 0, resetAt: Date.now() + RATE_LIMITS.virustotal.windowMs },
      abuseipdb: { count: 0, resetAt: Date.now() + RATE_LIMITS.abuseipdb.windowMs },
    };
  }

  /**
   * Check if service is available
   */
  isAvailable(service = 'any') {
    if (service === 'virustotal' || service === 'any') {
      if (this.options.virustotalKey) return true;
    }
    if (service === 'abuseipdb' || service === 'any') {
      if (this.options.abuseipdbKey) return true;
    }
    return false;
  }

  /**
   * Get available services
   */
  getAvailableServices() {
    const services = [];
    if (this.options.virustotalKey) services.push('virustotal');
    if (this.options.abuseipdbKey) services.push('abuseipdb');
    return services;
  }

  /**
   * Check rate limit
   */
  checkRateLimit(service) {
    const limit = this.rateLimits[service];
    if (!limit) return true;

    if (Date.now() > limit.resetAt) {
      limit.count = 0;
      limit.resetAt = Date.now() + RATE_LIMITS[service].windowMs;
    }

    return limit.count < RATE_LIMITS[service].requests;
  }

  /**
   * Increment rate limit counter
   */
  incrementRateLimit(service) {
    if (this.rateLimits[service]) {
      this.rateLimits[service].count++;
    }
  }

  /**
   * Check URL reputation
   */
  async checkUrl(targetUrl) {
    // Check cache first
    const cacheKey = `url:${targetUrl}`;
    if (this.options.cache && this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() < cached.expiry) {
        return cached.result;
      }
      this.cache.delete(cacheKey);
    }

    const result = {
      url: targetUrl,
      malicious: false,
      suspicious: false,
      score: 0,
      sources: [],
      details: {},
    };

    // Try VirusTotal
    if (this.options.virustotalKey && this.checkRateLimit('virustotal')) {
      try {
        const vtResult = await this.checkVirusTotal(targetUrl);
        result.sources.push('virustotal');
        result.details.virustotal = vtResult;
        
        if (vtResult.malicious > 0) {
          result.malicious = true;
          result.score = Math.max(result.score, vtResult.malicious / (vtResult.total || 1) * 100);
        }
        if (vtResult.suspicious > 0) {
          result.suspicious = true;
        }
      } catch (e) {
        result.details.virustotal = { error: e.message };
      }
    }

    // Cache result
    if (this.options.cache) {
      this.cache.set(cacheKey, {
        result,
        expiry: Date.now() + this.cacheExpiry,
      });
    }

    return result;
  }

  /**
   * Check IP reputation
   */
  async checkIp(ip) {
    const cacheKey = `ip:${ip}`;
    if (this.options.cache && this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() < cached.expiry) {
        return cached.result;
      }
      this.cache.delete(cacheKey);
    }

    const result = {
      ip,
      malicious: false,
      suspicious: false,
      score: 0,
      sources: [],
      details: {},
    };

    // Try AbuseIPDB
    if (this.options.abuseipdbKey && this.checkRateLimit('abuseipdb')) {
      try {
        const abuseResult = await this.checkAbuseIPDB(ip);
        result.sources.push('abuseipdb');
        result.details.abuseipdb = abuseResult;
        
        if (abuseResult.abuseConfidenceScore > 50) {
          result.malicious = true;
          result.score = abuseResult.abuseConfidenceScore;
        } else if (abuseResult.abuseConfidenceScore > 25) {
          result.suspicious = true;
          result.score = abuseResult.abuseConfidenceScore;
        }
      } catch (e) {
        result.details.abuseipdb = { error: e.message };
      }
    }

    // Try VirusTotal for IP
    if (this.options.virustotalKey && this.checkRateLimit('virustotal')) {
      try {
        const vtResult = await this.checkVirusTotalIp(ip);
        result.sources.push('virustotal');
        result.details.virustotal = vtResult;
        
        if (vtResult.malicious > 0) {
          result.malicious = true;
          result.score = Math.max(result.score, vtResult.malicious / (vtResult.total || 1) * 100);
        }
      } catch (e) {
        result.details.virustotal = { error: e.message };
      }
    }

    // Cache result
    if (this.options.cache) {
      this.cache.set(cacheKey, {
        result,
        expiry: Date.now() + this.cacheExpiry,
      });
    }

    return result;
  }

  /**
   * Check URL with VirusTotal
   */
  async checkVirusTotal(targetUrl) {
    this.incrementRateLimit('virustotal');

    // First, get URL ID (base64 of URL without padding)
    const urlId = Buffer.from(targetUrl).toString('base64').replace(/=/g, '');

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3/urls/${urlId}`,
        method: 'GET',
        headers: {
          'x-apikey': this.options.virustotalKey,
          'Accept': 'application/json',
        },
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode === 404) {
              // URL not in database, submit for scanning
              resolve({ status: 'not_found', malicious: 0, suspicious: 0, total: 0 });
              return;
            }
            if (res.statusCode !== 200) {
              reject(new Error(`VirusTotal API error: ${res.statusCode}`));
              return;
            }
            
            const json = JSON.parse(data);
            const stats = json.data?.attributes?.last_analysis_stats || {};
            
            resolve({
              status: 'found',
              malicious: stats.malicious || 0,
              suspicious: stats.suspicious || 0,
              harmless: stats.harmless || 0,
              undetected: stats.undetected || 0,
              total: Object.values(stats).reduce((a, b) => a + b, 0),
              lastAnalysis: json.data?.attributes?.last_analysis_date,
              categories: json.data?.attributes?.categories,
            });
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(this.options.timeout, () => {
        req.destroy();
        reject(new Error('VirusTotal request timeout'));
      });
      req.end();
    });
  }

  /**
   * Check IP with VirusTotal
   */
  async checkVirusTotalIp(ip) {
    this.incrementRateLimit('virustotal');

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3/ip_addresses/${ip}`,
        method: 'GET',
        headers: {
          'x-apikey': this.options.virustotalKey,
          'Accept': 'application/json',
        },
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode !== 200) {
              reject(new Error(`VirusTotal API error: ${res.statusCode}`));
              return;
            }
            
            const json = JSON.parse(data);
            const stats = json.data?.attributes?.last_analysis_stats || {};
            
            resolve({
              malicious: stats.malicious || 0,
              suspicious: stats.suspicious || 0,
              harmless: stats.harmless || 0,
              undetected: stats.undetected || 0,
              total: Object.values(stats).reduce((a, b) => a + b, 0),
              country: json.data?.attributes?.country,
              asOwner: json.data?.attributes?.as_owner,
            });
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(this.options.timeout, () => {
        req.destroy();
        reject(new Error('VirusTotal request timeout'));
      });
      req.end();
    });
  }

  /**
   * Check IP with AbuseIPDB
   */
  async checkAbuseIPDB(ip) {
    this.incrementRateLimit('abuseipdb');

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.abuseipdb.com',
        path: `/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        method: 'GET',
        headers: {
          'Key': this.options.abuseipdbKey,
          'Accept': 'application/json',
        },
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode !== 200) {
              reject(new Error(`AbuseIPDB API error: ${res.statusCode}`));
              return;
            }
            
            const json = JSON.parse(data);
            const result = json.data || {};
            
            resolve({
              abuseConfidenceScore: result.abuseConfidenceScore || 0,
              totalReports: result.totalReports || 0,
              countryCode: result.countryCode,
              isp: result.isp,
              domain: result.domain,
              isPublic: result.isPublic,
              isTor: result.isTor,
            });
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(this.options.timeout, () => {
        req.destroy();
        reject(new Error('AbuseIPDB request timeout'));
      });
      req.end();
    });
  }

  /**
   * Extract URLs and IPs from content
   */
  extractTargets(content) {
    const urls = new Set();
    const ips = new Set();

    // Extract URLs
    const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
    const urlMatches = content.match(urlPattern) || [];
    for (const u of urlMatches) {
      // Clean up URL
      const cleaned = u.replace(/[.,;:!?)]+$/, '');
      urls.add(cleaned);
    }

    // Extract IPs
    const ipPattern = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
    const ipMatches = content.match(ipPattern) || [];
    for (const ip of ipMatches) {
      // Validate IP
      const parts = ip.split('.');
      if (parts.every(p => parseInt(p) <= 255)) {
        // Skip private/local IPs
        if (!ip.startsWith('10.') && 
            !ip.startsWith('192.168.') && 
            !ip.startsWith('127.') &&
            !ip.match(/^172\.(1[6-9]|2\d|3[01])\./)) {
          ips.add(ip);
        }
      }
    }

    return { urls: Array.from(urls), ips: Array.from(ips) };
  }

  /**
   * Scan content for malicious URLs/IPs
   */
  async scanContent(content, options = {}) {
    const { urls, ips } = this.extractTargets(content);
    const results = {
      findings: [],
      checked: { urls: 0, ips: 0 },
      skipped: { urls: 0, ips: 0 },
    };

    const maxChecks = options.maxChecks || 10;
    let checksRemaining = maxChecks;

    // Check URLs
    for (const targetUrl of urls) {
      if (checksRemaining <= 0) {
        results.skipped.urls++;
        continue;
      }

      try {
        const result = await this.checkUrl(targetUrl);
        results.checked.urls++;
        checksRemaining--;

        if (result.malicious) {
          results.findings.push({
            type: 'url',
            target: targetUrl,
            severity: 'critical',
            score: result.score,
            sources: result.sources,
            message: `Malicious URL detected (${result.score.toFixed(0)}% threat score)`,
          });
        } else if (result.suspicious) {
          results.findings.push({
            type: 'url',
            target: targetUrl,
            severity: 'warning',
            score: result.score,
            sources: result.sources,
            message: 'Suspicious URL detected',
          });
        }
      } catch (e) {
        // Skip on error
        results.skipped.urls++;
      }
    }

    // Check IPs
    for (const ip of ips) {
      if (checksRemaining <= 0) {
        results.skipped.ips++;
        continue;
      }

      try {
        const result = await this.checkIp(ip);
        results.checked.ips++;
        checksRemaining--;

        if (result.malicious) {
          results.findings.push({
            type: 'ip',
            target: ip,
            severity: 'critical',
            score: result.score,
            sources: result.sources,
            message: `Malicious IP detected (${result.score.toFixed(0)}% abuse score)`,
          });
        } else if (result.suspicious) {
          results.findings.push({
            type: 'ip',
            target: ip,
            severity: 'warning',
            score: result.score,
            sources: result.sources,
            message: 'Suspicious IP detected',
          });
        }
      } catch (e) {
        results.skipped.ips++;
      }
    }

    return results;
  }

  /**
   * Get checker status
   */
  getStatus() {
    return {
      available: this.isAvailable(),
      services: this.getAvailableServices(),
      rateLimits: {
        virustotal: this.options.virustotalKey ? {
          remaining: RATE_LIMITS.virustotal.requests - this.rateLimits.virustotal.count,
          resetsIn: Math.max(0, this.rateLimits.virustotal.resetAt - Date.now()),
        } : null,
        abuseipdb: this.options.abuseipdbKey ? {
          remaining: RATE_LIMITS.abuseipdb.requests - this.rateLimits.abuseipdb.count,
          resetsIn: Math.max(0, this.rateLimits.abuseipdb.resetAt - Date.now()),
        } : null,
      },
      cacheSize: this.cache.size,
    };
  }
}

export { ReputationChecker };
module.exports = { ReputationChecker };
