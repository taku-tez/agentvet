import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rules } from '../../dist/rules/ssrf.js';

describe('SSRF Detection Rules', () => {
  it('should have 16 SSRF rules', () => {
    assert.equal(rules.length, 14);
  });

  describe('ssrf-aws-metadata', () => {
    const rule = rules.find(r => r.id === 'ssrf-aws-metadata');

    it('detects AWS metadata IP', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch("http://169.254.169.254/latest/meta-data/")', rule.pattern);
    });

    it('detects GCP metadata hostname', () => {
      rule.pattern.lastIndex = 0;
      assert.match('curl http://metadata.google.internal/computeMetadata/v1/', rule.pattern);
    });

    it('detects Azure metadata hostname', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch("http://metadata.azure.com/metadata/instance")', rule.pattern);
    });
  });

  describe('ssrf-url-from-param', () => {
    const rule = rules.find(r => r.id === 'ssrf-url-from-param');

    it('detects fetch with req.query', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch(req.query.url)', rule.pattern);
    });

    it('detects axios with req.body', () => {
      rule.pattern.lastIndex = 0;
      assert.match('axios(req.body.targetUrl)', rule.pattern);
    });

    it('detects Python requests with request.args', () => {
      rule.pattern.lastIndex = 0;
      assert.match('requests.get(request.args["url"])', rule.pattern);
    });
  });

  describe('ssrf-url-concat', () => {
    const rule = rules.find(r => r.id === 'ssrf-url-concat');

    it('detects fetch with string concatenation', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch("http://" + req.body.host)', rule.pattern);
    });
  });

  describe('ssrf-template-url', () => {
    const rule = rules.find(r => r.id === 'ssrf-template-url');

    it('detects fetch with template literal', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch(`https://${req.query.host}/api`)', rule.pattern);
    });
  });

  describe('ssrf-gopher-protocol', () => {
    const rule = rules.find(r => r.id === 'ssrf-gopher-protocol');

    it('detects gopher protocol', () => {
      rule.pattern.lastIndex = 0;
      assert.match('gopher://127.0.0.1:6379/_SET key value', rule.pattern);
    });
  });

  describe('ssrf-file-protocol', () => {
    const rule = rules.find(r => r.id === 'ssrf-file-protocol');

    it('detects file:// in fetch', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch("file:///etc/passwd")', rule.pattern);
    });

    it('detects file:// in requests', () => {
      rule.pattern.lastIndex = 0;
      assert.match('requests("file:///etc/shadow")', rule.pattern);
    });
  });

  describe('ssrf-dict-protocol', () => {
    const rule = rules.find(r => r.id === 'ssrf-dict-protocol');

    it('detects dict protocol', () => {
      rule.pattern.lastIndex = 0;
      assert.match('dict://127.0.0.1:11211/stat', rule.pattern);
    });
  });

  describe('ssrf-redirect-follow', () => {
    const rule = rules.find(r => r.id === 'ssrf-redirect-follow');

    it('detects followRedirects: true', () => {
      rule.pattern.lastIndex = 0;
      assert.match('followRedirects: true', rule.pattern);
    });

    it('detects Python allow_redirects=True', () => {
      rule.pattern.lastIndex = 0;
      assert.match('allow_redirects=True', rule.pattern);
    });
  });

  describe('ssrf-image-url-fetch', () => {
    const rule = rules.find(r => r.id === 'ssrf-image-url-fetch');

    it('detects imageUrl from request', () => {
      rule.pattern.lastIndex = 0;
      assert.match('imageUrl = req.body.imageUrl', rule.pattern);
    });

    it('detects avatar_url from params', () => {
      rule.pattern.lastIndex = 0;
      assert.match('avatar_url = params.avatar', rule.pattern);
    });
  });

  describe('ssrf-webhook-url', () => {
    const rule = rules.find(r => r.id === 'ssrf-webhook-url');

    it('detects webhookUrl from request', () => {
      rule.pattern.lastIndex = 0;
      assert.match('webhookUrl = req.body.url', rule.pattern);
    });

    it('detects callback_url from input', () => {
      rule.pattern.lastIndex = 0;
      assert.match('callback_url = input.callback', rule.pattern);
    });
  });

  describe('ssrf-python-fstring-url', () => {
    const rule = rules.find(r => r.id === 'ssrf-python-fstring-url');

    it('detects Python f-string with request input', () => {
      rule.pattern.lastIndex = 0;
      assert.match('requests.get(f"https://{request.host}/api")', rule.pattern);
    });
  });

  describe('ssrf-internal-ip-fetch', () => {
    const rule = rules.find(r => r.id === 'ssrf-internal-ip-fetch');

    it('detects fetch to 10.x.x.x', () => {
      rule.pattern.lastIndex = 0;
      assert.match('fetch("http://10.0.0.1/admin")', rule.pattern);
    });

    it('detects requests to 192.168.x.x', () => {
      rule.pattern.lastIndex = 0;
      assert.match('requests.get("http://192.168.1.1/api")', rule.pattern);
    });
  });
});
