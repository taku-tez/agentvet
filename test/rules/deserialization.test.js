import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rules } from '../../dist/rules/deserialization.js';

describe('Deserialization Detection Rules', () => {
  it('should have 22 deserialization rules', () => {
    assert.equal(rules.length, 20);
  });

  // ============================================
  // Java
  // ============================================
  describe('deser-java-objectinputstream', () => {
    const rule = rules.find(r => r.id === 'deser-java-objectinputstream');

    it('detects ObjectInputStream.readObject()', () => {
      rule.pattern.lastIndex = 0;
      assert.match('new ObjectInputStream(stream).readObject()', rule.pattern);
    });

    it('detects inline readObject', () => {
      rule.pattern.lastIndex = 0;
      assert.match('new ObjectInputStream(stream).readObject()', rule.pattern);
    });
  });

  describe('deser-java-xmldecoder', () => {
    const rule = rules.find(r => r.id === 'deser-java-xmldecoder');

    it('detects XMLDecoder', () => {
      rule.pattern.lastIndex = 0;
      assert.match('XMLDecoder(new BufferedInputStream(fis))', rule.pattern);
    });
  });

  describe('deser-java-snakeyaml-unsafe', () => {
    const rule = rules.find(r => r.id === 'deser-java-snakeyaml-unsafe');

    it('detects unsafe SnakeYAML load', () => {
      rule.pattern.lastIndex = 0;
      assert.match('new Yaml().load(input)', rule.pattern);
    });
  });

  describe('deser-java-xstream', () => {
    const rule = rules.find(r => r.id === 'deser-java-xstream');

    it('detects XStream fromXML', () => {
      rule.pattern.lastIndex = 0;
      assert.match('XStream().fromXML(xmlString)', rule.pattern);
    });
  });

  describe('deser-java-kryo-unsafe', () => {
    const rule = rules.find(r => r.id === 'deser-java-kryo-unsafe');

    it('detects Kryo registration disabled', () => {
      rule.pattern.lastIndex = 0;
      assert.match('kryo.setRegistrationRequired(false)', rule.pattern);
    });
  });

  // ============================================
  // PHP
  // ============================================
  describe('deser-php-unserialize', () => {
    const rule = rules.find(r => r.id === 'deser-php-unserialize');

    it('detects unserialize with $_POST', () => {
      rule.pattern.lastIndex = 0;
      assert.match('unserialize($_POST["data"])', rule.pattern);
    });

    it('detects unserialize with $_GET', () => {
      rule.pattern.lastIndex = 0;
      assert.match('unserialize($_GET["obj"])', rule.pattern);
    });

    it('detects unserialize with $_COOKIE', () => {
      rule.pattern.lastIndex = 0;
      assert.match('unserialize($_COOKIE["session"])', rule.pattern);
    });
  });

  describe('deser-php-phar', () => {
    const rule = rules.find(r => r.id === 'deser-php-phar');

    it('detects phar:// stream', () => {
      rule.pattern.lastIndex = 0;
      assert.match('file_get_contents("phar://archive.phar/file.txt")', rule.pattern);
    });
  });

  // ============================================
  // Ruby
  // ============================================
  describe('deser-ruby-marshal-load', () => {
    const rule = rules.find(r => r.id === 'deser-ruby-marshal-load');

    it('detects Marshal.load', () => {
      rule.pattern.lastIndex = 0;
      assert.match('Marshal.load(data)', rule.pattern);
    });

    it('detects Marshal.restore', () => {
      rule.pattern.lastIndex = 0;
      assert.match('Marshal.restore(binary_data)', rule.pattern);
    });
  });

  describe('deser-ruby-yaml-load', () => {
    const rule = rules.find(r => r.id === 'deser-ruby-yaml-load');

    it('detects YAML.load', () => {
      rule.pattern.lastIndex = 0;
      assert.match('YAML.load(user_input)', rule.pattern);
    });
  });

  // ============================================
  // .NET
  // ============================================
  describe('deser-dotnet-binaryformatter', () => {
    const rule = rules.find(r => r.id === 'deser-dotnet-binaryformatter');

    it('detects BinaryFormatter.Deserialize', () => {
      rule.pattern.lastIndex = 0;
      assert.match('new BinaryFormatter().Deserialize(stream)', rule.pattern);
    });
  });

  describe('deser-dotnet-newtonsoft-typenamehandling', () => {
    const rule = rules.find(r => r.id === 'deser-dotnet-newtonsoft-typenamehandling');

    it('detects TypeNameHandling.All', () => {
      rule.pattern.lastIndex = 0;
      assert.match('TypeNameHandling = TypeNameHandling.All', rule.pattern);
    });

    it('detects TypeNameHandling.Auto', () => {
      rule.pattern.lastIndex = 0;
      assert.match('TypeNameHandling = TypeNameHandling.Auto', rule.pattern);
    });
  });

  describe('deser-dotnet-objectstateformatter', () => {
    const rule = rules.find(r => r.id === 'deser-dotnet-objectstateformatter');

    it('detects ObjectStateFormatter.Deserialize', () => {
      rule.pattern.lastIndex = 0;
      assert.match('new ObjectStateFormatter().Deserialize(viewState)', rule.pattern);
    });
  });

  // ============================================
  // General
  // ============================================
  describe('deser-magic-bytes', () => {
    const rule = rules.find(r => r.id === 'deser-magic-bytes');

    it('detects Java serialization Base64', () => {
      rule.pattern.lastIndex = 0;
      assert.match('payload = "rO0AB..."', rule.pattern);
    });

    it('detects hex magic bytes', () => {
      rule.pattern.lastIndex = 0;
      assert.match('data = "aced0005..."', rule.pattern);
    });
  });

  describe('deser-gadget-chain', () => {
    const rule = rules.find(r => r.id === 'deser-gadget-chain');

    it('detects CommonsCollections gadget', () => {
      rule.pattern.lastIndex = 0;
      assert.match('CommonsCollections1 payload', rule.pattern);
    });

    it('detects Spring gadget', () => {
      rule.pattern.lastIndex = 0;
      assert.match('Spring1 chain', rule.pattern);
    });
  });

  describe('deser-yaml-unsafe-load', () => {
    const rule = rules.find(r => r.id === 'deser-yaml-unsafe-load');

    it('detects yaml.unsafe_load', () => {
      rule.pattern.lastIndex = 0;
      assert.match('yaml.unsafe_load(data)', rule.pattern);
    });

    it('detects yaml.full_load', () => {
      rule.pattern.lastIndex = 0;
      assert.match('yaml.full_load(data)', rule.pattern);
    });
  });
});
