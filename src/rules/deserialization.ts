import type { Rule } from "../types.js";

/**
 * Deserialization Attack Detection Rules
 * Detects unsafe deserialization across multiple languages (CWE-502)
 * Complements pickle.ts (Python-specific) with Java, PHP, Ruby, .NET, Go patterns
 */

export const rules: Rule[] = [
  // ============================================
  // Java Deserialization
  // ============================================
  {
    id: 'deser-java-objectinputstream',
    severity: 'critical',
    description: 'Java ObjectInputStream.readObject() detected - arbitrary code execution risk',
    pattern: /ObjectInputStream[^;]*\.readObject\s*\(/gi,
    recommendation: 'ObjectInputStream.readObject() can execute arbitrary code. Use allowlists (ObjectInputFilter) or safer alternatives like JSON.',
  },
  {
    id: 'deser-java-xmldecoder',
    severity: 'critical',
    description: 'Java XMLDecoder detected - code execution via XML',
    pattern: /XMLDecoder\s*\(/gi,
    recommendation: 'XMLDecoder can instantiate arbitrary objects. Use safe XML parsers instead.',
  },
  {
    id: 'deser-java-snakeyaml-unsafe',
    severity: 'high',
    description: 'SnakeYAML unsafe load detected (allows arbitrary object instantiation)',
    pattern: /new\s+Yaml\s*\(\s*\)\.load\s*\(/gi,
    recommendation: 'SnakeYAML Yaml().load() allows arbitrary object creation. Use SafeConstructor or Yaml(new SafeConstructor()).load().',
  },
  {
    id: 'deser-java-xstream',
    severity: 'high',
    description: 'XStream deserialization detected - potential RCE',
    pattern: /XStream\s*\(\s*\)[^;]*\.fromXML\s*\(/gi,
    recommendation: 'XStream can execute arbitrary code. Configure security framework with XStream.setupDefaultSecurity().',
  },
  {
    id: 'deser-java-kryo-unsafe',
    severity: 'warning',
    description: 'Kryo deserialization without class registration',
    pattern: /kryo\.setRegistrationRequired\s*\(\s*false\s*\)/gi,
    recommendation: 'Kryo with registration disabled can deserialize arbitrary classes. Enable setRegistrationRequired(true).',
  },

  // ============================================
  // PHP Deserialization
  // ============================================
  {
    id: 'deser-php-unserialize',
    severity: 'critical',
    description: 'PHP unserialize() with user input - object injection risk',
    pattern: /unserialize\s*\(\s*\$(?:_(?:GET|POST|REQUEST|COOKIE|SERVER)|(?!allowed)[a-zA-Z_]+)\s*[\[)]/gi,
    recommendation: 'PHP unserialize() with user input enables object injection attacks. Use json_decode() or specify allowed_classes.',
  },
  {
    id: 'deser-php-unserialize-no-filter',
    severity: 'high',
    description: 'PHP unserialize() without allowed_classes restriction',
    pattern: /unserialize\s*\([^)]*\)(?!.*allowed_classes)/gi,
    recommendation: 'Use unserialize($data, ["allowed_classes" => false]) or specify allowed classes explicitly.',
  },
  {
    id: 'deser-php-phar',
    severity: 'critical',
    description: 'PHP phar:// stream wrapper detected - deserialization via file ops',
    pattern: /phar:\/\//gi,
    recommendation: 'phar:// wrapper triggers deserialization automatically. Block phar:// in user-controlled paths.',
  },

  // ============================================
  // Ruby Deserialization
  // ============================================
  {
    id: 'deser-ruby-marshal-load',
    severity: 'critical',
    description: 'Ruby Marshal.load() detected - arbitrary code execution risk',
    pattern: /Marshal\.(?:load|restore)\s*\(/gi,
    recommendation: 'Marshal.load() can execute arbitrary code. Use JSON.parse() or YAML.safe_load() instead.',
  },
  {
    id: 'deser-ruby-yaml-load',
    severity: 'critical',
    description: 'Ruby YAML.load() detected (unsafe in Ruby < 3.1)',
    pattern: /YAML\.load\s*\([^)]*\)(?!.*permitted_classes)/gi,
    recommendation: 'YAML.load() allows arbitrary object instantiation. Use YAML.safe_load() instead.',
  },
  {
    id: 'deser-ruby-erb-eval',
    severity: 'high',
    description: 'Ruby ERB template instantiation with dynamic input',
    pattern: /ERB\.new\s*\([^)]*\)\.result/gi,
    recommendation: 'ERB templates with untrusted input can execute arbitrary Ruby code.',
  },

  // ============================================
  // .NET Deserialization
  // ============================================
  {
    id: 'deser-dotnet-binaryformatter',
    severity: 'critical',
    description: '.NET BinaryFormatter.Deserialize() detected - RCE risk',
    pattern: /BinaryFormatter[^;]*\.Deserialize\s*\(/gi,
    recommendation: 'BinaryFormatter is inherently unsafe and deprecated. Use System.Text.Json or DataContractSerializer with known types.',
  },
  {
    id: 'deser-dotnet-objectstateformatter',
    severity: 'critical',
    description: '.NET ObjectStateFormatter detected - ViewState deserialization',
    pattern: /ObjectStateFormatter[^;]*\.Deserialize\s*\(/gi,
    recommendation: 'ObjectStateFormatter deserialization is dangerous. Ensure ViewState MAC validation is enabled.',
  },
  {
    id: 'deser-dotnet-losformatter',
    severity: 'critical',
    description: '.NET LosFormatter detected - unsafe deserialization',
    pattern: /LosFormatter[^;]*\.Deserialize\s*\(/gi,
    recommendation: 'LosFormatter uses BinaryFormatter internally. Migrate to safe serializers.',
  },
  {
    id: 'deser-dotnet-javascriptserializer',
    severity: 'high',
    description: '.NET JavaScriptSerializer with type resolver',
    pattern: /JavaScriptSerializer\s*\([^)]*SimpleTypeResolver/gi,
    recommendation: 'JavaScriptSerializer with SimpleTypeResolver allows arbitrary type instantiation. Remove the type resolver.',
  },
  {
    id: 'deser-dotnet-newtonsoft-typenamehandling',
    severity: 'high',
    description: 'Newtonsoft.Json TypeNameHandling enabled',
    pattern: /TypeNameHandling\s*[=:]\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)/gi,
    recommendation: 'TypeNameHandling enables polymorphic deserialization attacks. Use TypeNameHandling.None or a custom SerializationBinder.',
  },

  // ============================================
  // YAML Unsafe Loading (Cross-language)
  // ============================================
  {
    id: 'deser-yaml-unsafe-load',
    severity: 'high',
    description: 'YAML unsafe load detected (allows arbitrary object instantiation)',
    pattern: /yaml\.(?:unsafe_load|full_load|load)\s*\([^)]*(?:Loader\s*=\s*yaml\.(?:Unsafe|Full)Loader)?/gi,
    recommendation: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) to prevent arbitrary object creation.',
  },

  // ============================================
  // Go Deserialization
  // ============================================
  {
    id: 'deser-go-gob-decode',
    severity: 'warning',
    description: 'Go gob.Decode with untrusted input',
    pattern: /gob\.NewDecoder\s*\([^)]*(?:req\.Body|r\.Body|conn)/gi,
    recommendation: 'gob.Decode from network input can cause panics or unexpected behavior. Validate and limit input size.',
  },

  // ============================================
  // General Patterns
  // ============================================
  {
    id: 'deser-magic-bytes',
    severity: 'warning',
    description: 'Java serialization magic bytes detected (0xACED)',
    pattern: /\\xac\\xed\\x00\\x05|rO0AB|aced0005/gi,
    recommendation: 'Java serialization stream detected. These can contain exploit payloads.',
  },
  {
    id: 'deser-gadget-chain',
    severity: 'critical',
    description: 'Known deserialization gadget chain class detected',
    pattern: /(?:CommonsCollections|CommonsBeanutils|Spring|Hibernate|JRMPClient|Groovy|Jdk7u21|BeanShell|C3P0|Vaadin|Click|Wicket|FileUpload|Myfaces)[0-9]*(?:\s|['".])/gi,
    recommendation: 'Known deserialization gadget chain detected. Remove vulnerable library or restrict deserialization.',
  },
];

// CommonJS compatibility
module.exports = { rules };
