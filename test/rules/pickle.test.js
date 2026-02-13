/**
 * Pickle / Deserialization Rules Unit Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/pickle.js');

describe('Pickle & Deserialization Rules', () => {

  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 80)}`);
  }

  describe('Pickle file detection', () => {
    test('should detect .pkl files', () => {
      testRule('pickle-file-detected', 'model.pkl', true);
    });
    test('should not match non-pickle files', () => {
      testRule('pickle-file-detected', 'model.json', false);
    });
  });

  describe('Unsafe pickle.load', () => {
    test('should detect pickle.load()', () => {
      testRule('pickle-unsafe-load', 'data = pickle.load(f)', true);
    });
    test('should detect pickle.loads()', () => {
      testRule('pickle-unsafe-load', 'data = pickle.loads(raw_bytes)', true);
    });
  });

  describe('joblib.load', () => {
    test('should detect joblib.load()', () => {
      testRule('joblib-unsafe-load', 'model = joblib.load("model.pkl")', true);
    });
    test('should not match joblib.dump', () => {
      testRule('joblib-unsafe-load', 'joblib.dump(model, "out.pkl")', false);
    });
  });

  describe('torch.load', () => {
    test('should detect unsafe torch.load()', () => {
      testRule('torch-unsafe-load', 'model = torch.load("model.pt")', true);
    });
  });

  describe('TensorFlow Lambda layer', () => {
    test('should detect Lambda layer', () => {
      testRule('tensorflow-lambda-layer', 'layer = Lambda(lambda x: x * 2)', true);
    });
  });

  describe('NumPy allow_pickle', () => {
    test('should detect np.load with allow_pickle=True', () => {
      testRule('numpy-allow-pickle', 'data = np.load("data.npy", allow_pickle=True)', true);
    });
    test('should not match np.load without allow_pickle', () => {
      testRule('numpy-allow-pickle', 'data = np.load("data.npy")', false);
    });
  });

  describe('cloudpickle', () => {
    test('should detect cloudpickle.load()', () => {
      testRule('cloudpickle-usage', 'obj = cloudpickle.load(f)', true);
    });
    test('should detect cloudpickle.dumps()', () => {
      testRule('cloudpickle-usage', 'data = cloudpickle.dumps(obj)', true);
    });
  });

  describe('dill', () => {
    test('should detect dill.load()', () => {
      testRule('dill-usage', 'obj = dill.load(f)', true);
    });
  });

  describe('shelve', () => {
    test('should detect shelve.open()', () => {
      testRule('shelve-usage', 'db = shelve.open("mydb")', true);
    });
  });

  describe('Model file detection', () => {
    test('should detect .safetensors files', () => {
      testRule('safetensors-usage', 'model.safetensors', true);
    });
    test('should detect .onnx files', () => {
      testRule('onnx-custom-ops', 'model.onnx', true);
    });
    test('should detect .pt files', () => {
      testRule('pytorch-model-file', 'model.pt', true);
    });
    test('should detect .pth files', () => {
      testRule('pytorch-model-file', 'weights.pth', true);
    });
    test('should detect .ckpt files', () => {
      testRule('checkpoint-file', 'epoch_10.ckpt', true);
    });
    test('should detect .h5 files', () => {
      testRule('keras-h5-lambda-risk', 'model.h5', true);
    });
  });

  describe('Pickle exploit patterns', () => {
    test('should detect __reduce__ exploit', () => {
      testRule('pickle-reduce-exploit', 'def __reduce__(self):', true);
    });
    test('should detect os.system in payload', () => {
      testRule('pickle-reduce-exploit', 'os.system("rm -rf /")', true);
    });
    test('should detect subprocess usage', () => {
      testRule('pickle-reduce-exploit', 'subprocess.Popen(["curl", url])', true);
    });
    test('should detect eval()', () => {
      testRule('pickle-reduce-exploit', 'eval(malicious_code)', true);
    });
  });
});
