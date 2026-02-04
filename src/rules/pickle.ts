import type { Rule } from "../types.js";

/**
 * Pickle Deserialization Security Rules
 * Detects unsafe pickle operations (CWE-502: Deserialization of Untrusted Data)
 */

export const rules: Rule[] = [
  // Pickle file detection
  {
    id: 'pickle-file-detected',
    severity: 'warning',
    description: 'Pickle file detected - potential deserialization risk',
    pattern: /\.pkl$/i,
    recommendation: 'Pickle files can contain arbitrary code. Only load pkl files from trusted sources. Consider using safer formats like JSON or safetensors.',
  },

  // Python pickle.load without safety
  {
    id: 'pickle-unsafe-load',
    severity: 'critical',
    description: 'Unsafe pickle.load() detected - arbitrary code execution risk',
    pattern: /pickle\.loads?\s*\(/gi,
    recommendation: 'pickle.load() can execute arbitrary code. Use json, yaml, or other safe formats. If pickle is required, validate the source and consider using fickling for static analysis.',
  },

  // Python joblib.load (uses pickle internally)
  {
    id: 'joblib-unsafe-load',
    severity: 'warning',
    description: 'joblib.load() detected - uses pickle internally',
    pattern: /joblib\.load\s*\(/gi,
    recommendation: 'joblib uses pickle internally and can execute arbitrary code. Only load from trusted sources.',
  },

  // PyTorch torch.load without weights_only
  {
    id: 'torch-unsafe-load',
    severity: 'critical',
    description: 'Unsafe torch.load() detected - uses pickle by default',
    pattern: /torch\.load\s*\([^)]*\)(?!\s*#.*weights_only)/gi,
    recommendation: 'torch.load() uses pickle by default. Use weights_only=True for model weights, or use torch.jit.load() for TorchScript models.',
  },

  // TensorFlow Lambda layers (can contain embedded code)
  {
    id: 'tensorflow-lambda-layer',
    severity: 'warning',
    description: 'TensorFlow Lambda layer detected - may contain embedded code',
    pattern: /Lambda\s*\(\s*lambda\s+/gi,
    recommendation: 'Lambda layers can contain arbitrary Python code. Avoid loading models with Lambda layers from untrusted sources. Use standard Keras layers instead.',
  },

  // HDF5/H5 model files with Lambda
  {
    id: 'keras-h5-lambda-risk',
    severity: 'warning',
    description: 'Keras H5/HDF5 model file - check for Lambda layers',
    pattern: /\.(?:h5|hdf5|keras)$/i,
    recommendation: 'Keras H5 models may contain Lambda layers with embedded Python code. Validate model architecture before loading from untrusted sources.',
  },

  // Numpy .npy/.npz with allow_pickle
  {
    id: 'numpy-allow-pickle',
    severity: 'warning',
    description: 'NumPy load with allow_pickle=True - potential code execution',
    pattern: /np\.load\s*\([^)]*allow_pickle\s*=\s*True/gi,
    recommendation: 'NumPy allow_pickle=True enables pickle deserialization. Ensure data source is trusted.',
  },

  // Cloudpickle (often used for distributed computing)
  {
    id: 'cloudpickle-usage',
    severity: 'warning',
    description: 'cloudpickle detected - extended pickle with same risks',
    pattern: /cloudpickle\.(?:load|loads|dump|dumps)\s*\(/gi,
    recommendation: 'cloudpickle extends pickle capabilities but has the same security risks. Only use with trusted data.',
  },

  // Dill (extended pickle)
  {
    id: 'dill-usage',
    severity: 'warning',
    description: 'dill library detected - extended pickle with same risks',
    pattern: /dill\.(?:load|loads|dump|dumps)\s*\(/gi,
    recommendation: 'dill extends pickle capabilities but has the same security risks. Only use with trusted data.',
  },

  // Shelve (uses pickle)
  {
    id: 'shelve-usage',
    severity: 'warning',
    description: 'shelve module detected - uses pickle internally',
    pattern: /shelve\.open\s*\(/gi,
    recommendation: 'shelve uses pickle internally. Only open shelve files from trusted sources.',
  },

  // ONNX model with custom ops
  {
    id: 'onnx-custom-ops',
    severity: 'info',
    description: 'ONNX model file detected',
    pattern: /\.onnx$/i,
    recommendation: 'ONNX is generally safe but verify model source. Custom operators may pose risks.',
  },

  // SafeTensors (safe alternative)
  {
    id: 'safetensors-usage',
    severity: 'info',
    description: 'safetensors format detected - safe model format',
    pattern: /\.safetensors$/i,
    recommendation: 'safetensors is a secure format that cannot contain arbitrary code. Good choice!',
  },

  // Malicious pickle patterns (known attack payloads)
  {
    id: 'pickle-reduce-exploit',
    severity: 'critical',
    description: 'Potential pickle exploit payload detected',
    pattern: /__reduce__|__reduce_ex__|__setstate__|os\.system|subprocess\.|eval\s*\(|exec\s*\(/gi,
    recommendation: 'This may be a malicious pickle payload attempting to execute arbitrary code.',
  },

  // PyTorch model files (.pt, .pth, .bin)
  {
    id: 'pytorch-model-file',
    severity: 'warning',
    description: 'PyTorch model file detected - uses pickle by default',
    pattern: /\.(?:pt|pth|bin)$/i,
    recommendation: 'PyTorch .pt/.pth files use pickle. Only load from trusted sources. Consider converting to safetensors format.',
  },

  // Checkpoint files
  {
    id: 'checkpoint-file',
    severity: 'warning',
    description: 'Model checkpoint file detected - may use pickle',
    pattern: /\.ckpt$/i,
    recommendation: 'Checkpoint files often use pickle serialization. Verify source before loading.',
  },
];

// CommonJS compatibility
module.exports = { rules };
