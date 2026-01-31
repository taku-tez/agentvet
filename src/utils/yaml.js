/**
 * Simple YAML Parser
 * Handles basic YAML structures without external dependencies
 */

function parse(content) {
  const lines = content.split('\n');
  const result = {};
  const stack = [{ obj: result, indent: -1 }];
  const currentArray = null;
  const currentArrayIndent = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    // Calculate indentation
    const indent = line.search(/\S/);
    
    // Pop stack until we find parent level
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    
    const parent = stack[stack.length - 1].obj;

    // Handle array items
    if (trimmed.startsWith('- ')) {
      const value = trimmed.slice(2).trim();
      
      if (Array.isArray(parent)) {
        if (value.includes(':')) {
          // Array of objects
          const obj = {};
          const [key, val] = splitKeyValue(value);
          obj[key] = parseValue(val);
          parent.push(obj);
          stack.push({ obj: obj, indent: indent });
        } else {
          parent.push(parseValue(value));
        }
      }
      continue;
    }

    // Handle key: value
    if (trimmed.includes(':')) {
      const [key, value] = splitKeyValue(trimmed);
      
      if (value === '' || value === null) {
        // Check if next line is array or nested object
        const nextLine = lines[i + 1];
        if (nextLine && nextLine.trim().startsWith('-')) {
          parent[key] = [];
          stack.push({ obj: parent[key], indent: indent });
        } else {
          parent[key] = {};
          stack.push({ obj: parent[key], indent: indent });
        }
      } else {
        parent[key] = parseValue(value);
      }
    }
  }

  return result;
}

function splitKeyValue(line) {
  const colonIndex = line.indexOf(':');
  if (colonIndex === -1) return [line.trim(), null];
  
  const key = line.slice(0, colonIndex).trim();
  const value = line.slice(colonIndex + 1).trim();
  
  return [key, value || null];
}

function parseValue(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  
  // Remove quotes
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  
  // Boolean
  if (value === 'true') return true;
  if (value === 'false') return false;
  
  // Null
  if (value === 'null' || value === '~') return null;
  
  // Number
  if (/^-?\d+$/.test(value)) return parseInt(value, 10);
  if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);
  
  // Array inline [a, b, c]
  if (value.startsWith('[') && value.endsWith(']')) {
    return value.slice(1, -1).split(',').map(v => parseValue(v.trim()));
  }
  
  return value;
}

function stringify(obj, indent = 0) {
  const prefix = '  '.repeat(indent);
  let result = '';

  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === 'object' && item !== null) {
        result += `${prefix}-\n${stringify(item, indent + 1)}`;
      } else {
        result += `${prefix}- ${item}\n`;
      }
    }
  } else if (typeof obj === 'object' && obj !== null) {
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'object' && value !== null) {
        result += `${prefix}${key}:\n${stringify(value, indent + 1)}`;
      } else {
        result += `${prefix}${key}: ${value}\n`;
      }
    }
  }

  return result;
}

module.exports = { parse, stringify };
