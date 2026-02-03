/**
 * Simple YAML Parser
 * Handles basic YAML structures without external dependencies
 */

interface StackItem {
  obj: any;
  indent: number;
}

export function parse(content: string): any {
  const lines = content.split('\n');
  const result: any = {};
  const stack: StackItem[] = [{ obj: result, indent: -1 }];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const indent = line.search(/\S/);
    
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    
    const parent = stack[stack.length - 1].obj;

    if (trimmed.startsWith('- ')) {
      const value = trimmed.slice(2).trim();
      
      if (Array.isArray(parent)) {
        if (value.includes(':')) {
          const obj: any = {};
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

    if (trimmed.includes(':')) {
      const [key, value] = splitKeyValue(trimmed);
      
      if (value === '' || value === null) {
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

function splitKeyValue(line: string): [string, string | null] {
  const colonIndex = line.indexOf(':');
  if (colonIndex === -1) return [line.trim(), null];
  
  const key = line.slice(0, colonIndex).trim();
  const value = line.slice(colonIndex + 1).trim();
  
  return [key, value || null];
}

function parseValue(value: string | null): any {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (value === 'null' || value === '~') return null;
  
  if (/^-?\d+$/.test(value)) return parseInt(value, 10);
  if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);
  
  if (value.startsWith('[') && value.endsWith(']')) {
    return value.slice(1, -1).split(',').map(v => parseValue(v.trim()));
  }
  
  return value;
}

export function stringify(obj: any, indent: number = 0): string {
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

// CommonJS compatibility
module.exports = { parse, stringify };
