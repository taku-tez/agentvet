#!/bin/bash
# Convert JS files to TS with basic transformations

cd /tmp/agentvet/src

# Rename .js to .ts (except index.ts which is already created)
for f in $(find . -name "*.js" -type f); do
  ts_file="${f%.js}.ts"
  if [ ! -f "$ts_file" ]; then
    mv "$f" "$ts_file"
  fi
done

echo "Converted files:"
find . -name "*.ts" | head -30
