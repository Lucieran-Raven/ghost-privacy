import { readFileSync } from 'node:fs';

const baseline = Number.parseInt(readFileSync('.eslint-warning-baseline', 'utf8').trim(), 10);
const input = readFileSync(0, 'utf8');
const report = JSON.parse(input);
const warnings = report.reduce((sum, file) => sum + (file.warningCount || 0), 0);
const errors = report.reduce((sum, file) => sum + (file.errorCount || 0), 0);

if (errors > 0) {
  console.error(`ESLint reported ${errors} errors.`);
  process.exit(1);
}

if (warnings > baseline) {
  console.error(`ESLint warnings increased: baseline=${baseline}, current=${warnings}`);
  process.exit(1);
}

if (warnings < baseline) {
  console.log(`ESLint warnings improved: baseline=${baseline}, current=${warnings}`);
} else {
  console.log(`ESLint warnings unchanged at ${warnings}.`);
}
