const fs = require('fs');
const path = require('path');

function patchCapacitorCliTarExtract() {
  const filePath = path.join(
    process.cwd(),
    'node_modules',
    '@capacitor',
    'cli',
    'dist',
    'util',
    'template.js'
  );

  if (!fs.existsSync(filePath)) {
    return;
  }

  const original = fs.readFileSync(filePath, 'utf8');

  const alreadyPatched =
    original.includes('const tar_1 = require("tar");') &&
    original.includes('tar_1.extract({');

  if (alreadyPatched) {
    return;
  }

  let next = original;

  next = next.replace(
    'const tar_1 = tslib_1.__importDefault(require("tar"));',
    'const tar_1 = require("tar");'
  );

  next = next.replace('tar_1.default.extract({', 'tar_1.extract({');

  if (next !== original) {
    fs.writeFileSync(filePath, next, 'utf8');
  }
}

try {
  patchCapacitorCliTarExtract();
} catch {
  process.exit(0);
}
