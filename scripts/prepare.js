#!/usr/bin/env node
/**
 * This script scans the ./dist folder and generates an "exports" field
 * in package.json that mirrors the file structure.
 *
 * For each export it maps:
 * - The "import" property pointing to the .js file.
 * - If a corresponding .d.ts file exists, a "types" property pointing to it.
 *
 * Run this script after building your TypeScript code with tsc.
 */

const fs = require('fs');
const path = require('path');

const projectRoot = process.cwd();
const distDir = path.join(projectRoot, 'dist');
const pkgPath = path.join(projectRoot, 'package.json');

// Read package.json
if (!fs.existsSync(pkgPath)) {
  console.error('package.json not found.');
  process.exit(1);
}
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

/**
 * Check if a declaration file exists for a given file.
 * Expects .d.ts to be in the same folder with the same base name.
 *
 * @param {string} filePath - Full path to the .js file.
 * @returns {string|null} - Relative path to the .d.ts file if exists, otherwise null.
 */
function getDeclarationFile(filePath) {
  const dtsFile = filePath.replace(/\.js$/, '.d.ts');
  return fs.existsSync(dtsFile) ? `./${path.relative(projectRoot, dtsFile).replace(/\\/g, '/')}` : null;
}

/**
 * Recursively scan a directory and build an exports mapping.
 *
 * @param {string} dir - The directory to scan.
 * @param {string} prefix - The export path prefix (default: '.').
 * @returns {object} - Exports mapping.
 */
function generateExports(dir, prefix = '.') {
  let exportsMap = {};
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    // Create a relative export key, normalizing to forward slashes.
    const relativeExportPath = path.join(prefix, entry.name).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      // Check if the directory contains an index.js file.
      const indexJs = path.join(entryPath, 'index.js');
      if (fs.existsSync(indexJs)) {
        const exportEntry = {
          import: `./${path.relative(projectRoot, indexJs).replace(/\\/g, '/')}`,
        };

        // Check for a declaration file (index.d.ts) in the same folder.
        const dtsPath = getDeclarationFile(indexJs);
        if (dtsPath) {
          exportEntry.types = dtsPath;
        }
        exportsMap[relativeExportPath] = exportEntry;
      }
      // Recursively add nested exports.
      const nestedExports = generateExports(entryPath, path.join(prefix, entry.name));
      exportsMap = { ...exportsMap, ...nestedExports };
    } else if (entry.isFile() && entry.name.endsWith('.js') && entry.name !== 'index.js') {
      // Remove the .js extension for the export key.
      const key = relativeExportPath.slice(0, -3);
      const exportEntry = {
        import: `./${path.relative(projectRoot, entryPath).replace(/\\/g, '/')}`,
      };

      // Check for a corresponding .d.ts file.
      const dtsPath = getDeclarationFile(entryPath);
      if (dtsPath) {
        exportEntry.types = dtsPath;
      }
      exportsMap[key] = exportEntry;
    }
  }

  return exportsMap;
}

// Generate exports based on the dist folder.
let exportsField = generateExports(distDir);

// Ensure that if dist/index.js exists, it is assigned to "."
const mainIndex = path.join(distDir, 'index.js');
if (fs.existsSync(mainIndex)) {
  const mainExport = {
    import: `./${path.relative(projectRoot, mainIndex).replace(/\\/g, '/')}`
  };
  const dtsMain = getDeclarationFile(mainIndex);
  if (dtsMain) {
    mainExport.types = dtsMain;
  }
  exportsField['.'] = mainExport;
}

// Update package.json with the new exports field.
pkg.exports = exportsField;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
console.log('Updated package.json exports field:');
console.log(JSON.stringify(exportsField, null, 2));
