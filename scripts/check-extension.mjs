import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const extensionRoot = path.join(repositoryRoot, 'Passwordify');
const manifestPath = path.join(extensionRoot, 'manifest.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));

assert.equal(manifest.manifest_version, 3, 'The extension must use Manifest V3.');
assert.deepEqual(
    manifest.permissions,
    ['storage', 'alarms'],
    'Only storage and time-limited cleanup permissions should be requested.',
);
assert.equal(manifest.background.service_worker, 'background.js');
assert.equal(manifest.background.type, 'module');
assert.equal(
    manifest.web_accessible_resources,
    undefined,
    'Vault pages must not be exposed as web-accessible resources.',
);
assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
assert.match(manifest.content_security_policy.extension_pages, /connect-src 'none'/);
assert.match(manifest.content_security_policy.extension_pages, /form-action 'none'/);
assert.match(manifest.content_security_policy.extension_pages, /frame-ancestors 'none'/);

const requiredManifestFiles = [
    manifest.action.default_popup,
    ...Object.values(manifest.icons),
];
for (const relativePath of requiredManifestFiles) {
    await readFile(path.join(extensionRoot, relativePath));
}

const extensionFiles = await readdir(extensionRoot);
const javascriptFiles = extensionFiles.filter((fileName) => fileName.endsWith('.js'));
for (const fileName of javascriptFiles) {
    const fullPath = path.join(extensionRoot, fileName);
    execFileSync(process.execPath, ['--check', fullPath], { stdio: 'pipe' });
    const source = await readFile(fullPath, 'utf8');
    assert.doesNotMatch(source, /Math\.random\s*\(/, `${fileName} uses Math.random().`);
    assert.doesNotMatch(source, /\.innerHTML\s*=/, `${fileName} writes innerHTML.`);
    assert.doesNotMatch(source, /\beval\s*\(/, `${fileName} uses eval().`);
}

const htmlFiles = extensionFiles.filter((fileName) => fileName.endsWith('.html'));
for (const fileName of htmlFiles) {
    const source = await readFile(path.join(extensionRoot, fileName), 'utf8');
    assert.doesNotMatch(source, /<script(?![^>]*\bsrc=)[^>]*>/i, `${fileName} has an inline script.`);

    for (const match of source.matchAll(/<(?:script|link)\b[^>]*(?:src|href)="([^"]+)"/gi)) {
        const reference = match[1];
        if (!reference.includes('://')) {
            await readFile(path.join(extensionRoot, reference));
        }
    }
}

console.log(
    `Extension checks passed (${javascriptFiles.length} JavaScript files, ${htmlFiles.length} HTML files).`,
);
