import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { writeFileSync, mkdirSync, readFileSync } from 'fs';

const require = createRequire(import.meta.url);
const Ajv2020 = require('ajv/dist/2020');
const standaloneCode = require('ajv/dist/standalone').default;
const addFormats = require('ajv-formats');

const __dirname = dirname(fileURLToPath(import.meta.url));

function readSchema(relPath) {
    return JSON.parse(readFileSync(join(__dirname, relPath), 'utf8'));
}

// AJV standalone always emits require() for its runtime helpers even with esm:true.
// Replace them with proper ESM imports so the output works in browser bundles.
//
// Two patterns appear in AJV output:
//   require("ajv-formats/dist/formats").fullFormats.uri
//     → import { fullFormats as _dep } from 'ajv-formats/dist/formats'; ... _dep.uri
//   require("ajv/dist/runtime/ucs2length").default
//     → import + unwrap shim (see below)
//
// Named imports are used for non-default properties because ajv-formats has no
// exports.default — a default import would resolve to undefined in Vite/esbuild.
//
// For `.default` properties: esbuild/Vite wrap CJS modules with __toESM(mod, 1)
// which sets target.default = the whole exports object (not exports.default), so
// `import X from 'mod'` yields the entire exports rather than the exported function.
// We work around this by importing under a raw alias then unwrapping at module level:
//   import _dep_raw from 'mod';
//   const _dep = typeof _dep_raw === 'function' ? _dep_raw : (_dep_raw?.default ?? _dep_raw);
function toEsm(code) {
    const importMap = new Map(); // "mod::prop" -> { mod, prop, isDefault, alias }

    const result = code.replace(
        /require\("([^"]+)"\)\.([\w]+)((?:\.[\w]+)*)/g,
        (_match, mod, prop, rest) => {
            const key = `${mod}::${prop}`;
            if (!importMap.has(key)) {
                importMap.set(key, {
                    mod,
                    prop,
                    isDefault: prop === 'default',
                    alias: `_ajv_dep_${importMap.size}`,
                });
            }
            const { alias } = importMap.get(key);
            return `${alias}${rest}`;
        }
    );

    const importLines = [...importMap.values()]
        .map(({ mod, prop, isDefault, alias }) => {
            if (isDefault) {
                const rawAlias = `${alias}_raw`;
                return [
                    `import ${rawAlias} from '${mod}';`,
                    `const ${alias} = typeof ${rawAlias} === 'function' ? ${rawAlias} : (${rawAlias}?.default ?? ${rawAlias});`,
                ].join('\n');
            }
            return `import { ${prop} as ${alias} } from '${mod}';`;
        })
        .join('\n');

    return importLines ? `${importLines}\n${result}` : result;
}

function compileValidator(schema, opts, extraSchemas = []) {
    const ajvEsm = new Ajv2020({ ...opts, code: { source: true, esm: true } });
    addFormats(ajvEsm);
    extraSchemas.forEach(s => ajvEsm.addSchema(s));
    const validateEsm = ajvEsm.compile(schema);

    const ajvCjs = new Ajv2020({ ...opts, code: { source: true, esm: false } });
    addFormats(ajvCjs);
    extraSchemas.forEach(s => ajvCjs.addSchema(s));
    const validateCjs = ajvCjs.compile(schema);

    return {
        esm: toEsm(standaloneCode(ajvEsm, validateEsm)),
        cjs: standaloneCode(ajvCjs, validateCjs),
    };
}

function write(distDir, srcDir, name, { esm, cjs }) {
    mkdirSync(distDir, { recursive: true });
    writeFileSync(join(distDir, `${name}.js`), esm);
    writeFileSync(join(srcDir, `${name}.cjs`), cjs);
}

const strict = { allErrors: true, strict: true, validateFormats: true, validateSchema: true };
const loose  = { allErrors: true, strict: false, validateFormats: true, validateSchema: true };

// alberta-wallet
const albertaCredentialIssuerSchema = readSchema('../src/alberta-wallet/schemas/alberta-credential-issuer-v1.json');
const credentialDisplaySchema       = readSchema('../src/alberta-wallet/schemas/card-display-v1.json');
const abDistDir = join(__dirname, '../dist/alberta-wallet/compiled');
const abSrcDir  = join(__dirname, '../src/alberta-wallet/compiled');
write(abDistDir, abSrcDir, 'validate-alberta-credential-issuer', compileValidator(albertaCredentialIssuerSchema, strict));
write(abDistDir, abSrcDir, 'validate-credential-display', compileValidator(credentialDisplaySchema, loose));

// openid-federation
const entityStatementSchema = readSchema('../src/openid-federation/schemas/entity-statement-v1.json');
const endpointErrorSchema   = readSchema('../src/openid-federation/schemas/endpoint-error-v1.json');
const fedDistDir = join(__dirname, '../dist/openid-federation/compiled');
const fedSrcDir  = join(__dirname, '../src/openid-federation/compiled');
write(fedDistDir, fedSrcDir, 'validate-entity-statement', compileValidator(entityStatementSchema, strict, [endpointErrorSchema, albertaCredentialIssuerSchema]));
write(fedDistDir, fedSrcDir, 'validate-endpoint-error', compileValidator(endpointErrorSchema, strict));

// sdjwt
const sdJwtSchema   = readSchema('../src/sdjwt/schemas/sd-jwt-v1.json');
const vcSdJwtSchema = readSchema('../src/sdjwt/schemas/vc+sd-jwt-v1.json');
const sdDistDir = join(__dirname, '../dist/sdjwt/compiled');
const sdSrcDir  = join(__dirname, '../src/sdjwt/compiled');
write(sdDistDir, sdSrcDir, 'validate-sd-jwt', compileValidator(sdJwtSchema, strict));
write(sdDistDir, sdSrcDir, 'validate-vc-sd-jwt', compileValidator(vcSdJwtSchema, strict, [sdJwtSchema]));

console.log('Precompiled AJV validators written to dist/{alberta-wallet,openid-federation,sdjwt}/compiled/');
