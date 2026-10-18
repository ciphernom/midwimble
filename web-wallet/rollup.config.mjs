// Bundles light_client.js and the libp2p it uses into one ES module the page
// imports: `npm ci && npm run bundle`.
//
// libp2p ships browser-specific entry points; without `browser: true` and
// these conditions the resolver can pick Node builds that reference
// 'dgram'/'net' and fail at runtime instead of at build time.

import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
    input: 'light_client.js',
    output: {
        file: 'light_client.bundle.js',
        format: 'es',
        // One file, even if a dependency imports dynamically.
        inlineDynamicImports: true,
    },
    plugins: [
        resolve({
            preferBuiltins: false,
            browser: true,
            exportConditions: ['browser', 'import', 'module', 'default'],
        }),
        commonjs(),
    ],
    // libp2p is full of benign circular imports.
    onwarn(warning, warn) {
        if (warning.code !== 'CIRCULAR_DEPENDENCY') warn(warning);
    },
};
