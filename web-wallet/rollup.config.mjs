// Bundles the npm code the wallet runs into files the page loads as they are
// (`npm ci && npm run bundle`):
//
// - light_client.bundle.js: light_client.js and the libp2p it uses, one ES
//   module the page imports;
// - qr_reader.bundle.js: qr_reader.js and jsQR, the worker that reads QR
//   codes for the send form's "scan" button.
//
// libp2p ships browser-specific entry points; without `browser: true` and
// these conditions the resolver can pick Node builds that reference
// 'dgram'/'net' and fail at runtime instead of at build time.

import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

const plugins = () => [
    resolve({
        preferBuiltins: false,
        browser: true,
        exportConditions: ['browser', 'import', 'module', 'default'],
    }),
    commonjs(),
];

export default [
    {
        input: 'light_client.js',
        output: {
            file: 'light_client.bundle.js',
            format: 'es',
            // One file, even if a dependency imports dynamically.
            inlineDynamicImports: true,
        },
        plugins: plugins(),
        // libp2p is full of benign circular imports.
        onwarn(warning, warn) {
            if (warning.code !== 'CIRCULAR_DEPENDENCY') warn(warning);
        },
    },
    {
        input: 'qr_reader.js',
        output: {
            file: 'qr_reader.bundle.js',
            format: 'es',
            banner: '/*! jsQR 1.4.0, https://github.com/cozmo/jsQR, Apache License 2.0 */',
        },
        plugins: plugins(),
    },
];
