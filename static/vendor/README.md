# Vendored libraries

Built into the binary and served by core-pulse itself. Nothing is loaded from a CDN.

| File | Library | License | Source | SHA-256 |
|---|---|---|---|---|
| `htmx-2.0.4.min.js` | [htmx](https://htmx.org) 2.0.4 | 0BSD, `LICENSE.htmx` | `npm/htmx.org@2.0.4/dist/htmx.min.js` | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| `htmx-ext-sse-2.2.2.js` | htmx SSE extension 2.2.2 | 0BSD, `LICENSE.htmx-ext-sse` | `npm/htmx-ext-sse@2.2.2/sse.js` | `83eca6fa0611fe2b0bf1700b424b88b5eced38ef448ef9760a2ea08fbc875611` |
| `uplot-1.6.31.iife.min.js` | [uPlot](https://github.com/leeoniya/uPlot) 1.6.31 | MIT, `LICENSE.uplot` | `npm/uplot@1.6.31/dist/uPlot.iife.min.js` | `2d27e8ad3d228164525ce213f9dc716f39b4e3aee0cc773fb3491c96cf4921a2` |
| `uplot-1.6.31.min.css` | uPlot 1.6.31 | MIT, `LICENSE.uplot` | `npm/uplot@1.6.31/dist/uPlot.min.css` | `df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04` |

Sources are paths on the npm registry. To update, download the new version,
check its hash, and change the file names here, in `src/web/assets.rs` and in
`templates/base.html`.
