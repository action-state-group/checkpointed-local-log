// Fails when the browser entry (dist/browser.js) reaches a Node built-in,
// such as node:crypto, through any import. Run by `npm run build`.
import { isBuiltin } from "node:module";
import { build } from "esbuild";

const reached = new Set();
const result = await build({
  entryPoints: ["dist/browser.js"],
  bundle: true,
  write: false,
  minify: true,
  platform: "browser",
  format: "esm",
  logLevel: "silent",
  plugins: [
    {
      name: "no-node-builtins",
      setup(builder) {
        builder.onResolve({ filter: /.*/ }, (args) => {
          if (isBuiltin(args.path)) {
            reached.add(`${args.path} (from ${args.importer})`);
            return { path: args.path, external: true };
          }
          return undefined;
        });
      },
    },
  ],
});
if (reached.size > 0) {
  console.error(
    `dist/browser.js reaches Node built-ins:\n  ${[...reached].join("\n  ")}`,
  );
  process.exit(1);
}
const bytes = result.outputFiles[0].contents.length;
console.log(`dist/browser.js: no Node built-ins, ${bytes} bytes minified`);
