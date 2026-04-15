import { copyFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const source = resolve("manifest.json");
const target = resolve("dist/manifest.json");

await mkdir(dirname(target), { recursive: true });
await copyFile(source, target);
