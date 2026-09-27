// Regenerates the app icons in src-tauri/icons from the SVGs in src-tauri/icons/source.
// icon.ico gets the hand-placed 16 px drawing; every other size comes from wattwall.svg.
// The tray icon is not here: Rust draws it at run time (wattwall-core meter.rs).
// Run from the repository root: node scripts/icons.mjs
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const icons = join("src-tauri", "icons");
const work = mkdtempSync(join(tmpdir(), "wattwall-icons-"));

const cli = join("node_modules", "@tauri-apps", "cli", "tauri.js");
const render = (source, sizes, out) => {
  execFileSync(process.execPath, [cli, "icon", source, "-o", out, "--png", sizes.join(",")], { stdio: "inherit" });
};

// ICO with PNG layers, smallest first. Windows reads PNG layers at every size.
const ico = (layers) => {
  const header = Buffer.alloc(6 + 16 * layers.length);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(layers.length, 4);
  let offset = header.length;
  layers.forEach(([size, data], index) => {
    const entry = 6 + 16 * index;
    header.writeUInt8(size >= 256 ? 0 : size, entry);
    header.writeUInt8(size >= 256 ? 0 : size, entry + 1);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(data.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...layers.map(([, data]) => data)]);
};

try {
  const main = join(work, "main");
  const small = join(work, "small");
  render(join(icons, "source", "wattwall.svg"), [24, 32, 48, 64, 128, 256, 512], main);
  render(join(icons, "source", "wattwall-16.svg"), [16], small);
  const png = (size) => readFileSync(join(size === 16 ? small : main, `${size}x${size}.png`));

  copyFileSync(join(main, "32x32.png"), join(icons, "32x32.png"));
  copyFileSync(join(main, "128x128.png"), join(icons, "128x128.png"));
  copyFileSync(join(main, "256x256.png"), join(icons, "128x128@2x.png"));
  copyFileSync(join(main, "512x512.png"), join(icons, "icon.png"));
  writeFileSync(join(icons, "icon.ico"), ico([16, 24, 32, 48, 64, 256].map((size) => [size, png(size)])));
  console.log("icons written to", icons);
} finally {
  rmSync(work, { recursive: true, force: true });
}
