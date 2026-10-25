import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const write = process.argv.includes("--write");
const unknownArguments = process.argv.slice(2).filter((argument) => argument !== "--write");

if (unknownArguments.length > 0) {
  console.error(`Unknown argument(s): ${unknownArguments.join(", ")}`);
  process.exitCode = 2;
} else {
  const dashboardRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const repositoryRoot = resolve(dashboardRoot, "..");
  const assets = [
    {
      source: resolve(dashboardRoot, "node_modules/bootstrap/dist/css/bootstrap.min.css"),
      destination: resolve(repositoryRoot, "marketing/assets/vendor/bootstrap/bootstrap.min.css")
    },
    {
      source: resolve(dashboardRoot, "node_modules/bootstrap/dist/js/bootstrap.bundle.min.js"),
      destination: resolve(repositoryRoot, "marketing/assets/vendor/bootstrap/bootstrap.bundle.min.js")
    }
  ];

  let hasDrift = false;

  for (const asset of assets) {
    const source = await readRequiredFile(asset.source, repositoryRoot);
    const destination = await readOptionalFile(asset.destination);
    const matches = destination?.equals(source) ?? false;

    if (write && !matches) {
      await mkdir(dirname(asset.destination), { recursive: true });
      await copyFile(asset.source, asset.destination);
      console.log(`Synced ${displayPath(asset.destination, repositoryRoot)} (${digest(source)}).`);
      continue;
    }

    if (!matches) {
      hasDrift = true;
      const actual = destination ? digest(destination) : "missing";
      console.error(
        `${displayPath(asset.destination, repositoryRoot)} differs from installed Bootstrap ` +
        `(expected ${digest(source)}, actual ${actual}).`
      );
      continue;
    }

    console.log(`Verified ${displayPath(asset.destination, repositoryRoot)} (${digest(source)}).`);
  }

  if (hasDrift) {
    console.error("Run `npm run sync:marketing-vendor` from dashboard/ to update the vendored files.");
    process.exitCode = 1;
  }
}

async function readRequiredFile(path, repositoryRoot) {
  try {
    return await readFile(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `${displayPath(path, repositoryRoot)} is missing. Run \`npm ci\` in dashboard/ before checking vendor assets.`,
        { cause: error }
      );
    }
    throw error;
  }
}

async function readOptionalFile(path) {
  try {
    return await readFile(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

function displayPath(path, repositoryRoot) {
  return relative(repositoryRoot, path).replaceAll("\\", "/");
}

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
