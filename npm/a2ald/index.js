"use strict";

const os = require("os");
const path = require("path");

const PLATFORM_PACKAGES = {
  "linux-x64":    "@a2al/a2ald-linux-x64",
  "linux-arm64":  "@a2al/a2ald-linux-arm64",
  "darwin-x64":   "@a2al/a2ald-darwin-x64",
  "darwin-arm64": "@a2al/a2ald-darwin-arm64",
  "win32-x64":    "@a2al/a2ald-win32-x64",
};

/**
 * Returns the absolute path to the a2ald binary for the current platform.
 * @throws {Error} if the platform is unsupported or the platform package is not installed.
 */
function getBinaryPath() {
  const key = `${os.platform()}-${os.arch()}`;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) {
    throw new Error(
      `a2ald: unsupported platform ${key}. ` +
      `Supported: ${Object.keys(PLATFORM_PACKAGES).join(", ")}`
    );
  }
  const exe = os.platform() === "win32" ? "a2ald.exe" : "a2ald";
  try {
    return require.resolve(`${pkg}/bin/${exe}`);
  } catch {
    throw new Error(
      `a2ald: platform package ${pkg} is not installed. ` +
      `Try: npm install ${pkg}`
    );
  }
}

module.exports = { getBinaryPath };
