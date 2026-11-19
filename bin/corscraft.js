#!/usr/bin/env node
/**
 * CORSCraft CLI Entry Point
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */
import("../dist/src/cli.js").then((cli) => {
  cli.run(process.argv.slice(2));
}).catch((err) => {
  console.error("Failed to start CORSCraft:", err);
  process.exit(1);
});
