#!/usr/bin/env node

import { resolve } from "node:path";
import { serveContractedAgent } from "@red-cup-engineering/a2a-contracted-agent-service";

const ROOT = resolve(import.meta.dirname, "..");
serveContractedAgent({
  port: Number(process.env.PORT ?? "8792"), host: process.env.HOST ?? "127.0.0.1", baseUrl: process.env.BASE_URL,
  agentCard: resolve(ROOT, "content/agent-cards/c2pa-provenance.json"), executor: process.execPath,
  executorArgs: [resolve(ROOT, "scripts/execute-a2a-task.mjs")]
}).then(({ baseUrl }) => process.stdout.write(`${baseUrl}\n`)).catch((error) => { process.stderr.write(`${error.stack ?? error.message}\n`); process.exitCode = 1; });
