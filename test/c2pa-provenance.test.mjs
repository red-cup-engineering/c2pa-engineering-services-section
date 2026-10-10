import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { Reader } from "@contentauth/c2pa-node";
import { makeNiUri } from "@red-cup-engineering/uri-services-section/ni-uri";
import { aiAssetActId, signAiAsset, validateAiAssetOperation } from "../src/c2pa.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const CALLER = `eip155:31337:0x${"44".repeat(20)}`;
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64");
const ni = (value) => makeNiUri(Buffer.from(value));
const OPERATION = Object.freeze({
  asset: PNG, mediaType: "image/png", title: "article-card.png",
  digitalSourceType: "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
  model: "test-model", humanOversight: "human-reviewed", accessibleDisclosure: "AI-generated image; reviewed by a human editor.",
});

function openssl(args) {
  const result = spawnSync("openssl", args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
}
function signingFixture(root) {
  const leafKey = join(root, "leaf-key.pem"), privateKey = join(root, "leaf-pkcs8.pem"), csr = join(root, "leaf.csr");
  const caKey = join(root, "ca-key.pem"), ca = join(root, "ca.pem"), leaf = join(root, "leaf.pem"), chain = join(root, "chain.pem");
  openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", leafKey]);
  openssl(["pkcs8", "-topk8", "-nocrypt", "-in", leafKey, "-out", privateKey]);
  openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", caKey]);
  openssl(["req", "-new", "-x509", "-key", caKey, "-out", ca, "-days", "1", "-subj", "/CN=C2PA Test Root/O=Emsenn/", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  openssl(["req", "-new", "-key", leafKey, "-out", csr, "-subj", "/CN=C2PA Test Signer/O=Emsenn/"]);
  openssl(["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", leaf, "-days", "1", "-extfile", join(ROOT, "content/c2pa-signer.ext")]);
  writeFileSync(chain, Buffer.concat([readFileSync(leaf), readFileSync(ca)]));
  return { certificatePath: chain, privateKeyPath: privateKey };
}

test("the signing act is identified by its operation and accountable caller", () => {
  assert.equal(aiAssetActId(OPERATION, CALLER), aiAssetActId({ ...OPERATION }, CALLER));
  assert.notEqual(aiAssetActId(OPERATION, CALLER), aiAssetActId({ ...OPERATION, title: "other.png" }, CALLER));
  assert.throws(() => validateAiAssetOperation({ ...OPERATION, accessibleDisclosure: "An image." }), /AI involvement/);
  assert.throws(() => validateAiAssetOperation({ ...OPERATION, mediaType: "text/plain" }), /media profile/);
});

test("official C2PA 2.4 signs and validates an AI asset", async () => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "c2pa-signing-"));
  try {
    const result = await signAiAsset({ operation: OPERATION, caller: CALLER, ...signingFixture(fixtureRoot) });
    assert.equal(ni(result.signedAsset), result.assetNi); assert.equal(ni(result.manifest), result.manifestNi);
    assert.equal(result.act, aiAssetActId(OPERATION, CALLER));
    const reader = await Reader.fromAsset({ buffer: result.signedAsset, mimeType: "image/png" }, { verify: { verify_after_reading: true, verify_trust: false } });
    const report = reader.json(), active = reader.getActive();
    assert.equal(report.validation_state, "Valid"); assert.deepEqual(report.validation_results.activeManifest.failure, []);
    assert.equal(active.assertions.find((item) => item.label === "c2pa.actions.v2").data.actions[0].digitalSourceType, OPERATION.digitalSourceType);
    const article50 = active.assertions.find((item) => item.label === "org.emsenn.article50").data;
    assert.equal(article50.accountableEnterprise, CALLER); assert.equal(article50.senAct, result.act); assert.equal(article50.humanOversight, "human-reviewed");
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
