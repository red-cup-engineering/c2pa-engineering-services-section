/**
 * C2PA 2.4 signing of AI-generated media with an EU AI Act Article 50
 * disclosure assertion. The accountable publisher's on-chain binding of the
 * signed asset to its manifest (publishArticle50Asset) lives in
 * ethereum-engineering-services-section/publish-article50-asset.
 */
import { readFileSync } from "node:fs";
import { Builder, LocalSigner, Reader } from "@contentauth/c2pa-node";
import { semanticId } from "@red-cup-engineering/computer-content-address-engineering-services-section/semiotic-content-address";
import { makeNiUri } from "@red-cup-engineering/uri-services-section/ni-uri";

const SOURCE_TYPES = new Set([
  "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
  "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
  "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia",
  "http://cv.iptc.org/newscodes/digitalsourcetype/compositeSynthetic",
]);
const OVERSIGHT = new Set(["none", "human-directed", "human-reviewed", "human-authored-with-ai-assistance"]);
const ASSERTION = "org.emsenn.article50";

/** The predicate of the (asset, manifest) relation a publisher commits on chain. */
export const C2PA_BINDING_PREDICATE = semanticId({ kind: "predicate", name: "has-c2pa-manifest" });

function fail(message) { throw new Error(message); }
function nonempty(value, label) { if (typeof value !== "string" || value.trim() !== value || value.length === 0) fail(`${label} must be nonempty text`); return value; }
const rawNi = (value) => makeNiUri(Buffer.from(value));

/** Check an AI-asset signing operation against the C2PA media and Article 50 profile. */
export function validateAiAssetOperation(value) {
  if (!Buffer.isBuffer(value.asset) && !(value.asset instanceof Uint8Array)) fail("C2PA asset must be bytes");
  if (!/^(?:image|audio|video)\/[A-Za-z0-9.+-]+$|^application\/pdf$/u.test(nonempty(value.mediaType, "mediaType"))) fail("asset mediaType is outside the C2PA media profile");
  nonempty(value.title, "title"); nonempty(value.model, "model"); nonempty(value.accessibleDisclosure, "accessibleDisclosure");
  if (!/\bAI\b|artificial intelligence/iu.test(value.accessibleDisclosure)) fail("accessible disclosure must identify AI involvement");
  if (!SOURCE_TYPES.has(value.digitalSourceType)) fail("unsupported IPTC AI digital source type");
  if (!OVERSIGHT.has(value.humanOversight)) fail("unsupported human-oversight status");
  return value;
}

/** The semantic identity of one accountable signing act. */
export function aiAssetActId(operation, caller) {
  const { asset, mediaType, title, digitalSourceType, model, humanOversight, accessibleDisclosure } = validateAiAssetOperation(operation);
  return semanticId({ kind: "c2pa.article50-signing", caller: nonempty(caller, "accountable enterprise"), asset: new Uint8Array(asset), mediaType, title, digitalSourceType, model, humanOversight, accessibleDisclosure });
}

/** Sign an AI asset with the official C2PA SDK and verify the signed result. */
export async function signAiAsset({ operation, caller, certificatePath, privateKeyPath, tsaUrl }) {
  const act = aiAssetActId(operation, caller);
  if (!certificatePath || !privateKeyPath) fail("C2PA signing custody is not configured");
  const signer = LocalSigner.newSigner(readFileSync(certificatePath), readFileSync(privateKeyPath), "es256", tsaUrl || undefined);
  const builder = Builder.withJson({
    claim_version: 2,
    claim_generator_info: [{ name: "@red-cup-engineering/c2pa-services-section", version: "1.0.0" }],
    title: operation.title,
    format: operation.mediaType,
    assertions: [],
    resources: { resources: {} },
  }, { verify: { verify_after_signing: true } });
  builder.setIntent({ create: operation.digitalSourceType });
  builder.addAssertion(ASSERTION, {
    artificialIntelligence: true,
    disclosure: operation.accessibleDisclosure,
    digitalSourceType: operation.digitalSourceType,
    model: operation.model,
    humanOversight: operation.humanOversight,
    accountableEnterprise: caller,
    senAct: act,
  }, "Cbor");
  const destination = { buffer: null };
  const manifest = builder.sign(signer, { buffer: Buffer.from(operation.asset), mimeType: operation.mediaType }, destination);
  if (!Buffer.isBuffer(destination.buffer) || destination.buffer.length === 0) fail("official C2PA SDK returned no signed asset");
  const reader = await Reader.fromAsset({ buffer: destination.buffer, mimeType: operation.mediaType }, { verify: { verify_after_reading: true, verify_trust: false } });
  const report = reader?.json(), active = reader?.getActive();
  const failures = report?.validation_results?.activeManifest?.failure ?? [];
  const assertion = active?.assertions?.find((item) => item.label === ASSERTION)?.data;
  const action = active?.assertions?.find((item) => item.label === "c2pa.actions.v2")?.data?.actions?.[0];
  if (!reader?.isEmbedded() || !["Valid", "Trusted"].includes(report?.validation_state) || failures.length !== 0) fail("signed C2PA asset failed official SDK validation");
  if (action?.action !== "c2pa.created" || action.digitalSourceType !== operation.digitalSourceType) fail("C2PA creation action lost its declared AI source type");
  if (assertion?.disclosure !== operation.accessibleDisclosure || assertion?.model !== operation.model || assertion?.accountableEnterprise !== caller || assertion?.senAct !== act) fail("C2PA Article 50 assertion lost request semantics");
  const reportBytes = Buffer.from(JSON.stringify(report), "utf8");
  return Object.freeze({ act, signedAsset: destination.buffer, manifest, reportBytes, assetNi: rawNi(destination.buffer), manifestNi: rawNi(manifest), accessibleDisclosure: operation.accessibleDisclosure });
}
