import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Builder, LocalSigner, Reader } from "@contentauth/c2pa-node";
import { admitNormalizedSemanticContent, EMPTY_WITNESS_ROOT, identifyNormalizedSemanticContent } from "@red-cup-engineering/computer-code-engineering-services-section/semiotic-expression-notation/semantic-content-identity";
import { inferTerm } from "@red-cup-engineering/computer-code-engineering-services-section/semiotic-expression-notation/runtime";
import { makeNiUri } from "@red-cup-engineering/uri-services-section/ni-uri";

const BASE = ["base"], EFFECT = ["effect"];
const EVIDENCE = BASE;
const WIT = ["wit", ["grounded", EFFECT, EVIDENCE]];
const SOURCE_TYPES = new Set([
  "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
  "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
  "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia",
  "http://cv.iptc.org/newscodes/digitalsourcetype/compositeSynthetic"
]);
const OVERSIGHT = new Set(["none", "human-directed", "human-reviewed", "human-authored-with-ai-assistance"]);

export function identifyC2paTerm(term, objectKind) { return identifyNormalizedSemanticContent({ objectKind, semanticType: inferTerm(term), term, witnessRoot: EMPTY_WITNESS_ROOT }); }
export function admitC2paTerm(bytes, token) { return admitNormalizedSemanticContent(bytes, token); }
export const C2PA_LAW = identifyC2paTerm(["mark", "org.emsenn.c2pa.article50-media-signing.v1"], "c2pa.law").token;
const productType = (...members) => members.slice(0, -1).reduceRight((right, left) => ["prod", left, right], members.at(-1));
export const C2PA_AUTHORIZATION_TYPE = productType(BASE, BASE, BASE, BASE, BASE, BASE);
export const C2PA_OPERATION_TYPE = productType(BASE, BASE, BASE, BASE, BASE, BASE, BASE);
export const C2PA_REQUEST_TYPE = productType(C2PA_AUTHORIZATION_TYPE, C2PA_OPERATION_TYPE);
export const C2PA_PAYLOAD_TYPE = productType(BASE, BASE, BASE, BASE, BASE, BASE, BASE);
export const C2PA_RESPONSE_TYPE = productType(productType(EFFECT, C2PA_REQUEST_TYPE), productType(WIT, C2PA_PAYLOAD_TYPE));

function fail(message) { throw new Error(message); }
function tuple(values) { return values.length === 1 ? values[0] : ["pair", values[0], tuple(values.slice(1))]; }
function fields(term, count) { if (count === 1) return [term]; if (term?.[0] !== "pair") fail("malformed C2PA RMN tuple"); return [term[1], ...fields(term[2], count - 1)]; }
function mark(value) { if (typeof value !== "string") fail("C2PA RMN Mark must carry text"); return ["mark", value]; }
function marked(term) { if (term?.[0] !== "mark" || typeof term[1] !== "string") fail("expected text-bearing C2PA RMN Mark"); return term[1]; }
const BYTE_PREFIX = "base64url:";
/** Encodes arbitrary octets in the standard base64url text alphabet for RMN Mark. */
export function encodeC2paBytes(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) fail("C2PA byte carrier requires bytes");
  return `${BYTE_PREFIX}${Buffer.from(value).toString("base64url")}`;
}
/** Decodes only canonical base64url text so byte identity has one RMN spelling. */
export function decodeC2paBytes(value) {
  if (typeof value !== "string" || !value.startsWith(BYTE_PREFIX)) fail("C2PA byte Mark must use base64url text");
  const encoded = value.slice(BYTE_PREFIX.length);
  if (!/^[A-Za-z0-9_-]*$/u.test(encoded)) fail("C2PA byte Mark has invalid base64url text");
  const bytes = Buffer.from(encoded, "base64url");
  if (bytes.toString("base64url") !== encoded) fail("C2PA byte Mark is not canonical base64url text");
  return bytes;
}
function byteMark(value) { return mark(encodeC2paBytes(value)); }
function markedBytes(term) { return decodeC2paBytes(marked(term)); }
function niTerm(value) { return mark(value); }
function niValue(term) { return marked(term); }
const rawNi = (value) => makeNiUri(Buffer.from(value));
function nonempty(value, label) { if (typeof value !== "string" || value.trim() !== value || value.length === 0) fail(`${label} must be nonempty text`); return value; }
function mediaType(value) { nonempty(value, "mediaType"); if (!/^(?:image|audio|video)\/[A-Za-z0-9.+-]+$|^application\/pdf$/u.test(value)) fail("asset mediaType is outside the C2PA media profile"); return value; }

export function encodeC2paOperation(value) {
  if (!Buffer.isBuffer(value.asset) && !(value.asset instanceof Uint8Array)) fail("C2PA asset must be bytes");
  mediaType(value.mediaType); nonempty(value.title, "title"); nonempty(value.model, "model"); nonempty(value.accessibleDisclosure, "accessibleDisclosure");
  if (!/\bAI\b|artificial intelligence/iu.test(value.accessibleDisclosure)) fail("accessible disclosure must identify AI involvement");
  if (!SOURCE_TYPES.has(value.digitalSourceType)) fail("unsupported IPTC AI digital source type");
  if (!OVERSIGHT.has(value.humanOversight)) fail("unsupported human-oversight status");
  return tuple([byteMark(value.asset), mark(value.mediaType), mark(value.title), mark(value.digitalSourceType), mark(value.model), mark(value.humanOversight), mark(value.accessibleDisclosure)]);
}

export function decodeC2paOperation(term) {
  const [asset, media, title, sourceType, model, oversight, disclosure] = fields(term, 7);
  const value = { asset: markedBytes(asset), mediaType: marked(media), title: marked(title), digitalSourceType: marked(sourceType), model: marked(model), humanOversight: marked(oversight), accessibleDisclosure: marked(disclosure) };
  encodeC2paOperation(value);
  return value;
}

export function encodeC2paAuthorization({ law, caller, provider, precondition, postcondition, refusal }) {
  [law, caller, provider, precondition, postcondition, refusal].forEach((value) => nonempty(value, "C2PA authorization commitment"));
  return tuple([mark(law), mark(caller), mark(provider), mark(precondition), mark(postcondition), mark(refusal)]);
}

export function decodeC2paAuthorization(term) {
  const [law, caller, provider, precondition, postcondition, refusal] = fields(term, 6);
  return { law: marked(law), caller: marked(caller), provider: marked(provider), precondition: marked(precondition), postcondition: marked(postcondition), refusal: marked(refusal) };
}

export async function signAiAsset({ operation, caller, operationNi, certificatePath, privateKeyPath, tsaUrl }) {
  const value = decodeC2paOperation(operation);
  nonempty(caller, "accountable enterprise"); nonempty(operationNi, "RMN act identity");
  if (!certificatePath || !privateKeyPath) fail("C2PA signing custody is not configured");
  const certificate = readFileSync(certificatePath), privateKey = readFileSync(privateKeyPath);
  const signer = LocalSigner.newSigner(certificate, privateKey, "es256", tsaUrl || undefined);
  const builder = Builder.withJson({
    claim_version: 2,
    claim_generator_info: [{ name: "@red-cup-engineering/c2pa-services-section", version: "1.0.0" }],
    title: value.title,
    format: value.mediaType,
    assertions: [],
    resources: { resources: {} }
  }, { verify: { verify_after_signing: true } });
  builder.setIntent({ create: value.digitalSourceType });
  builder.addAssertion("org.emsenn.article50", {
    artificialIntelligence: true,
    disclosure: value.accessibleDisclosure,
    digitalSourceType: value.digitalSourceType,
    model: value.model,
    humanOversight: value.humanOversight,
    accountableEnterprise: caller,
    senAct: operationNi
  }, "Cbor");
  const destination = { buffer: null };
  const manifest = builder.sign(signer, { buffer: value.asset, mimeType: value.mediaType }, destination);
  if (!Buffer.isBuffer(destination.buffer) || destination.buffer.length === 0) fail("official C2PA SDK returned no signed asset");
  const reader = await Reader.fromAsset({ buffer: destination.buffer, mimeType: value.mediaType }, { verify: { verify_after_reading: true, verify_trust: false } });
  const report = reader?.json(), active = reader?.getActive();
  const failures = report?.validation_results?.activeManifest?.failure ?? [];
  const assertion = active?.assertions?.find((item) => item.label === "org.emsenn.article50")?.data;
  const action = active?.assertions?.find((item) => item.label === "c2pa.actions.v2")?.data?.actions?.[0];
  if (!reader?.isEmbedded() || !["Valid", "Trusted"].includes(report?.validation_state) || failures.length !== 0) fail("signed C2PA asset failed official SDK validation");
  if (action?.action !== "c2pa.created" || action.digitalSourceType !== value.digitalSourceType) fail("C2PA creation action lost its declared AI source type");
  if (assertion?.disclosure !== value.accessibleDisclosure || assertion?.model !== value.model || assertion?.accountableEnterprise !== caller || assertion?.senAct !== operationNi) fail("C2PA Article 50 assertion lost request semantics");
  const reportBytes = Buffer.from(JSON.stringify(report), "utf8");
  return { signedAsset: destination.buffer, manifest, reportBytes, assetNi: rawNi(destination.buffer), manifestNi: rawNi(manifest), accessibleDisclosure: value.accessibleDisclosure };
}

export function encodeC2paPayload({ disposition, signedAsset, manifest, reportBytes, assetNi, manifestNi, accessibleDisclosure }) {
  return tuple([mark(disposition), byteMark(signedAsset), byteMark(manifest), niTerm(assetNi), niTerm(manifestNi), byteMark(reportBytes), mark(accessibleDisclosure)]);
}

export function decodeC2paPayload(term) {
  const [disposition, signedAsset, manifest, assetNi, manifestNi, report, disclosure] = fields(term, 7);
  return { disposition: marked(disposition), signedAsset: markedBytes(signedAsset), manifest: markedBytes(manifest), assetNi: niValue(assetNi), manifestNi: niValue(manifestNi), reportBytes: markedBytes(report), accessibleDisclosure: marked(disclosure) };
}

export function decodeC2paResponse(term) {
  const [bundle, result] = fields(term, 2), [effect, request] = fields(bundle, 2), [authorization, operation] = fields(request, 2), [witness, payload] = fields(result, 2);
  if (effect?.[0] !== "effect" || witness?.[0] !== "witness") fail("malformed C2PA response proof");
  return { completionCell: effect[1], authorization: decodeC2paAuthorization(authorization), operation: decodeC2paOperation(operation), operationTerm: operation, requestTerm: request, witness, ...decodeC2paPayload(payload) };
}
