#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ROLE_AGENT, ROLE_USER } from "@red-cup-engineering/a2a-services-section/a2a-client";
import { extractSenPart, senPart } from "@red-cup-engineering/a2a-services-section/rmn-part";
import { conformTerm } from "@red-cup-engineering/relation-model-notation-conformance/client";
import { assayWitTransition } from "@red-cup-engineering/computer-inference-engine/fabric/effect-assay";
import { makeNiUri } from "@red-cup-engineering/uri-services-section/ni-uri";
import { assayEffectTransition } from "@red-cup-engineering/computer-code-engineering-services-section/semiotic-expression-notation/runtime";
import { circuitInterfaceFromAgentCard } from "@red-cup-engineering/hierarchical-circuit-law";
import { admitC2paTerm, C2PA_LAW, C2PA_REQUEST_TYPE, C2PA_RESPONSE_TYPE, decodeC2paAuthorization, decodeC2paOperation, encodeC2paBytes, encodeC2paPayload, identifyC2paTerm, signAiAsset } from "../src/c2pa-rmn.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ACCOUNT = circuitInterfaceFromAgentCard(JSON.parse(readFileSync(join(ROOT, "content/agent-cards/c2pa-provenance.json"), "utf8"))).account;
function senAgent() { if (!process.env.SEN_CONFORMANCE_AGENT) throw new Error("SEN_CONFORMANCE_AGENT must name the hired RMN provider's A2A 1.0 Agent Card"); return process.env.SEN_CONFORMANCE_AGENT; }
function witAgent() { if (!process.env.WIT_TRANSITION_ASSAY_AGENT) throw new Error("WIT_TRANSITION_ASSAY_AGENT must name the hired WIT transition provider's signed A2A 1.0 Agent Card"); return process.env.WIT_TRANSITION_ASSAY_AGENT; }
const rawNi = (value) => makeNiUri(Buffer.from(value));

const source = (JSON.parse(readFileSync(0, "utf8")));
if (source.role !== ROLE_USER) throw new Error("C2PA provenance requires an A2A ROLE_USER message");
const input = extractSenPart(source.parts);
const request = admitC2paTerm(input.bytes, input.ni).envelope.settledBody, requestType = ["prod", ["effect"], C2PA_REQUEST_TYPE];
if (request?.[0] !== "ascribe" || request.length !== 3 || JSON.stringify(request[1]) !== JSON.stringify(requestType)) throw new Error("C2PA A2A ingress requires one canonical explicitly typed RMN effect bundle");
const proposal = await conformTerm({ agentUrl: senAgent(), term: request[2], expectedType: request[1] });
const cell = proposal.effectCell, requestTerm = proposal.normalForm[2], [authorizationTerm, operation] = [requestTerm[1], requestTerm[2]], authorization = decodeC2paAuthorization(authorizationTerm), operationValue = decodeC2paOperation(operation);
if (authorization.law !== C2PA_LAW || authorization.provider !== ACCOUNT || authorization.caller !== cell.caller || authorization.provider !== cell.provider) throw new Error("C2PA request authorization is not addressed to this law, account, and service scale");
if (cell.outcome.positiveEvidence || cell.outcome.negativeEvidence) throw new Error("C2PA proposal must enter at FOUR-bottom");

let disposition = "completion", output;
try {
  output = await signAiAsset({ operation, caller: cell.caller, operationNi: identifyC2paTerm(requestTerm, "c2pa.operation").token, certificatePath: process.env.C2PA_SIGNING_CERTIFICATE, privateKeyPath: process.env.C2PA_SIGNING_PRIVATE_KEY, tsaUrl: process.env.C2PA_TSA_URL });
} catch (error) {
  disposition = "refused";
  const reportBytes = Buffer.from(error instanceof Error ? error.message : String(error), "utf8"), empty = Buffer.alloc(0);
  output = { signedAsset: empty, manifest: empty, reportBytes, assetNi: rawNi(operationValue.asset), manifestNi: rawNi(empty), accessibleDisclosure: `C2PA signing refused: ${reportBytes.toString("utf8")}` };
}
const evidenceTerm = ["mark", encodeC2paBytes(disposition === "completion" ? output.manifest : output.reportBytes)];
const evidence = await conformTerm({ agentUrl: senAgent(), term: evidenceTerm, expectedType: ["base"] });
const measures = [...cell.measures.filter(({ dimension }) => !["content-byte", "provenance-manifest"].includes(dimension)),
  { dimension: "content-byte", quantity: String(output.signedAsset.length), unit: "byte" },
  { dimension: "provenance-manifest", quantity: disposition === "completion" ? "1" : "0", unit: "c2pa-manifest" }];
const completionCell = { ...cell, evidenceRoot: evidence.term, outcome: { positiveEvidence: disposition === "completion", negativeEvidence: disposition === "refused" }, measures };
const transition = await assayWitTransition({ agentUrl: witAgent(), proposalCell: cell, completionCell, evidence: evidence.term });
if (transition.evidence !== evidence.term || transition.outcome?.positiveEvidence !== completionCell.outcome.positiveEvidence || transition.outcome?.negativeEvidence !== completionCell.outcome.negativeEvidence) throw new Error("WIT transition receipt does not attest the exact C2PA completion");
const senTransition = assayEffectTransition({ proposalCell: cell, completionCell, evidence: evidence.term });
const responseTerm = ["pair", ["pair", ["effect", completionCell], requestTerm], ["pair", senTransition.witnessTerm, encodeC2paPayload({ disposition, ...output })]];
const response = await conformTerm({ agentUrl: senAgent(), term: responseTerm, expectedType: C2PA_RESPONSE_TYPE });
const message = ({ messageId: randomUUID(), contextId: source.contextId, taskId: source.taskId, role: ROLE_AGENT,
  parts: [senPart(identifyC2paTerm(response.response, "c2pa.response").bytes, "c2pa-provenance.rmn.cbor"), { content: { $case: "text", value: output.accessibleDisclosure }, metadata: {}, filename: "", mediaType: "text/plain" }],
  metadata: { disposition, proposalNi: proposal.term, completionNi: response.term, witnessNi: senTransition.witness, assetNi: output.assetNi, manifestNi: output.manifestNi, c2pa: "2.4" }, extensions: [], referenceTaskIds: [] });
process.stdout.write(`${JSON.stringify(message)}\n`);
