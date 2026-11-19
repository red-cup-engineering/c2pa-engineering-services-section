export type Article50SigningRequest = Readonly<{
  c2paAgentUrl: string;
  rmnAgentUrl: string;
  caller: string;
  provider: string;
  asset: Buffer | Uint8Array;
  mediaType: string;
  title: string;
  digitalSourceType: string;
  model: string;
  humanOversight: "none" | "human-directed" | "human-reviewed" | "human-authored-with-ai-assistance";
  accessibleDisclosure: string;
  precondition: string;
  postcondition: string;
  refusal: string;
  evidenceRoot: string;
  measures?: readonly unknown[];
  parent?: string | null;
  signal?: AbortSignal;
}>;

export type Article50SigningReceipt = Readonly<{
  disposition: "completion";
  signedAsset: Buffer;
  manifest: Buffer;
  reportBytes: Buffer;
  assetNi: string;
  manifestNi: string;
  accessibleDisclosure: string;
  requestNi: string;
  responseNi: string;
  operationNi: string;
  completionCell: Readonly<Record<string, unknown>>;
  operation: unknown;
  witness: unknown;
}>;

export function signArticle50Asset(request: Article50SigningRequest): Promise<Article50SigningReceipt>;

export const C2PA_BINDING_PREDICATE: string;
export function publishArticle50Asset(request: Readonly<{
  signing: Article50SigningRequest;
  anchor: Readonly<{
    bindingPath: string;
    keystorePath: string;
    passwordFile: string;
    deploymentPath: string;
    rpcUrl: string;
    bundlerUrl: string;
    receiptWaitMs?: number;
  }>;
}>): Promise<Article50SigningReceipt & Readonly<{ evidenceRoot: string; commitment: Readonly<Record<string, unknown>> }>>;
