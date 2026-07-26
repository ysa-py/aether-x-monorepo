/**
 * App-level type aliases derived from the GENERATED OpenAPI types
 * (`types/api.generated.ts`, produced by `npm run generate:api` from the Go
 * control-plane spec). The REST response shapes are NEVER hand-maintained here,
 * so backend and frontend cannot drift. App-only union/derivation types stay.
 */
import type { components } from "./api.generated";

type Schema = components["schemas"];

// ---- Generated-backed response shapes -------------------------------------
export type CoreStatus = Schema["CoreStatus"];
export type CoreInstance = Schema["CoreInstance"];
export type ListCoresResponse = Schema["ListCoresResponse"];
export type RouteResponse = Schema["RouteResponse"];
export type IssueTokenResponse = Schema["IssueTokenResponse"];
export type TokenClaims = Schema["TokenClaims"];
export type VerifyTokenResponse = Schema["VerifyTokenResponse"];
export type AuditRootResponse = Schema["AuditRootResponse"];

// ---- App-level derivations ------------------------------------------------
/** The action label the REST API returns (DIRECT/PROXY/BLOCK/...). */
export type RouteActionLabel = RouteResponse["action"];

/** Proto-side route action (not used over REST; kept for symmetry). */
export type RouteAction =
  | "ROUTE_ACTION_UNSPECIFIED"
  | "ROUTE_ACTION_DIRECT"
  | "ROUTE_ACTION_PROXY"
  | "ROUTE_ACTION_BLOCK";

/** Connection state derived from TanStack Query status (app-only). */
export type ConnectionState = "connected" | "reconnecting" | "offline";
