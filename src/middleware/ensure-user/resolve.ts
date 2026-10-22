import { env } from "cloudflare:workers";
import { getAuthMode, isHostedAuthMode } from "@/lib/auth-mode";
import { resolveCloudflareAccessContext } from "./cloudflareAccess";
import { resolveLocalNoAuthContext } from "./delegated";
import { resolveHostedContext } from "./hosted";
import type { EnsuredUserContext } from "./types";

// Resolves the authenticated user for a request's headers across every auth
// mode. Shared by ensureUserMiddleware (server functions) and raw API routes,
// which can't use function middleware. A projectId lets hosted mode prefetch
// the project alongside its membership check; callers still verify it.
export async function resolveUserContextFromHeaders(
  headers: Headers,
  projectId?: string | null,
): Promise<EnsuredUserContext> {
  const authMode = getAuthMode(env.AUTH_MODE);
  if (authMode === "local_noauth") {
    return resolveLocalNoAuthContext();
  }
  if (isHostedAuthMode(authMode)) {
    return resolveHostedContext(headers, projectId);
  }
  return resolveCloudflareAccessContext(headers);
}
