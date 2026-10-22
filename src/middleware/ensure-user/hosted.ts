import { getAuth, hasHostedAuthConfig } from "@/lib/auth";
import { getActiveOrganizationId } from "@/lib/auth-session";
import { AuthRepository } from "@/server/auth/repositories/AuthRepository";
import { ProjectRepository } from "@/server/features/projects/repositories/ProjectRepository";
import { resolveActiveHostedOrganization } from "@/server/auth/default-hosted-organization";
import { AppError } from "@/server/lib/errors";
import type { EnsuredUserContext } from "./types";

async function requireHostedSession(headers: Headers) {
  if (!hasHostedAuthConfig()) {
    throw new AppError(
      "AUTH_CONFIG_MISSING",
      "Missing Better Auth hosted configuration",
    );
  }

  const session = await getAuth().api.getSession({ headers });

  if (!session?.user?.id || !session.user.email) {
    throw new AppError("UNAUTHENTICATED");
  }

  return session;
}

export async function resolveHostedContext(
  headers: Headers,
  projectId?: string | null,
): Promise<EnsuredUserContext> {
  const session = await requireHostedSession(headers);
  const activeOrganizationId = getActiveOrganizationId(session);

  if (activeOrganizationId) {
    // The session's activeOrganizationId is only a hint (it can outlive a
    // membership: removal, org deletion, cookie cache). The member row is the
    // authorization fact and also carries the caller's role. The project
    // lookup runs alongside it to save a DB round trip; it is scoped to the
    // same organization and only used once the membership is confirmed.
    const [membership, project] = await Promise.all([
      AuthRepository.getMembership(session.user.id, activeOrganizationId),
      projectId
        ? ProjectRepository.getProjectForOrganization(
            projectId,
            activeOrganizationId,
          )
        : null,
    ]);

    if (membership) {
      return {
        userId: session.user.id,
        userEmail: session.user.email,
        emailVerified: session.user.emailVerified ?? false,
        organizationId: activeOrganizationId,
        role: membership.role,
        project: project ?? undefined,
      };
    }
  }

  // No active org, or a stale one: re-resolve from live memberships (creating
  // a default workspace only when the user has none) and repoint the session.
  const authApi = getAuth().api;
  const resolved = await resolveActiveHostedOrganization(
    session.user.id,
    (body) => authApi.createOrganization({ body }),
  );

  await authApi.setActiveOrganization({
    headers,
    body: { organizationId: resolved.organizationId },
  });

  return {
    userId: session.user.id,
    userEmail: session.user.email,
    emailVerified: session.user.emailVerified ?? false,
    organizationId: resolved.organizationId,
    role: resolved.role,
  };
}
