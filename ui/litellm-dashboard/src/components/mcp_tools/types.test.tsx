import { describe, it, expect } from "vitest";
import {
  AUTH_TYPE,
  OAUTH_FLOW,
  MCP_OAUTH2_FLOW_M2M,
  TRANSPORT,
  handleTransport,
  handleAuth,
  getMcpOAuthMode,
  getOAuthAuthorizationIdentity,
  isHeldOAuthTokenStale,
  preservedAdminCredentials,
  oauth2FlowToFormValue,
  preservedDeclaredAppCredentials,
  withoutMintedTokenCredentials,
  credentialAuthClass,
} from "./types";

describe("getOAuthAuthorizationIdentity", () => {
  // Regression: the identity used to pick the audience from spec_path only when values.transport was
  // OPENAPI, but the create form keeps transport in component state, so values.transport was absent and
  // spec_path edits on OpenAPI servers never invalidated a held token.
  it("changes when spec_path changes even when transport is absent from form values", () => {
    const authorized = { auth_type: AUTH_TYPE.OAUTH2, spec_path: "https://a.example.com/openapi.json" };
    const edited = { auth_type: AUTH_TYPE.OAUTH2, spec_path: "https://b.example.com/openapi.json" };
    expect(getOAuthAuthorizationIdentity(edited)).not.toBe(getOAuthAuthorizationIdentity(authorized));
    expect(isHeldOAuthTokenStale(edited, getOAuthAuthorizationIdentity(authorized))).toBe(true);
  });

  it("changes when url changes", () => {
    const authorized = { auth_type: AUTH_TYPE.OAUTH2, url: "https://a.example.com/mcp" };
    const edited = { auth_type: AUTH_TYPE.OAUTH2, url: "https://b.example.com/mcp" };
    expect(getOAuthAuthorizationIdentity(edited)).not.toBe(getOAuthAuthorizationIdentity(authorized));
  });

  // Regression: upstream_resource is the RFC 8707 audience the upstream token is minted for, so
  // editing it strands a held token on the previous audience. It must invalidate here for the same
  // reason it belongs in the backend's mcp_oauth_token_identity, which this function mirrors.
  it("changes when the upstream_resource credential changes", () => {
    const authorized = {
      auth_type: AUTH_TYPE.OAUTH2,
      url: "https://a.example.com/mcp",
      credentials: { client_id: "cid", upstream_resource: "api://audience-one" },
    };
    const retargeted = {
      auth_type: AUTH_TYPE.OAUTH2,
      url: "https://a.example.com/mcp",
      credentials: { client_id: "cid", upstream_resource: "api://audience-two" },
    };
    const unset = {
      auth_type: AUTH_TYPE.OAUTH2,
      url: "https://a.example.com/mcp",
      credentials: { client_id: "cid" },
    };
    expect(getOAuthAuthorizationIdentity(retargeted)).not.toBe(getOAuthAuthorizationIdentity(authorized));
    expect(getOAuthAuthorizationIdentity(unset)).not.toBe(getOAuthAuthorizationIdentity(authorized));
    expect(isHeldOAuthTokenStale(retargeted, getOAuthAuthorizationIdentity(authorized))).toBe(true);
  });

  it("is stable across non-mint fields", () => {
    const authorized = { auth_type: AUTH_TYPE.OAUTH2, url: "https://a.example.com/mcp", server_name: "one" };
    const renamed = { auth_type: AUTH_TYPE.OAUTH2, url: "https://a.example.com/mcp", server_name: "two" };
    expect(getOAuthAuthorizationIdentity(renamed)).toBe(getOAuthAuthorizationIdentity(authorized));
    expect(isHeldOAuthTokenStale(renamed, getOAuthAuthorizationIdentity(authorized))).toBe(false);
  });
});

describe("handleTransport", () => {
  it("should default to SSE when transport is null", () => {
    expect(handleTransport(null)).toBe(TRANSPORT.SSE);
  });

  it("should default to SSE when transport is undefined", () => {
    expect(handleTransport(undefined)).toBe(TRANSPORT.SSE);
  });

  it("should return openapi when specPath is present and transport is not stdio", () => {
    expect(handleTransport("http", "/spec.yaml")).toBe(TRANSPORT.OPENAPI);
  });

  it("should keep stdio even when specPath is present", () => {
    expect(handleTransport(TRANSPORT.STDIO, "/spec.yaml")).toBe(TRANSPORT.STDIO);
  });

  it("should return the transport as-is when no specPath", () => {
    expect(handleTransport("http")).toBe("http");
  });
});

describe("handleAuth", () => {
  it("should default to NONE when authType is null", () => {
    expect(handleAuth(null)).toBe(AUTH_TYPE.NONE);
  });

  it("should default to NONE when authType is undefined", () => {
    expect(handleAuth(undefined)).toBe(AUTH_TYPE.NONE);
  });

  it("should return the provided auth type", () => {
    expect(handleAuth(AUTH_TYPE.OAUTH2)).toBe("oauth2");
  });
});

describe("constants", () => {
  it("should define all expected auth types", () => {
    expect(AUTH_TYPE.NONE).toBe("none");
    expect(AUTH_TYPE.API_KEY).toBe("api_key");
    expect(AUTH_TYPE.BEARER_TOKEN).toBe("bearer_token");
    expect(AUTH_TYPE.OAUTH2).toBe("oauth2");
  });

  it("should define all expected transport types", () => {
    expect(TRANSPORT.SSE).toBe("sse");
    expect(TRANSPORT.HTTP).toBe("http");
    expect(TRANSPORT.STDIO).toBe("stdio");
    expect(TRANSPORT.OPENAPI).toBe("openapi");
  });

  it("should define OAuth flow types", () => {
    expect(OAUTH_FLOW.INTERACTIVE).toBe("interactive");
    expect(OAUTH_FLOW.M2M).toBe("m2m");
  });

  it("should define the backend M2M flow value", () => {
    expect(MCP_OAUTH2_FLOW_M2M).toBe("client_credentials");
  });
});

describe("getMcpOAuthMode", () => {
  it("returns null for non-OAuth2 servers", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.API_KEY })).toBeNull();
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.NONE })).toBeNull();
    expect(getMcpOAuthMode({})).toBeNull();
  });

  it("classifies client_credentials as m2m", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.OAUTH2, oauth2_flow: MCP_OAUTH2_FLOW_M2M })).toBe("m2m");
  });

  it("classifies oauth2_token_exchange as token_exchange regardless of the oauth2 secondary fields", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.OAUTH2_TOKEN_EXCHANGE })).toBe("token_exchange");
    expect(
      getMcpOAuthMode({
        auth_type: AUTH_TYPE.OAUTH2_TOKEN_EXCHANGE,
        oauth2_flow: MCP_OAUTH2_FLOW_M2M,
        delegate_auth_to_upstream: true,
      }),
    ).toBe("token_exchange");
  });

  it("treats m2m as m2m even when delegate_auth_to_upstream is true", () => {
    expect(
      getMcpOAuthMode({
        auth_type: AUTH_TYPE.OAUTH2,
        oauth2_flow: MCP_OAUTH2_FLOW_M2M,
        delegate_auth_to_upstream: true,
      }),
    ).toBe("m2m");
  });

  it("classifies an interactive server with delegate_auth_to_upstream as passthrough", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.OAUTH2, oauth2_flow: null, delegate_auth_to_upstream: true })).toBe(
      "passthrough",
    );
  });

  it("classifies an interactive server without delegation as authorization_code", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.OAUTH2, oauth2_flow: null, delegate_auth_to_upstream: false })).toBe(
      "authorization_code",
    );
  });

  it("defaults to authorization_code when delegate_auth_to_upstream is undefined", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.OAUTH2 })).toBe("authorization_code");
  });

  it("treats explicit authorization_code as interactive, not m2m", () => {
    expect(
      getMcpOAuthMode({
        auth_type: AUTH_TYPE.OAUTH2,
        oauth2_flow: "authorization_code",
        delegate_auth_to_upstream: false,
      }),
    ).toBe("authorization_code");
  });

  // Regression: the old heuristic labeled any OAuth2 server with a token endpoint
  // as M2M. getMcpOAuthMode ignores token_url, so an interactive server that
  // legitimately carries one is classified by oauth2_flow + delegate, never M2M.
  it("does not treat an interactive server with a token endpoint as m2m", () => {
    expect(getMcpOAuthMode({ auth_type: AUTH_TYPE.OAUTH2, oauth2_flow: null, delegate_auth_to_upstream: false })).toBe(
      "authorization_code",
    );
  });
});

describe("oauth2FlowToFormValue", () => {
  it("maps client_credentials to the M2M select value", () => {
    expect(oauth2FlowToFormValue(MCP_OAUTH2_FLOW_M2M)).toBe(OAUTH_FLOW.M2M);
  });

  it("maps authorization_code to the Interactive select value", () => {
    expect(oauth2FlowToFormValue("authorization_code")).toBe(OAUTH_FLOW.INTERACTIVE);
  });

  it("returns undefined for a null/unset flow so the select shows its placeholder", () => {
    expect(oauth2FlowToFormValue(null)).toBeUndefined();
    expect(oauth2FlowToFormValue(undefined)).toBeUndefined();
  });
});

describe("preservedDeclaredAppCredentials", () => {
  it("keeps only non-empty string declared-app keys and never token-shaped keys", () => {
    expect(preservedDeclaredAppCredentials(undefined)).toBeUndefined();
    expect(preservedDeclaredAppCredentials({})).toBeUndefined();
    expect(preservedDeclaredAppCredentials({ client_id: 123 })).toBeUndefined();
    expect(preservedDeclaredAppCredentials({ client_id: "" })).toBeUndefined();
    expect(preservedDeclaredAppCredentials({ client_id: "a", access_token: "t", scopes: ["s"] })).toEqual({
      client_id: "a",
    });
    expect(preservedDeclaredAppCredentials({ client_secret: "s" })).toEqual({ client_secret: "s" });
    expect(preservedDeclaredAppCredentials({ client_id: "a", client_secret: "b", refresh_token: "r" })).toEqual({
      client_id: "a",
      client_secret: "b",
    });
  });
});

describe("withoutMintedTokenCredentials", () => {
  it("drops token keys and keeps the declared app and other config", () => {
    expect(withoutMintedTokenCredentials(undefined)).toBeUndefined();
    const mixed = {
      client_id: "a",
      client_secret: "b",
      access_token: "t",
      refresh_token: "r",
      expires_in: 3600,
      scope: "read",
      scopes: ["read"],
    };
    expect(withoutMintedTokenCredentials(mixed)).toEqual({ client_id: "a", client_secret: "b", scopes: ["read"] });
  });

  it("returns undefined (not {}) when only minted keys are present, so a restore never blanks the fields", () => {
    expect(withoutMintedTokenCredentials({ access_token: "t", refresh_token: "r", expires_in: 3600 })).toBeUndefined();
    // A declared client is always kept, so a stored client_id can never be overwritten with empty.
    expect(withoutMintedTokenCredentials({ client_id: "x", access_token: "t" })).toEqual({ client_id: "x" });
  });
});

describe("credentialAuthClass", () => {
  it("collapses the client-forwarded modes to one class and leaves others distinct", () => {
    expect(credentialAuthClass(AUTH_TYPE.TRUE_PASSTHROUGH)).toBe("client_forwarded");
    expect(credentialAuthClass(AUTH_TYPE.OAUTH_DELEGATE)).toBe("client_forwarded");
    expect(credentialAuthClass(AUTH_TYPE.OAUTH2)).toBe(AUTH_TYPE.OAUTH2);
    expect(credentialAuthClass(null)).toBeNull();
  });
});

describe("preservedAdminCredentials vs preservedDeclaredAppCredentials", () => {
  // Regression: upstream_resource is admin-typed config living in `credentials`, and the invalidation
  // reset wipes that whole object. If it is not preserved, editing an unrelated field like the URL
  // silently discards the admin's resource indicator and the server goes back to sending none.
  it("preserves upstream_resource across an invalidation reset", () => {
    const credentials = { client_id: "cid", client_secret: "csec", upstream_resource: "api://audience" };
    expect(preservedAdminCredentials(credentials)).toEqual(credentials);
  });

  it("preserves upstream_resource even when no OAuth app is declared", () => {
    // A dynamic-client-registration server has no client_id/client_secret but can still pin a resource.
    expect(preservedAdminCredentials({ upstream_resource: "auto" })).toEqual({ upstream_resource: "auto" });
  });

  it("strips minted token material", () => {
    const credentials = { client_id: "cid", upstream_resource: "auto", access_token: "tok", refresh_token: "r" };
    expect(preservedAdminCredentials(credentials)).toEqual({ client_id: "cid", upstream_resource: "auto" });
  });

  // The two helpers answer different questions and must not be collapsed: "has the admin declared an
  // OAuth app" gates the app-may-not-match-upstream warning, so a resource-only server must read as
  // having no declared app.
  it("does not report a declared app for a resource-only server", () => {
    expect(preservedDeclaredAppCredentials({ upstream_resource: "auto" })).toBeUndefined();
    expect(preservedAdminCredentials({ upstream_resource: "auto" })).toBeDefined();
  });

  it("still reports a declared app when client keys are present", () => {
    expect(preservedDeclaredAppCredentials({ client_id: "cid", upstream_resource: "auto" })).toEqual({
      client_id: "cid",
    });
  });
});
