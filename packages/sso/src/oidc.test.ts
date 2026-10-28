import { APIError } from "@better-auth/core/error";
import { betterFetch } from "@better-fetch/fetch";
import { createAuthClient } from "better-auth/client";
import { organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify } from "jose";
import { OAuth2Server } from "oauth2-mock-server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { getAuthStateVerificationIdentifier } from "../../better-auth/src/state";
import { sso } from ".";
import { ssoClient } from "./client";

const server = new OAuth2Server();

describe("SSO", async () => {
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8080"],
			plugins: [sso(), organization()],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.issuer.on;
		await server.start(8080, "localhost");
		console.log("Issuer URL:", server.issuer.url); // -> http://localhost:8080
	});

	afterAll(async () => {
		await server.stop().catch(() => {});
	});

	server.service.on("beforeUserinfo", (userInfoResponse, req) => {
		userInfoResponse.body = {
			email: "oauth2@test.com",
			name: "OAuth2 Test",
			sub: "oauth2",
			picture: "https://test.com/picture.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	});

	server.service.on("beforeTokenSigning", (token, req) => {
		token.payload.sub = "oauth2";
		token.payload.email = "sso-user@localhost:8000.com";
		token.payload.email_verified = true;
		token.payload.name = "Test User";
		token.payload.picture = "https://test.com/picture.png";
	});

	async function simulateOAuthFlow(
		authUrl: string,
		headers: Headers,
		fetchImpl?: (...args: any) => any,
	) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");
		const newHeaders = new Headers();
		let callbackURL = "";
		await betterFetch(location, {
			method: "GET",
			customFetchImpl: fetchImpl || customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should register a new SSO provider", async () => {
		const { headers } = await signInWithTestUser();
		const provider = await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "localhost.com",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
				providerId: "test",
			},
			headers,
		});
		expect(provider).toMatchObject({
			id: expect.any(String),
			issuer: "http://localhost:8080",
			oidcConfig: {
				issuer: "http://localhost:8080",
				clientId: "test",
				clientSecret: "test",
				authorizationEndpoint: "http://localhost:8080/authorize",
				tokenEndpoint: "http://localhost:8080/token",
				jwksEndpoint: "http://localhost:8080/jwks",
				discoveryEndpoint:
					"http://localhost:8080/.well-known/openid-configuration",
				mapping: {
					email: "email",
					emailVerified: "email_verified",
					name: "name",
					image: "picture",
				},
			},
			userId: expect.any(String),
		});
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/11434
	 */
	it("should reject registration when the issuer differs from discovery by a trailing slash", async () => {
		const { headers } = await signInWithTestUser();

		await expect(
			auth.api.registerSSOProvider({
				body: {
					issuer: `${server.issuer.url}/`,
					domain: "issuer-mismatch.example.com",
					providerId: "issuer-mismatch",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
					},
				},
				headers,
			}),
		).rejects.toMatchObject({
			status: "BAD_REQUEST",
			body: {
				code: "issuer_mismatch",
			},
		});
	});

	it("rejects OIDC profile mappings that attempt to replace the subject", async () => {
		const { headers } = await signInWithTestUser();
		const profileMappingWithSubjectOverride = {
			id: "employee_id",
			email: "email",
			name: "name",
		};

		await expect(
			auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain: "subject-mapping.example.com",
					providerId: "subject-mapping",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
						skipDiscovery: true,
						authorizationEndpoint: `${server.issuer.url}/authorize`,
						tokenEndpoint: `${server.issuer.url}/token`,
						jwksEndpoint: `${server.issuer.url}/jwks`,
						mapping: profileMappingWithSubjectOverride,
					},
				},
				headers,
			}),
		).rejects.toMatchObject({ status: 400 });
	});

	it("should fail to register a new SSO provider with invalid issuer", async () => {
		const { headers } = await signInWithTestUser();

		try {
			await auth.api.registerSSOProvider({
				body: {
					issuer: "invalid",
					domain: "localhost",
					providerId: "test",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
					},
				},
				headers,
			});
		} catch (e) {
			expect(e).toMatchObject({
				status: 400,
				body: {
					message: "[body.issuer] Invalid URL",
				},
			});
		}
	});

	it("should not allow creating a provider with duplicate providerId", async () => {
		const { headers } = await signInWithTestUser();

		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "duplicate.com",
				providerId: "duplicate-oidc-provider",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
				},
			},
			headers,
		});

		await expect(
			auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain: "another-duplicate.com",
					providerId: "duplicate-oidc-provider",
					oidcConfig: {
						clientId: "test2",
						clientSecret: "test2",
					},
				},
				headers,
			}),
		).rejects.toMatchObject({
			status: "UNPROCESSABLE_ENTITY",
			body: {
				message: "SSO provider with this providerId already exists",
			},
		});
	});

	it("should sign in with SSO provider with email matching", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "my-email@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Ftest",
		);
		expect(res.url).toContain("login_hint=my-email%40localhost.com");
		const { callbackURL } = await simulateOAuthFlow(res.url, headers);
		expect(callbackURL).toContain("/dashboard");
	});

	it("should sign in with SSO provider with domain", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "my-email@test.com",
			domain: "localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Ftest",
		);
		const { callbackURL } = await simulateOAuthFlow(res.url, headers);
		expect(callbackURL).toContain("/dashboard");
	});

	it("should sign in with SSO provider with providerId", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "test",
			loginHint: "user@example.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Ftest",
		);
		expect(res.url).toContain("login_hint=user%40example.com");

		const { callbackURL } = await simulateOAuthFlow(res.url, headers);
		expect(callbackURL).toContain("/dashboard");
	});

	it("should redirect with the token endpoint error description when code exchange fails", async () => {
		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "token-error.com",
				providerId: "token-error-provider",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
				},
			},
			headers,
		});

		const tokenErrorHandler = (tokenEndpointResponse: {
			body: Record<string, unknown>;
			statusCode: number;
		}) => {
			tokenEndpointResponse.body = {
				error: "invalid_client",
				error_description: "client rejected by issuer",
			};
			tokenEndpointResponse.statusCode = 401;
		};
		server.service.once("beforeResponse", tokenErrorHandler);

		const signInHeaders = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "token-error-provider",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});

		try {
			const { callbackURL } = await simulateOAuthFlow(res.url, signInHeaders);
			const redirectURL = new URL(callbackURL, "http://localhost:3000");
			expect(redirectURL.searchParams.get("error")).toBe("invalid_provider");
			expect(redirectURL.searchParams.get("error_description")).toBe(
				"client rejected by issuer",
			);
		} finally {
			server.service.removeListener("beforeResponse", tokenErrorHandler);
		}
	});

	it("should redirect with an encoded invalid request when callback has no code", async () => {
		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "missing-code.com",
				providerId: "missing-code-provider",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
				},
			},
			headers,
		});

		const signInHeaders = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "missing-code-provider",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});

		let callbackLocation: string | null = null;
		await betterFetch(res.url, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				callbackLocation = context.response.headers.get("location");
			},
		});
		if (!callbackLocation) throw new Error("No callback location found");

		const callbackWithoutCode = new URL(callbackLocation);
		callbackWithoutCode.searchParams.delete("code");

		let redirectLocation = "";
		await betterFetch(callbackWithoutCode.toString(), {
			method: "GET",
			customFetchImpl,
			headers: signInHeaders,
			onError(context) {
				redirectLocation = context.response.headers.get("location") || "";
			},
		});

		const redirectURL = new URL(redirectLocation, "http://localhost:3000");
		expect(redirectURL.searchParams.get("error")).toBe("invalid_request");
		expect(redirectURL.searchParams.get("error_description")).toBe(
			"authorization_code_not_found",
		);
	});

	it("should forward additionalParams to the SSO authorization URL", async () => {
		const res = await authClient.signIn.sso({
			providerId: "test",
			callbackURL: "/dashboard",
			additionalParams: { domain_hint: "contoso.com" },
			fetchOptions: { throw: true },
		});
		const url = new URL(res.url);
		expect(url.searchParams.get("domain_hint")).toBe("contoso.com");
	});

	it("should reject SSO additionalParams that collide with reserved OAuth params", async () => {
		const res = await authClient.signIn.sso({
			providerId: "test",
			callbackURL: "/dashboard",
			additionalParams: { redirect_uri: "https://attacker.example/callback" },
		});
		expect(res.error?.status).toBe(400);
	});

	it("should hydrate authorizationEndpoint via discovery when missing from stored config", async () => {
		const { headers } = await signInWithTestUser();

		// Register a provider with skipDiscovery, providing tokenEndpoint +
		// jwksEndpoint but deliberately omitting authorizationEndpoint.
		// This simulates a legacy provider stored without the authorization URL.
		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "no-auth-endpoint.com",
				providerId: "no-auth-endpoint",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					skipDiscovery: true,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
			},
			headers,
		});

		// Use a unique identity so the callback doesn't collide with the
		// "sso-user@localhost:8000.com" account already linked to "test" provider.
		const originalUserinfoListeners =
			server.service.listeners("beforeUserinfo");
		const originalTokenListeners =
			server.service.listeners("beforeTokenSigning");
		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.on("beforeUserinfo", (userInfoResponse: any) => {
			userInfoResponse.body = {
				email: "no-auth-endpoint-user@no-auth-endpoint.com",
				name: "No Auth Endpoint User",
				sub: "no-auth-endpoint-user",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});
		server.service.on("beforeTokenSigning", (token: any) => {
			token.payload.email = "no-auth-endpoint-user@no-auth-endpoint.com";
			token.payload.email_verified = true;
			token.payload.name = "No Auth Endpoint User";
			token.payload.sub = "no-auth-endpoint-user";
		});

		try {
			const signInHeaders = new Headers();
			const res = await authClient.signIn.sso({
				providerId: "no-auth-endpoint",
				callbackURL: "/dashboard",
				fetchOptions: {
					throw: true,
					onSuccess: cookieSetter(signInHeaders),
				},
			});

			// Discovery should have hydrated authorizationEndpoint — no error
			expect(res.url).toContain("http://localhost:8080/authorize");

			const { callbackURL } = await simulateOAuthFlow(res.url, signInHeaders);
			expect(callbackURL).toContain("/dashboard");
		} finally {
			server.service.removeAllListeners("beforeUserinfo");
			server.service.removeAllListeners("beforeTokenSigning");
			for (const listener of originalUserinfoListeners) {
				server.service.on("beforeUserinfo", listener as any);
			}
			for (const listener of originalTokenListeners) {
				server.service.on("beforeTokenSigning", listener as any);
			}
		}
	});

	it("should normalize email to lowercase in OIDC authentication", async () => {
		const { headers } = await signInWithTestUser();

		// Register a new provider for this test
		await auth.api.registerSSOProvider({
			body: {
				providerId: "email-case-oidc-provider",
				issuer: server.issuer.url!,
				domain: "email-case-test.com",
				oidcConfig: {
					clientId: "email-case-test-client",
					clientSecret: "test-client-secret",
					discoveryEndpoint: `${server.issuer.url!}/.well-known/openid-configuration`,
					pkce: false,
				},
			},
			headers,
		});

		// Store original listeners and set up mixed-case email
		const originalUserinfoListeners =
			server.service.listeners("beforeUserinfo");
		const originalTokenListeners =
			server.service.listeners("beforeTokenSigning");

		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");

		const mixedCaseEmail = "OIDCUser@Example.COM";

		server.service.on("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: mixedCaseEmail,
				name: "OIDC Test User",
				sub: "oidc-email-case-test-user",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});

		server.service.on("beforeTokenSigning", (token) => {
			token.payload.email = mixedCaseEmail;
			token.payload.email_verified = true;
			token.payload.name = "OIDC Test User";
			token.payload.sub = "oidc-email-case-test-user";
		});

		try {
			// First sign in - should create user with lowercase email
			const signInHeaders1 = new Headers();
			const res1 = await authClient.signIn.sso({
				email: `user@email-case-test.com`,
				callbackURL: "/dashboard",
				fetchOptions: {
					throw: true,
					onSuccess: cookieSetter(signInHeaders1),
				},
			});

			const { callbackURL: callbackURL1, headers: sessionHeaders1 } =
				await simulateOAuthFlow(res1.url, signInHeaders1);
			expect(callbackURL1).toContain("/dashboard");

			// Get session and verify email is lowercase
			const session1 = await authClient.getSession({
				fetchOptions: {
					headers: sessionHeaders1,
				},
			});

			expect(session1.data?.user.email).toBe("oidcuser@example.com");
			const firstUserId = session1.data?.user.id;
			expect(firstUserId).toBeDefined();

			// Second sign in with same mixed-case email - should find existing user
			const signInHeaders2 = new Headers();
			const res2 = await authClient.signIn.sso({
				email: `user@email-case-test.com`,
				callbackURL: "/dashboard",
				fetchOptions: {
					throw: true,
					onSuccess: cookieSetter(signInHeaders2),
				},
			});

			const { callbackURL: callbackURL2, headers: sessionHeaders2 } =
				await simulateOAuthFlow(res2.url, signInHeaders2);
			expect(callbackURL2).toContain("/dashboard");

			// Verify same user is returned
			const session2 = await authClient.getSession({
				fetchOptions: {
					headers: sessionHeaders2,
				},
			});

			expect(session2.data?.user.id).toBe(firstUserId);
			expect(session2.data?.user.email).toBe("oidcuser@example.com");
		} finally {
			// Restore original listeners
			server.service.removeAllListeners("beforeUserinfo");
			server.service.removeAllListeners("beforeTokenSigning");
			for (const listener of originalUserinfoListeners) {
				server.service.on("beforeUserinfo", listener);
			}
			for (const listener of originalTokenListeners) {
				server.service.on("beforeTokenSigning", listener);
			}
		}
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/11630
	 */
	it("reads the email from a mapped array claim in the ID token (Azure AD B2C)", async () => {
		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				providerId: "b2c-emails-array",
				issuer: server.issuer.url!,
				domain: "b2c-emails-array.com",
				oidcConfig: {
					clientId: "b2c-emails-array-client",
					clientSecret: "test-client-secret",
					skipDiscovery: true,
					authorizationEndpoint: `${server.issuer.url!}/authorize`,
					tokenEndpoint: `${server.issuer.url!}/token`,
					jwksEndpoint: `${server.issuer.url!}/jwks`,
					pkce: false,
					mapping: { email: "emails" },
				},
			},
			headers,
		});
		const originalTokenListeners =
			server.service.listeners("beforeTokenSigning");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.on("beforeTokenSigning", (token) => {
			token.payload.sub = "b2c-emails-array-sub";
			token.payload.name = "Jane Doe";
			token.payload.emails = ["", "jane@b2c-emails-array.com"];
		});
		try {
			const signInHeaders = new Headers();
			const res = await authClient.signIn.sso({
				providerId: "b2c-emails-array",
				callbackURL: "/dashboard",
				fetchOptions: { throw: true, onSuccess: cookieSetter(signInHeaders) },
			});
			const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
				res.url,
				signInHeaders,
			);
			expect(callbackURL).toContain("/dashboard");
			const session = await auth.api.getSession({ headers: sessionHeaders });
			expect(session?.user.email).toBe("jane@b2c-emails-array.com");
			expect(session?.user.emailVerified).toBe(false);
		} finally {
			server.service.removeAllListeners("beforeTokenSigning");
			for (const listener of originalTokenListeners) {
				server.service.on("beforeTokenSigning", listener);
			}
		}
	});
});

describe("SSO disable implicit sign in", async () => {
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8080"],
			plugins: [sso({ disableImplicitSignUp: true }), organization()],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.issuer.on;
		await server.start(8080, "localhost");
		console.log("Issuer URL:", server.issuer.url); // -> http://localhost:8080
	});

	afterAll(async () => {
		await server.stop();
	});

	server.service.on("beforeUserinfo", (userInfoResponse, req) => {
		userInfoResponse.body = {
			email: "oauth2@test.com",
			name: "OAuth2 Test",
			sub: "oauth2",
			picture: "https://test.com/picture.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	});

	server.service.on("beforeTokenSigning", (token, req) => {
		token.payload.email = "sso-user@localhost:8000.com";
		token.payload.email_verified = true;
		token.payload.name = "Test User";
		token.payload.picture = "https://test.com/picture.png";
	});

	async function simulateOAuthFlow(
		authUrl: string,
		headers: Headers,
		fetchImpl?: (...args: any) => any,
	) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");
		const newHeaders = new Headers(headers);
		let callbackURL = "";
		await betterFetch(location, {
			method: "GET",
			customFetchImpl: fetchImpl || customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should register a new SSO provider", async () => {
		const { headers } = await signInWithTestUser();
		const provider = await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "localhost.com",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
				providerId: "test",
			},
			headers,
		});
		expect(provider).toMatchObject({
			id: expect.any(String),
			issuer: "http://localhost:8080",
			oidcConfig: {
				issuer: "http://localhost:8080",
				clientId: "test",
				clientSecret: "test",
				authorizationEndpoint: "http://localhost:8080/authorize",
				tokenEndpoint: "http://localhost:8080/token",
				jwksEndpoint: "http://localhost:8080/jwks",
				discoveryEndpoint:
					"http://localhost:8080/.well-known/openid-configuration",
				mapping: {
					email: "email",
					emailVerified: "email_verified",
					name: "name",
					image: "picture",
				},
			},
			userId: expect.any(String),
		});
	});

	it("should not create user with SSO provider when sign ups are disabled", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "my-email@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Ftest",
		);
		const { callbackURL } = await simulateOAuthFlow(res.url, headers);
		expect(callbackURL).not.toContain("error=signup disabled");
		const url = new URL(callbackURL);
		expect(url.pathname).toBe("/api/auth/error");
		expect(url.searchParams.get("error")).toBe("signup disabled");
	});

	it("should create user with SSO provider when sign ups are disabled but sign up is requested", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "my-email@localhost.com",
			callbackURL: "/dashboard",
			requestSignUp: true,
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Ftest",
		);
		const { callbackURL } = await simulateOAuthFlow(res.url, headers);
		expect(callbackURL).toContain("/dashboard");
	});
});

describe("provisioning", async (ctx) => {
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8080"],
			plugins: [sso(), organization()],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.issuer.on;
		await server.start(8080, "localhost");
		console.log("Issuer URL:", server.issuer.url); // -> http://localhost:8080
	});

	afterAll(async () => {
		await server.stop();
	});
	async function simulateOAuthFlow(
		authUrl: string,
		headers: Headers,
		fetchImpl?: (...args: any) => any,
	) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");

		let callbackURL = "";
		const newHeaders = new Headers();
		await betterFetch(location, {
			method: "GET",
			customFetchImpl: fetchImpl || customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return callbackURL;
	}

	server.service.on("beforeUserinfo", (userInfoResponse, req) => {
		userInfoResponse.body = {
			email: "test@localhost.com",
			name: "OAuth2 Test",
			sub: "oauth2",
			picture: "https://test.com/picture.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	});

	server.service.on("beforeTokenSigning", (token, req) => {
		token.payload.email = "sso-user@localhost:8000.com";
		token.payload.email_verified = true;
		token.payload.name = "Test User";
		token.payload.picture = "https://test.com/picture.png";
	});
	it("should provision user", async () => {
		const { headers } = await signInWithTestUser();
		const organization = await auth.api.createOrganization({
			body: {
				name: "Localhost",
				slug: "localhost",
			},
			headers,
		});
		const provider = await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "localhost.com",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
				providerId: "test2",
				organizationId: organization?.id,
			},
			headers,
		});
		expect(provider).toMatchObject({
			organizationId: organization?.id,
		});
		const newHeaders = new Headers();
		const res = await authClient.signIn.sso({
			email: "my-email@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				onSuccess: cookieSetter(newHeaders),
				throw: true,
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Ftest",
		);

		const callbackURL = await simulateOAuthFlow(res.url, newHeaders);
		expect(callbackURL).toContain("/dashboard");
		const org = await auth.api.getFullOrganization({
			query: {
				organizationId: organization?.id || "",
			},
			headers,
		});
		const member = org?.members.find(
			(m: any) => m.user.email === "test@localhost.com",
		);
		expect(member).toMatchObject({
			role: "member",
			user: {
				id: expect.any(String),
				name: "OAuth2 Test",
				email: "test@localhost.com",
				image: "https://test.com/picture.png",
			},
		});
	});

	it("should sign in with SSO provide with org slug", async () => {
		const res = await auth.api.signInSSO({
			body: {
				organizationSlug: "localhost",
				callbackURL: "/dashboard",
			},
		});

		expect(res.url).toContain("http://localhost:8080/authorize");
	});
});

/**
 * @see https://github.com/better-auth/better-auth/issues/7857
 */
describe("provisionUser should only be called for new users", async () => {
	const provisionUserFn = vi.fn();
	const validateUserInfoFn = vi.fn();
	const getRoleFn = vi.fn(
		async ({
			attributes,
		}: {
			attributes: Record<string, string | string[]>;
		}) =>
			Array.isArray(attributes.groups) && attributes.groups.includes("admins")
				? "admin"
				: "member",
	);
	const getMemberDataFn = vi.fn(
		async ({
			attributes,
			defaultData,
		}: {
			attributes: Record<string, string | string[]>;
			defaultData: Record<string, unknown>;
		}) => ({
			...defaultData,
			providerGroups: Array.isArray(attributes.groups)
				? attributes.groups.join(",")
				: "",
		}),
	);
	let oidcIdentity = {
		email: "provision-test@localhost.com",
		sub: "provision-test-sub",
	};
	let oidcGroups: string[] = [];
	let oidcUserInfoEmailVerified: boolean | undefined = false;
	let oidcIdTokenEmailVerified: boolean | undefined = false;
	let userInfoRequestCount = 0;
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8082"],
			user: {
				validateUserInfo({ source }) {
					if (source.method === "sso-oidc") {
						validateUserInfoFn(source);
					}
				},
			},
			plugins: [
				sso({
					provisionUser: provisionUserFn,
					organizationProvisioning: {
						getRole: getRoleFn,
						getMemberData: getMemberDataFn,
					},
					domainVerification: {
						enabled: true,
						trustEmailOwnership: true,
					},
				}),
				organization({
					schema: {
						member: {
							additionalFields: {
								providerGroups: { type: "string", required: false },
							},
						},
					},
				}),
			],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.on("beforeUserinfo", (userInfoResponse) => {
			userInfoRequestCount += 1;
			userInfoResponse.body = {
				email: oidcIdentity.email,
				name: "Provision Test",
				sub: oidcIdentity.sub,
				picture: "https://test.com/picture.png",
				email_verified: oidcUserInfoEmailVerified,
				groups: oidcGroups,
			};
			userInfoResponse.statusCode = 200;
		});
		server.service.on("beforeTokenSigning", (token) => {
			token.payload.sub = oidcIdentity.sub;
			token.payload.email = oidcIdentity.email;
			token.payload.email_verified = oidcIdTokenEmailVerified;
			token.payload.name = "Provision Test";
			token.payload.picture = "https://test.com/picture.png";
		});
		await server.start(8082, "localhost");
	});

	afterAll(async () => {
		await server.stop();
	});

	async function simulateOAuthFlow(authUrl: string, headers: Headers) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");

		let callbackURL = "";
		const newHeaders = new Headers();
		await betterFetch(location, {
			method: "GET",
			customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	async function ensurePersistedProvider(
		headers: Headers,
		providerId: string,
		domain = "localhost.com",
		organizationId?: string,
		domainVerified = true,
	) {
		const context = await auth.$context;
		const existing = await context.adapter.findOne({
			model: "ssoProvider",
			where: [{ field: "providerId", value: providerId }],
		});
		if (!existing) {
			await auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain,
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
						authorizationEndpoint: `${server.issuer.url}/authorize`,
						tokenEndpoint: `${server.issuer.url}/token`,
						jwksEndpoint: `${server.issuer.url}/jwks`,
						discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
						mapping: {
							email: "email",
							emailVerified: "email_verified",
							name: "name",
							image: "picture",
						},
					},
					providerId,
					...(organizationId ? { organizationId } : {}),
				},
				headers,
			});
		}
		await context.adapter.update({
			model: "ssoProvider",
			where: [{ field: "providerId", value: providerId }],
			update: { domainVerified },
		});
	}

	it("should call provisionUser only on first sign-in (new user), not on subsequent sign-ins", async () => {
		const { headers } = await signInWithTestUser();
		await ensurePersistedProvider(headers, "provision-test");
		const context = await auth.$context;

		provisionUserFn.mockClear();
		validateUserInfoFn.mockClear();

		// First sign-in: new user -> provisionUser should be called
		const signInHeaders1 = new Headers();
		const res1 = await authClient.signIn.sso({
			email: "user@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders1),
			},
		});
		await simulateOAuthFlow(res1.url, signInHeaders1);
		expect(provisionUserFn).toHaveBeenCalledTimes(1);
		expect(provisionUserFn.mock.calls[0]?.[0].user.emailVerified).toBe(true);
		expect(provisionUserFn.mock.calls[0]?.[0].attributes).toEqual({
			email: "provision-test@localhost.com",
			name: "Provision Test",
			sub: "provision-test-sub",
			picture: "https://test.com/picture.png",
			email_verified: "false",
		});
		expect(
			await context.adapter.findOne<{ emailVerified: boolean }>({
				model: "user",
				where: [{ field: "email", value: "provision-test@localhost.com" }],
			}),
		).toMatchObject({ emailVerified: true });
		expect(validateUserInfoFn).toHaveBeenCalledTimes(1);
		expect(validateUserInfoFn.mock.calls[0]?.[0]).toMatchObject({
			action: "create-user",
			method: "sso-oidc",
			sso: {
				providerId: "provision-test",
				profile: { sub: "provision-test-sub" },
			},
		});
		expect(validateUserInfoFn.mock.calls[0]?.[0].oauth).toBeUndefined();

		provisionUserFn.mockClear();

		// Second sign-in: existing user -> provisionUser should NOT be called
		const signInHeaders2 = new Headers();
		const res2 = await authClient.signIn.sso({
			email: "user@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders2),
			},
		});
		await simulateOAuthFlow(res2.url, signInHeaders2);
		expect(provisionUserFn).toHaveBeenCalledTimes(0);
		expect(validateUserInfoFn).toHaveBeenCalledTimes(2);
		expect(validateUserInfoFn.mock.calls[1]?.[0]).toMatchObject({
			action: "sign-in",
			method: "sso-oidc",
			sso: {
				providerId: "provision-test",
				profile: { sub: "provision-test-sub" },
			},
		});
		expect(validateUserInfoFn.mock.calls[1]?.[0].oauth).toBeUndefined();
	});

	it("requires local email verification before linking an existing account", async () => {
		const { headers } = await signInWithTestUser();
		await ensurePersistedProvider(headers, "provision-test");
		const context = await auth.$context;
		const unverifiedEmail = "unverified-link@localhost.com";
		const localSignup = await auth.api.signUpEmail({
			body: {
				email: unverifiedEmail,
				password: "test-password-123",
				name: "Unverified Local User",
			},
		});
		const sessionsBefore = await context.adapter.findMany({
			model: "session",
			where: [{ field: "userId", value: localSignup.user.id }],
		});
		provisionUserFn.mockClear();
		oidcIdentity = { email: unverifiedEmail, sub: "unverified-link-sub" };

		const unverifiedHeaders = new Headers();
		const unverifiedSignIn = await authClient.signIn.sso({
			providerId: "provision-test",
			email: unverifiedEmail,
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(unverifiedHeaders),
			},
		});
		const unverifiedResult = await simulateOAuthFlow(
			unverifiedSignIn.url,
			unverifiedHeaders,
		);
		expect(
			new URL(unverifiedResult.callbackURL).searchParams.get("error"),
		).toBe("account not linked");
		expect(
			await context.adapter.findOne({
				model: "account",
				where: [
					{ field: "providerId", value: "provision-test" },
					{ field: "accountId", value: "unverified-link-sub" },
				],
			}),
		).toBeNull();
		expect(provisionUserFn).not.toHaveBeenCalled();
		expect(
			await context.adapter.findOne<{ emailVerified: boolean; name: string }>({
				model: "user",
				where: [{ field: "id", value: localSignup.user.id }],
			}),
		).toMatchObject({ emailVerified: false, name: "Unverified Local User" });
		expect(
			await context.adapter.findMany({
				model: "session",
				where: [{ field: "userId", value: localSignup.user.id }],
			}),
		).toHaveLength(sessionsBefore.length);

		for (const [index, rawVerifiedClaim] of [
			true,
			false,
			undefined,
		].entries()) {
			const unmatchedEmail = `unmatched-${index}@outside.example`;
			const unmatchedSub = `unmatched-link-${index}-sub`;
			const unmatchedSignup = await auth.api.signUpEmail({
				body: {
					email: unmatchedEmail,
					password: "test-password-123",
					name: "Unmatched Local User",
				},
			});
			const unmatchedSessions = await context.adapter.findMany({
				model: "session",
				where: [{ field: "userId", value: unmatchedSignup.user.id }],
			});
			oidcIdentity = { email: unmatchedEmail, sub: unmatchedSub };
			oidcUserInfoEmailVerified = rawVerifiedClaim;
			const unmatchedHeaders = new Headers();
			const unmatchedSignIn = await authClient.signIn.sso({
				providerId: "provision-test",
				email: unmatchedEmail,
				callbackURL: "/dashboard",
				fetchOptions: {
					throw: true,
					onSuccess: cookieSetter(unmatchedHeaders),
				},
			});
			const unmatchedResult = await simulateOAuthFlow(
				unmatchedSignIn.url,
				unmatchedHeaders,
			);
			expect(
				new URL(unmatchedResult.callbackURL).searchParams.get("error"),
			).toBe("account not linked");
			expect(
				await context.adapter.findOne({
					model: "account",
					where: [
						{ field: "providerId", value: "provision-test" },
						{ field: "accountId", value: unmatchedSub },
					],
				}),
			).toBeNull();
			expect(
				await context.adapter.findOne<{ emailVerified: boolean }>({
					model: "user",
					where: [{ field: "id", value: unmatchedSignup.user.id }],
				}),
			).toMatchObject({ emailVerified: false });
			expect(
				await context.adapter.findMany({
					model: "session",
					where: [{ field: "userId", value: unmatchedSignup.user.id }],
				}),
			).toHaveLength(unmatchedSessions.length);
			expect(provisionUserFn).not.toHaveBeenCalled();
		}

		const verifiedEmail = "verified-link@localhost.com";
		const verifiedUser = await auth.api.signUpEmail({
			body: {
				email: verifiedEmail,
				password: "test-password-123",
				name: "Verified Local User",
			},
		});
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: verifiedUser.user.id }],
			update: { emailVerified: true },
		});
		oidcIdentity = { email: verifiedEmail, sub: "verified-link-sub" };

		const verifiedHeaders = new Headers();
		const verifiedSignIn = await authClient.signIn.sso({
			providerId: "provision-test",
			email: verifiedEmail,
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(verifiedHeaders),
			},
		});
		const verifiedResult = await simulateOAuthFlow(
			verifiedSignIn.url,
			verifiedHeaders,
		);
		expect(verifiedResult.callbackURL).toContain("/dashboard");
		expect(
			await context.adapter.findOne({
				model: "account",
				where: [
					{ field: "providerId", value: "provision-test" },
					{ field: "accountId", value: "verified-link-sub" },
				],
			}),
		).not.toBeNull();
	});

	it("uses verified ID-token claims when the provider has no UserInfo endpoint", async () => {
		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "localhost.com",
				providerId: "provision-id-token-only",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					skipDiscovery: true,
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
					},
				},
			},
			headers,
		});
		const context = await auth.$context;
		await context.adapter.update({
			model: "ssoProvider",
			where: [{ field: "providerId", value: "provision-id-token-only" }],
			update: { domainVerified: true },
		});
		oidcIdentity = {
			email: "id-token-only@localhost.com",
			sub: "id-token-only-sub",
		};
		oidcIdTokenEmailVerified = true;
		provisionUserFn.mockClear();
		userInfoRequestCount = 0;

		const signInHeaders = new Headers();
		const signIn = await authClient.signIn.sso({
			providerId: "provision-id-token-only",
			email: oidcIdentity.email,
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});
		const result = await simulateOAuthFlow(signIn.url, signInHeaders);
		expect(result.callbackURL).toContain("/dashboard");
		expect(userInfoRequestCount).toBe(0);
		expect(provisionUserFn.mock.calls[0]?.[0].user.emailVerified).toBe(true);
		expect(provisionUserFn.mock.calls[0]?.[0].attributes).toMatchObject({
			email: oidcIdentity.email,
			sub: oidcIdentity.sub,
			email_verified: "true",
		});
		expect(
			await context.adapter.findOne({
				model: "account",
				where: [
					{ field: "providerId", value: "provision-id-token-only" },
					{ field: "accountId", value: oidcIdentity.sub },
				],
			}),
		).not.toBeNull();
		expect(
			await context.adapter.findOne<{ emailVerified: boolean }>({
				model: "user",
				where: [{ field: "email", value: oidcIdentity.email }],
			}),
		).toMatchObject({ emailVerified: true });
		oidcIdTokenEmailVerified = false;
	});

	it("forwards unmapped raw claims to OIDC organization callbacks and persists their results", async () => {
		const { headers } = await signInWithTestUser();
		const organizationRecord = await auth.api.createOrganization({
			body: { name: "Claims Org", slug: "oidc-claims-org" },
			headers,
		});
		await ensurePersistedProvider(
			headers,
			"provision-attributes-test",
			"localhost.com",
			organizationRecord.id,
		);
		oidcIdentity = {
			email: "claims-test@localhost.com",
			sub: "claims-test-sub",
		};
		oidcGroups = [" Engineering ", " admins "];
		getRoleFn.mockClear();
		getMemberDataFn.mockClear();

		const signInHeaders = new Headers();
		const signIn = await authClient.signIn.sso({
			providerId: "provision-attributes-test",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});
		const result = await simulateOAuthFlow(signIn.url, signInHeaders);
		expect(result.callbackURL).toContain("/dashboard");
		const rawGroups = [" Engineering ", " admins "];
		const normalizedAttributes = { groups: ["Engineering", "admins"] };
		const expectedCallbackArgs = expect.objectContaining({
			userInfo: expect.objectContaining({ groups: rawGroups }),
			attributes: expect.objectContaining(normalizedAttributes),
		});
		expect(getRoleFn).toHaveBeenCalledWith(expectedCallbackArgs);
		expect(getMemberDataFn).toHaveBeenCalledWith(expectedCallbackArgs);

		const context = await auth.$context;
		const user = await context.adapter.findOne<{ id: string }>({
			model: "user",
			where: [{ field: "email", value: oidcIdentity.email }],
		});
		expect(user).not.toBeNull();
		const member = await context.adapter.findOne<{
			role: string;
			providerGroups: string;
		}>({
			model: "member",
			where: [
				{ field: "organizationId", value: organizationRecord.id },
				{ field: "userId", value: user?.id ?? "" },
			],
		});
		expect(member).toMatchObject({
			role: "admin",
			providerGroups: "Engineering,admins",
		});
	});

	it("rejects an unverified persisted OIDC domain before writing authentication data", async () => {
		const { headers } = await signInWithTestUser();
		await ensurePersistedProvider(
			headers,
			"unverified-domain-provider",
			"localhost.com",
			undefined,
			false,
		);
		const context = await auth.$context;
		const before = {
			users: await context.adapter.findMany({ model: "user" }),
			accounts: await context.adapter.findMany({ model: "account" }),
			sessions: await context.adapter.findMany({ model: "session" }),
		};
		provisionUserFn.mockClear();

		await expect(
			auth.api.signInSSO({
				body: {
					providerId: "unverified-domain-provider",
					callbackURL: "/dashboard",
				},
			}),
		).rejects.toThrow(/Provider domain has not been verified/);
		expect(await context.adapter.findMany({ model: "user" })).toHaveLength(
			before.users.length,
		);
		expect(await context.adapter.findMany({ model: "account" })).toHaveLength(
			before.accounts.length,
		);
		expect(await context.adapter.findMany({ model: "session" })).toHaveLength(
			before.sessions.length,
		);
		expect(provisionUserFn).not.toHaveBeenCalled();
	});
});

/**
 * @see https://github.com/better-auth/better-auth/issues/8630
 */
describe("provisionUserOnEveryLogin should call provisionUser on every sign-in", async () => {
	const provisionUserFn = vi.fn();
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8083"],
			plugins: [
				sso({
					provisionUser: provisionUserFn,
					provisionUserOnEveryLogin: true,
				}),
				organization(),
			],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.on("beforeUserinfo", (userInfoResponse) => {
			userInfoResponse.body = {
				email: "provision-every-login@localhost.com",
				name: "Provision Every Login",
				sub: "provision-every-login-sub",
				picture: "https://test.com/picture.png",
				email_verified: true,
			};
			userInfoResponse.statusCode = 200;
		});
		server.service.on("beforeTokenSigning", (token) => {
			token.payload.sub = "provision-every-login-sub";
			token.payload.email = "provision-every-login@localhost.com";
			token.payload.email_verified = true;
			token.payload.name = "Provision Every Login";
			token.payload.picture = "https://test.com/picture.png";
		});
		await server.start(8083, "localhost");
	});

	afterAll(async () => {
		await server.stop();
	});

	async function simulateOAuthFlow(authUrl: string, headers: Headers) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");

		let callbackURL = "";
		const newHeaders = new Headers();
		await betterFetch(location, {
			method: "GET",
			customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should call provisionUser on both first and subsequent sign-ins", async () => {
		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "localhost.com",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
				providerId: "provision-every-login-test",
			},
			headers,
		});

		provisionUserFn.mockClear();

		// First sign-in: new user -> provisionUser should be called
		const signInHeaders1 = new Headers();
		const res1 = await authClient.signIn.sso({
			email: "user@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders1),
			},
		});
		await simulateOAuthFlow(res1.url, signInHeaders1);
		expect(provisionUserFn).toHaveBeenCalledTimes(1);
		expect(provisionUserFn.mock.calls[0]?.[0].user.emailVerified).toBe(false);

		provisionUserFn.mockClear();

		// Second sign-in: existing user -> provisionUser should still be called
		const signInHeaders2 = new Headers();
		const res2 = await authClient.signIn.sso({
			email: "user@localhost.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders2),
			},
		});
		await simulateOAuthFlow(res2.url, signInHeaders2);
		expect(provisionUserFn).toHaveBeenCalledTimes(1);
	});
});

/**
 * @see https://github.com/better-auth/better-auth/issues/7693
 */
describe("SSO shared redirectURI", async () => {
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8080"],
			plugins: [
				sso({
					redirectURI: "/sso/callback",
				}),
				organization(),
			],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: {
			customFetchImpl,
		},
	});

	const userinfoHandler = (userInfoResponse: any) => {
		userInfoResponse.body = {
			email: "shared-redirect@test.com",
			name: "Shared Redirect User",
			sub: "shared-redirect-user",
			picture: "https://test.com/shared.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	};

	const tokenHandler = (token: any) => {
		token.payload.sub = "shared-redirect-user";
		token.payload.email = "shared-redirect@test.com";
		token.payload.email_verified = true;
		token.payload.name = "Shared Redirect User";
		token.payload.picture = "https://test.com/shared.png";
	};

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.on("beforeUserinfo", userinfoHandler);
		server.service.on("beforeTokenSigning", tokenHandler);
		await server.start(8080, "localhost");
	});

	afterAll(async () => {
		server.service.removeListener("beforeUserinfo", userinfoHandler);
		server.service.removeListener("beforeTokenSigning", tokenHandler);
		await server.stop().catch(() => {});
	});

	async function simulateOAuthFlow(
		authUrl: string,
		headers: Headers,
		fetchImpl?: (...args: any) => any,
	) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");
		const newHeaders = new Headers();
		let callbackURL = "";
		await betterFetch(location, {
			method: "GET",
			customFetchImpl: fetchImpl || customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should return shared redirectURI when registering provider", async () => {
		const { headers } = await signInWithTestUser();
		const provider = await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "shared-redirect.com",
				oidcConfig: {
					clientId: "shared-test",
					clientSecret: "shared-test-secret",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
				providerId: "shared-test",
			},
			headers,
		});
		// Should use the shared redirect URI, not per-provider
		expect(provider.redirectURI).toBe(
			"http://localhost:3000/api/auth/sso/callback",
		);
		expect(provider.redirectURI).not.toContain("shared-test");
	});

	it("should use shared redirect URI in authorization URL", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "user@shared-redirect.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		expect(res.url).toContain("http://localhost:8080/authorize");
		// Should use shared redirect URI without providerId in path
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback",
		);
		// Should NOT contain the per-provider path
		expect(res.url).not.toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Fshared-test",
		);
	});

	it("should complete OIDC flow using shared callback endpoint", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "user@shared-redirect.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});
		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			res.url,
			headers,
		);
		expect(callbackURL).toContain("/dashboard");

		// Verify session was created
		const session = await authClient.getSession({
			fetchOptions: {
				headers: sessionHeaders,
			},
		});
		expect(session.data?.user.email).toBe("shared-redirect@test.com");
	});
});

describe("OIDC SSO with defaultSSO array", async () => {
	const { auth, customFetchImpl, cookieSetter } = await getTestInstance({
		trustedOrigins: ["http://localhost:8084"],
		plugins: [
			sso({
				trustEmailVerified: true,
				domainVerification: {
					enabled: true,
					trustEmailOwnership: true,
				},
				defaultSSO: [
					{
						domain: "default-oidc.com",
						providerId: "default-oidc-provider",
						oidcConfig: {
							issuer: "http://localhost:8084",
							clientId: "default-client",
							clientSecret: "default-secret",
							pkce: false,
							// No explicit authorizationEndpoint / tokenEndpoint / jwksEndpoint
							// All resolved via OIDC discovery
							discoveryEndpoint:
								"http://localhost:8084/.well-known/openid-configuration",
						},
					},
					{
						domain: "default-oidc-explicit.com",
						providerId: "default-oidc-provider-explicit",
						oidcConfig: {
							issuer: "http://localhost:8084",
							clientId: "explicit-client",
							clientSecret: "explicit-secret",
							pkce: false,
							// All endpoints set explicitly – discovery should be skipped
							authorizationEndpoint: "http://localhost:8084/authorize",
							tokenEndpoint: "http://localhost:8084/token",
							jwksEndpoint: "http://localhost:8084/jwks",
							discoveryEndpoint:
								"http://localhost:8084/.well-known/openid-configuration",
						},
					},
					{
						domain:
							"https://default-oidc-normalized.com/path,default-oidc-secondary.com",
						providerId: "default-oidc-provider-normalized",
						oidcConfig: {
							issuer: "http://localhost:8084",
							clientId: "normalized-client",
							clientSecret: "normalized-secret",
							pkce: false,
							authorizationEndpoint: "http://localhost:8084/authorize",
							tokenEndpoint: "http://localhost:8084/token",
							jwksEndpoint: "http://localhost:8084/jwks",
							discoveryEndpoint:
								"http://localhost:8084/.well-known/openid-configuration",
						},
					},
				],
			}),
			organization(),
		],
	});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: { customFetchImpl },
	});

	// Shared state set during token signing so the userinfo handler knows which client is active
	let currentEmail = "default-sso-user@default-oidc.com";
	let currentSub = "default-sso-sub";
	let currentEmailVerified: boolean | string | undefined = true;
	let currentIdentityOverride: { email: string; sub: string } | undefined;

	const userinfoHandler = (userInfoResponse: any) => {
		userInfoResponse.body = {
			email: currentEmail,
			name: "Default SSO User",
			sub: currentSub,
			picture: "https://test.com/default.png",
			email_verified: currentEmailVerified,
		};
		userInfoResponse.statusCode = 200;
	};

	const tokenHandler = (token: any) => {
		const isExplicit = token.payload.aud === "explicit-client";
		const isNormalized = token.payload.aud === "normalized-client";
		currentEmail =
			currentIdentityOverride?.email ??
			(isNormalized
				? "default-sso-user@default-oidc-secondary.com"
				: isExplicit
					? "default-sso-user@default-oidc-explicit.com"
					: "default-sso-user@default-oidc.com");
		currentSub =
			currentIdentityOverride?.sub ??
			(isNormalized
				? "normalized-sso-sub"
				: isExplicit
					? "explicit-sso-sub"
					: "default-sso-sub");
		token.payload.email = currentEmail;
		token.payload.email_verified = currentEmailVerified;
		token.payload.name = "Default SSO User";
		token.payload.picture = "https://test.com/default.png";
		token.payload.sub = currentSub;
	};

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.on("beforeUserinfo", userinfoHandler);
		server.service.on("beforeTokenSigning", tokenHandler);
		await server.start(8084, "localhost");
	});

	afterAll(async () => {
		server.service.removeListener("beforeUserinfo", userinfoHandler);
		server.service.removeListener("beforeTokenSigning", tokenHandler);
		await server.stop().catch(() => {});
	});

	async function simulateOAuthFlow(authUrl: string, headers: Headers) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");
		const newHeaders = new Headers();
		let callbackURL = "";
		await betterFetch(location, {
			method: "GET",
			customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should sign in via defaultSSO OIDC using providerId (discovery resolves endpoints)", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "default-oidc-provider",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});

		// Authorization URL must point to the mock IdP resolved via discovery
		expect(res.url).toContain("http://localhost:8084/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Fdefault-oidc-provider",
		);

		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			res.url,
			headers,
		);
		expect(callbackURL).toContain("/dashboard");

		const session = await authClient.getSession({
			fetchOptions: { headers: sessionHeaders },
		});
		expect(session.data?.user.email).toBe("default-sso-user@default-oidc.com");
	});

	it("should sign in via defaultSSO OIDC using email domain matching", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "someone@default-oidc.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});

		expect(res.url).toContain("http://localhost:8084/authorize");

		const { callbackURL } = await simulateOAuthFlow(res.url, headers);
		expect(callbackURL).toContain("/dashboard");
	});

	it("should sign in via defaultSSO OIDC using normalized domain matching", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			email: "someone@default-oidc-secondary.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});

		expect(res.url).toContain("http://localhost:8084/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Fdefault-oidc-provider-normalized",
		);

		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			res.url,
			headers,
		);
		expect(callbackURL).toContain("/dashboard");

		const session = await authClient.getSession({
			fetchOptions: { headers: sessionHeaders },
		});
		expect(session.data?.user.email).toBe(
			"default-sso-user@default-oidc-secondary.com",
		);
	});

	it("should sign in via defaultSSO OIDC with all endpoints explicit (no discovery needed)", async () => {
		const headers = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "default-oidc-provider-explicit",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(headers),
			},
		});

		expect(res.url).toContain("http://localhost:8084/authorize");
		expect(res.url).toContain(
			"redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fsso%2Fcallback%2Fdefault-oidc-provider-explicit",
		);

		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			res.url,
			headers,
		);
		expect(callbackURL).toContain("/dashboard");

		const session = await authClient.getSession({
			fetchOptions: { headers: sessionHeaders },
		});
		expect(session.data?.user.email).toBe(
			"default-sso-user@default-oidc-explicit.com",
		);
	});

	it.each([
		{ claim: true, expected: true },
		{ claim: "true", expected: true },
		{ claim: "false", expected: false },
		{ claim: undefined, expected: false },
	])(
		"keeps configured default OIDC domain trust separate from email_verified=$claim",
		async ({ claim, expected }) => {
			currentIdentityOverride = {
				email: `claim-${String(claim)}@default-oidc.com`,
				sub: `claim-${String(claim)}`,
			};
			currentEmail = currentIdentityOverride.email;
			currentSub = currentIdentityOverride.sub;
			currentEmailVerified = claim;
			const headers = new Headers();
			const response = await authClient.signIn.sso({
				providerId: "default-oidc-provider",
				callbackURL: "/dashboard",
				fetchOptions: {
					throw: true,
					onSuccess: cookieSetter(headers),
				},
			});
			const { callbackURL } = await simulateOAuthFlow(response.url, headers);
			expect(callbackURL).toContain("/dashboard");
			const context = await auth.$context;
			const user = await context.adapter.findOne<{ emailVerified: boolean }>({
				model: "user",
				where: [{ field: "email", value: currentEmail }],
			});
			expect(user?.emailVerified).toBe(expected);
			currentIdentityOverride = undefined;
		},
	);
});

describe("OIDC SSO with private_key_jwt", async () => {
	let privateJwk: JsonWebKey;
	let publicJwk: JsonWebKey;
	let capturedTokenRequest: Record<string, any> | undefined;

	const resolvePrivateKey = vi.fn(async ({ keyId }: { keyId?: string }) => ({
		privateKeyJwk: privateJwk,
		kid: keyId,
		algorithm: "RS256",
	}));

	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8080"],
			plugins: [
				sso({
					resolvePrivateKey,
				}),
				organization(),
			],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: { customFetchImpl },
	});

	const userinfoHandler = (userInfoResponse: any) => {
		userInfoResponse.body = {
			email: "jwt-auth-user@private-key-jwt.com",
			name: "Private Key JWT User",
			sub: "private-key-jwt-sub",
			picture: "https://test.com/private-key-jwt.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	};

	const tokenHandler = (token: any) => {
		token.payload.email = "jwt-auth-user@private-key-jwt.com";
		token.payload.email_verified = true;
		token.payload.name = "Private Key JWT User";
		token.payload.picture = "https://test.com/private-key-jwt.png";
		token.payload.sub = "private-key-jwt-sub";
	};

	const responseHandler = (_tokenEndpointResponse: any, req: any) => {
		capturedTokenRequest = { ...(req.body ?? {}) };
	};

	beforeAll(async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS256", {
			extractable: true,
		});
		privateJwk = await exportJWK(privateKey);
		publicJwk = await exportJWK(publicKey);

		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.removeAllListeners("beforeResponse");
		server.service.on("beforeUserinfo", userinfoHandler);
		server.service.on("beforeTokenSigning", tokenHandler);
		server.service.on("beforeResponse", responseHandler);
		await server.issuer.keys.generate("RS256");
		await server.start(8080, "localhost");

		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			headers,
			body: {
				issuer: server.issuer.url!,
				domain: "private-key-jwt.com",
				providerId: "private-key-jwt-provider",
				oidcConfig: {
					clientId: "private-key-jwt-client",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
					tokenEndpointAuthentication: "private_key_jwt",
					privateKeyId: "private-key-jwt-key",
					privateKeyAlgorithm: "RS256",
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
						image: "picture",
					},
				},
			},
		});
	});

	afterAll(async () => {
		server.service.removeListener("beforeUserinfo", userinfoHandler);
		server.service.removeListener("beforeTokenSigning", tokenHandler);
		server.service.removeListener("beforeResponse", responseHandler);
		await server.stop().catch(() => {});
	});

	async function simulateOAuthFlow(authUrl: string, headers: Headers) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");
		const newHeaders = new Headers();
		let callbackURL = "";
		await betterFetch(location, {
			method: "GET",
			customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should sign in using private_key_jwt and resolvePrivateKey", async () => {
		capturedTokenRequest = undefined;
		resolvePrivateKey.mockClear();

		const signInHeaders = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "private-key-jwt-provider",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});

		expect(res.url).toContain("http://localhost:8080/authorize");

		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			res.url,
			signInHeaders,
		);
		expect(callbackURL).toContain("/dashboard");

		expect(resolvePrivateKey).toHaveBeenCalledWith({
			providerId: "private-key-jwt-provider",
			keyId: "private-key-jwt-key",
			issuer: server.issuer.url!,
		});
		expect(capturedTokenRequest).toBeDefined();
		const tokenReq = capturedTokenRequest! as unknown as Record<
			string,
			unknown
		>;
		expect(tokenReq.client_assertion).toBeDefined();
		expect(tokenReq.client_assertion_type).toBe(
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		);
		expect(tokenReq.client_id).toBe("private-key-jwt-client");
		expect(tokenReq.client_secret).toBeUndefined();

		const jwks = createLocalJWKSet({
			keys: [
				{
					...publicJwk,
					kid: "private-key-jwt-key",
					alg: "RS256",
					use: "sig",
				},
			],
		});
		const { payload } = await jwtVerify(
			tokenReq.client_assertion as string,
			jwks,
			{
				algorithms: ["RS256"],
				audience: `${server.issuer.url}/token`,
			},
		);
		expect(payload.iss).toBe("private-key-jwt-client");
		expect(payload.sub).toBe("private-key-jwt-client");

		const session = await authClient.getSession({
			fetchOptions: { headers: sessionHeaders },
		});
		expect(session.data?.user.email).toBe("jwt-auth-user@private-key-jwt.com");
	});

	it("should redirect with no_private_key_available when resolvePrivateKey returns no key material", async () => {
		resolvePrivateKey.mockResolvedValueOnce(
			{} as Awaited<ReturnType<typeof resolvePrivateKey>>,
		);

		const signInHeaders = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "private-key-jwt-provider",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});

		const { callbackURL } = await simulateOAuthFlow(res.url, signInHeaders);
		expect(callbackURL).toContain("error_description=no_private_key_available");
	});
});

/**
 * @see https://github.com/better-auth/better-auth/issues/8269
 */
describe("SSO OIDC UserInfo endpoint sub claim mapping", async () => {
	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8080"],
			plugins: [sso(), organization()],
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: { customFetchImpl },
	});

	const userinfoHandler = (userInfoResponse: any) => {
		userInfoResponse.body = {
			sub: "userinfo-only-sub-id",
			email: "userinfo-only@test.com",
			name: "UserInfo Only User",
			picture: "https://test.com/picture.png",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	};

	// Strip the id_token from the token endpoint response to simulate providers
	// that do not include user claims in the ID token (or return no ID token).
	const beforeResponseHandler = (tokenEndpointResponse: any) => {
		tokenEndpointResponse.body.id_token = undefined;
	};

	const tokenHandler = (token: any) => {
		// Intentionally leave the token payload minimal — no email claim —
		// so that the UserInfo endpoint path is exercised.
	};

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		server.service.removeAllListeners("beforeUserinfo");
		server.service.removeAllListeners("beforeTokenSigning");
		server.service.removeAllListeners("beforeResponse");
		server.service.on("beforeUserinfo", userinfoHandler);
		server.service.on("beforeTokenSigning", tokenHandler);
		server.service.on("beforeResponse", beforeResponseHandler);
		await server.start(8080, "localhost");
	});

	afterAll(async () => {
		server.service.removeListener("beforeUserinfo", userinfoHandler);
		server.service.removeListener("beforeTokenSigning", tokenHandler);
		server.service.removeListener("beforeResponse", beforeResponseHandler);
		await server.stop().catch(() => {});
	});

	async function simulateOAuthFlow(authUrl: string, headers: Headers) {
		let location: string | null = null;
		await betterFetch(authUrl, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		if (!location) throw new Error("No redirect location found");
		const newHeaders = new Headers();
		let callbackURL = "";
		await betterFetch(location, {
			method: "GET",
			customFetchImpl,
			headers,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
				cookieSetter(newHeaders)(context);
			},
		});

		return { callbackURL, headers: newHeaders };
	}

	it("should sign in successfully using sub claim from UserInfo endpoint when no ID token is returned", async () => {
		const { headers } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				issuer: server.issuer.url!,
				domain: "test.com",
				providerId: "userinfo-sub-test",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${server.issuer.url}/authorize`,
					tokenEndpoint: `${server.issuer.url}/token`,
					jwksEndpoint: `${server.issuer.url}/jwks`,
					userInfoEndpoint: `${server.issuer.url}/userinfo`,
					discoveryEndpoint: `${server.issuer.url}/.well-known/openid-configuration`,
				},
			},
			headers,
		});

		const signInHeaders = new Headers();
		const res = await authClient.signIn.sso({
			email: "user@test.com",
			callbackURL: "/dashboard",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});

		const { callbackURL, headers: sessionHeaders } = await simulateOAuthFlow(
			res.url,
			signInHeaders,
		);

		// Should redirect to dashboard, not an error page
		expect(callbackURL).toContain("/dashboard");
		expect(callbackURL).not.toContain("error=invalid_provider");
		expect(callbackURL).not.toContain("missing_user_info");

		// Verify the session was created with the correct email from UserInfo
		const session = await authClient.getSession({
			fetchOptions: { headers: sessionHeaders },
		});
		expect(session.data?.user.email).toBe("userinfo-only@test.com");
	});

	/**
	 * @see https://github.com/better-auth/better-auth/security/advisories/GHSA-5rr4-8452-hf4v
	 */
	describe("skipDiscovery SSRF protection (registerSSOProvider)", () => {
		it("should reject registration when tokenEndpoint points to a non-publicly-routable host", async () => {
			const { headers } = await signInWithTestUser();

			await expect(
				auth.api.registerSSOProvider({
					body: {
						issuer: server.issuer.url!,
						domain: "ssrf-token.com",
						providerId: "ssrf-token-endpoint",
						oidcConfig: {
							clientId: "test",
							clientSecret: "test",
							skipDiscovery: true,
							authorizationEndpoint: `${server.issuer.url}/authorize`,
							tokenEndpoint: "http://169.254.169.254/latest/meta-data/",
							jwksEndpoint: `${server.issuer.url}/jwks`,
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					code: "discovery_private_host",
				},
			});
		});

		it("should reject registration when userInfoEndpoint points to a cloud metadata host", async () => {
			const { headers } = await signInWithTestUser();

			await expect(
				auth.api.registerSSOProvider({
					body: {
						issuer: server.issuer.url!,
						domain: "ssrf-userinfo.com",
						providerId: "ssrf-userinfo-endpoint",
						oidcConfig: {
							clientId: "test",
							clientSecret: "test",
							skipDiscovery: true,
							authorizationEndpoint: `${server.issuer.url}/authorize`,
							tokenEndpoint: `${server.issuer.url}/token`,
							jwksEndpoint: `${server.issuer.url}/jwks`,
							userInfoEndpoint:
								"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					code: "discovery_private_host",
				},
			});
		});

		it("should reject registration when jwksEndpoint points to a loopback port not in trustedOrigins", async () => {
			const { headers } = await signInWithTestUser();

			await expect(
				auth.api.registerSSOProvider({
					body: {
						issuer: server.issuer.url!,
						domain: "ssrf-jwks.com",
						providerId: "ssrf-jwks-endpoint",
						oidcConfig: {
							clientId: "test",
							clientSecret: "test",
							skipDiscovery: true,
							authorizationEndpoint: `${server.issuer.url}/authorize`,
							tokenEndpoint: `${server.issuer.url}/token`,
							jwksEndpoint: "http://localhost:6379/",
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					code: "discovery_private_host",
				},
			});
		});

		it("should reject registration when an endpoint is not a valid URL", async () => {
			const { headers } = await signInWithTestUser();

			await expect(
				auth.api.registerSSOProvider({
					body: {
						issuer: server.issuer.url!,
						domain: "ssrf-invalid.com",
						providerId: "ssrf-invalid-url",
						oidcConfig: {
							clientId: "test",
							clientSecret: "test",
							skipDiscovery: true,
							authorizationEndpoint: `${server.issuer.url}/authorize`,
							tokenEndpoint: "not-a-url",
							jwksEndpoint: `${server.issuer.url}/jwks`,
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				body: {
					code: "VALIDATION_ERROR",
				},
			});
		});

		it("should reject registration when an endpoint uses a non-http(s) protocol", async () => {
			const { headers } = await signInWithTestUser();

			await expect(
				auth.api.registerSSOProvider({
					body: {
						issuer: server.issuer.url!,
						domain: "ssrf-protocol.com",
						providerId: "ssrf-bad-protocol",
						oidcConfig: {
							clientId: "test",
							clientSecret: "test",
							skipDiscovery: true,
							authorizationEndpoint: `${server.issuer.url}/authorize`,
							tokenEndpoint: "file:///etc/passwd",
							jwksEndpoint: `${server.issuer.url}/jwks`,
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					code: "discovery_invalid_url",
				},
			});
		});

		it("should accept registration when endpoints match a trustedOrigins entry", async () => {
			const { headers } = await signInWithTestUser();

			const provider = await auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain: "ssrf-trusted.com",
					providerId: "ssrf-trusted-endpoints",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
						skipDiscovery: true,
						authorizationEndpoint: `${server.issuer.url}/authorize`,
						tokenEndpoint: `${server.issuer.url}/token`,
						jwksEndpoint: `${server.issuer.url}/jwks`,
						userInfoEndpoint: `${server.issuer.url}/userinfo`,
					},
				},
				headers,
			});

			expect(provider.providerId).toBe("ssrf-trusted-endpoints");
		});

		it("should reject registration when oidcConfig endpoints point to a private host even without skipDiscovery", async () => {
			const { headers } = await signInWithTestUser();

			await expect(
				auth.api.registerSSOProvider({
					body: {
						issuer: server.issuer.url!,
						domain: "ssrf-override.com",
						providerId: "ssrf-override-endpoint",
						oidcConfig: {
							clientId: "test",
							clientSecret: "test",
							tokenEndpoint: "http://169.254.169.254/token",
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					code: "discovery_private_host",
				},
			});
		});
	});

	/**
	 * @see https://github.com/better-auth/better-auth/security/advisories/GHSA-5rr4-8452-hf4v
	 */
	describe("OIDC endpoint SSRF protection (updateSSOProvider)", () => {
		it("should reject update when oidcConfig contains a link-local endpoint", async () => {
			const { headers } = await signInWithTestUser();

			const provider = await auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain: "ssrf-update-target.com",
					providerId: "ssrf-update-target",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
						skipDiscovery: true,
						authorizationEndpoint: `${server.issuer.url}/authorize`,
						tokenEndpoint: `${server.issuer.url}/token`,
						jwksEndpoint: `${server.issuer.url}/jwks`,
					},
				},
				headers,
			});

			await expect(
				auth.api.updateSSOProvider({
					body: {
						providerId: provider.providerId,
						oidcConfig: {
							userInfoEndpoint:
								"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					code: "discovery_private_host",
				},
			});
		});

		it("should reject update when oidcConfig contains an invalid URL", async () => {
			const { headers } = await signInWithTestUser();

			const provider = await auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain: "ssrf-update-invalid.com",
					providerId: "ssrf-update-invalid",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
						skipDiscovery: true,
						authorizationEndpoint: `${server.issuer.url}/authorize`,
						tokenEndpoint: `${server.issuer.url}/token`,
						jwksEndpoint: `${server.issuer.url}/jwks`,
					},
				},
				headers,
			});

			await expect(
				auth.api.updateSSOProvider({
					body: {
						providerId: provider.providerId,
						oidcConfig: {
							tokenEndpoint: "not-a-url",
						},
					},
					headers,
				}),
			).rejects.toMatchObject({
				body: {
					code: "VALIDATION_ERROR",
				},
			});
		});

		it("should accept update when oidcConfig endpoints are trusted", async () => {
			const { headers } = await signInWithTestUser();

			const provider = await auth.api.registerSSOProvider({
				body: {
					issuer: server.issuer.url!,
					domain: "ssrf-update-trusted.com",
					providerId: "ssrf-update-trusted",
					oidcConfig: {
						clientId: "test",
						clientSecret: "test",
						skipDiscovery: true,
						authorizationEndpoint: `${server.issuer.url}/authorize`,
						tokenEndpoint: `${server.issuer.url}/token`,
						jwksEndpoint: `${server.issuer.url}/jwks`,
					},
				},
				headers,
			});

			const updated = await auth.api.updateSSOProvider({
				body: {
					providerId: provider.providerId,
					oidcConfig: {
						userInfoEndpoint: `${server.issuer.url}/userinfo`,
					},
				},
				headers,
			});

			expect(updated.providerId).toBe("ssrf-update-trusted");
		});
	});
});

describe("SSO OIDC hook rejection redirect", async () => {
	const hookServer = new OAuth2Server();

	beforeAll(async () => {
		await hookServer.issuer.keys.generate("RS256");
		await hookServer.start(8090, "localhost");
	});

	afterAll(async () => {
		await hookServer.stop().catch(() => {});
	});

	hookServer.service.on("beforeUserinfo", (userInfoResponse) => {
		userInfoResponse.body = {
			email: "rejected@test.com",
			name: "Rejected User",
			sub: "rejected-sub",
			email_verified: true,
		};
		userInfoResponse.statusCode = 200;
	});

	hookServer.service.on("beforeTokenSigning", (token) => {
		token.payload.sub = "rejected-sub";
		token.payload.email = "rejected@test.com";
		token.payload.email_verified = true;
	});

	const { auth, signInWithTestUser, customFetchImpl, cookieSetter } =
		await getTestInstance({
			trustedOrigins: ["http://localhost:8090", "https://frontend.example.com"],
			plugins: [sso()],
			databaseHooks: {
				session: {
					create: {
						before: async (session, ctx) => {
							if (!ctx) return;
							const user = await ctx.context.internalAdapter.findUserById(
								session.userId,
							);
							if (user?.email === "rejected@test.com") {
								throw APIError.from("FORBIDDEN", {
									code: "HOOK_REJECTED",
									message: "SSO hook rejected this user",
								});
							}
						},
					},
				},
			},
		});

	const authClient = createAuthClient({
		plugins: [ssoClient()],
		baseURL: "http://localhost:3000",
		fetchOptions: { customFetchImpl },
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/10022
	 */
	it("should preserve the errorCallbackURL query and fragment when a session hook throws", async () => {
		const { headers: adminHeaders } = await signInWithTestUser();
		await auth.api.registerSSOProvider({
			body: {
				issuer: hookServer.issuer.url!,
				domain: "hook-reject.com",
				providerId: "hook-reject",
				oidcConfig: {
					clientId: "test",
					clientSecret: "test",
					authorizationEndpoint: `${hookServer.issuer.url}/authorize`,
					tokenEndpoint: `${hookServer.issuer.url}/token`,
					jwksEndpoint: `${hookServer.issuer.url}/jwks`,
					discoveryEndpoint: `${hookServer.issuer.url}/.well-known/openid-configuration`,
					mapping: {
						email: "email",
						emailVerified: "email_verified",
						name: "name",
					},
				},
			},
			headers: adminHeaders,
		});

		const signInHeaders = new Headers();
		const res = await authClient.signIn.sso({
			providerId: "hook-reject",
			callbackURL: "https://frontend.example.com/dashboard",
			errorCallbackURL:
				"https://frontend.example.com/auth-error?source=sso#retry",
			fetchOptions: {
				throw: true,
				onSuccess: cookieSetter(signInHeaders),
			},
		});

		let location: string | null = null;
		await betterFetch(res.url, {
			method: "GET",
			redirect: "manual",
			onError(context) {
				location = context.response.headers.get("location");
			},
		});

		let callbackURL = "";
		await betterFetch(location!, {
			method: "GET",
			customFetchImpl,
			headers: signInHeaders,
			onError(context) {
				callbackURL = context.response.headers.get("location") || "";
			},
		});

		const url = new URL(callbackURL);
		expect(url.origin).toBe("https://frontend.example.com");
		expect(url.pathname).toBe("/auth-error");
		expect(url.searchParams.get("source")).toBe("sso");
		expect(url.searchParams.get("error")).toBe("HOOK_REJECTED");
		expect(url.searchParams.get("error_description")).toBe(
			"SSO hook rejected this user",
		);
		expect(url.hash).toBe("#retry");
	});
});

describe("SSO OIDC IDP-initiated bounce", async () => {
	const { customFetchImpl } = await getTestInstance({
		trustedOrigins: ["http://localhost:8080"],
		plugins: [
			sso({
				defaultSSO: [
					{
						domain: "idp-initiated.com",
						providerId: "idp-initiated",
						oidcConfig: {
							issuer: "http://localhost:8080",
							clientId: "idp-initiated-client",
							clientSecret: "idp-initiated-secret",
							pkce: true,
							discoveryEndpoint:
								"http://localhost:8080/.well-known/openid-configuration",
							allowIdpInitiated: true,
						},
					},
					{
						domain: "strict-oidc.com",
						providerId: "strict-oidc",
						oidcConfig: {
							issuer: "http://localhost:8080",
							clientId: "strict-client",
							clientSecret: "strict-secret",
							pkce: true,
							discoveryEndpoint:
								"http://localhost:8080/.well-known/openid-configuration",
						},
					},
				],
			}),
		],
	});

	beforeAll(async () => {
		await server.issuer.keys.generate("RS256");
		await server.start(8080, "localhost");
	});

	afterAll(async () => {
		await server.stop().catch(() => {});
	});

	it("should bounce a stateless OIDC callback to the provider's authorize endpoint when allowIdpInitiated is true", async () => {
		const res = await customFetchImpl(
			"http://localhost:3000/api/auth/sso/callback/idp-initiated?code=idp-issued-code",
			{ method: "GET", redirect: "manual" },
		);

		expect(res.status).toBe(302);
		const location = res.headers.get("location") || "";
		expect(location).toContain("http://localhost:8080/authorize");
		const url = new URL(location);
		expect(url.searchParams.get("state")).toBeTruthy();
		expect(url.searchParams.get("client_id")).toBe("idp-initiated-client");
		expect(url.searchParams.get("code")).toBeNull();
	});

	it("should not bounce when the `code` parameter is empty", async () => {
		const res = await customFetchImpl(
			"http://localhost:3000/api/auth/sso/callback/idp-initiated?code=",
			{ method: "GET", redirect: "manual" },
		);

		expect(res.status).toBe(302);
		const location = res.headers.get("location") || "";
		expect(location).not.toContain("http://localhost:8080/authorize");
	});

	it("should not bounce on an empty `state=` parameter, only on truly stateless callbacks", async () => {
		const res = await customFetchImpl(
			"http://localhost:3000/api/auth/sso/callback/idp-initiated?code=idp-issued-code&state=",
			{ method: "GET", redirect: "manual" },
		);

		expect(res.status).toBe(302);
		const location = res.headers.get("location") || "";
		expect(location).not.toContain("http://localhost:8080/authorize");
		expect(location).toContain("state_not_found");
	});

	it("should carry ssoProviderId in the bounced state when options.redirectURI is configured", async () => {
		const { customFetchImpl: sharedRedirectFetch, auth: sharedRedirectAuth } =
			await getTestInstance({
				trustedOrigins: ["http://localhost:8080"],
				plugins: [
					sso({
						redirectURI: "/sso/callback",
						defaultSSO: [
							{
								domain: "idp-initiated-shared.com",
								providerId: "idp-initiated-shared",
								oidcConfig: {
									issuer: "http://localhost:8080",
									clientId: "idp-initiated-shared-client",
									clientSecret: "idp-initiated-shared-secret",
									pkce: true,
									discoveryEndpoint:
										"http://localhost:8080/.well-known/openid-configuration",
									allowIdpInitiated: true,
								},
							},
						],
					}),
				],
			});

		const res = await sharedRedirectFetch(
			"http://localhost:3000/api/auth/sso/callback/idp-initiated-shared?code=idp-issued-code",
			{ method: "GET", redirect: "manual" },
		);

		expect(res.status).toBe(302);
		const location = res.headers.get("location") || "";
		expect(location).toContain("http://localhost:8080/authorize");
		const url = new URL(location);
		expect(url.searchParams.get("redirect_uri")).toBe(
			"http://localhost:3000/api/auth/sso/callback",
		);
		const stateNonce = url.searchParams.get("state");
		expect(stateNonce).toBeTruthy();

		// The shared callback resolves the provider from the server-only
		// `serverContext` channel, so the bounce must write `ssoProviderId` there
		// and never into the client-controlled top-level state.
		const ctx = await sharedRedirectAuth.$context;
		const verification = await ctx.internalAdapter.findVerificationValue(
			getAuthStateVerificationIdentifier(stateNonce!),
		);
		const parsedState = JSON.parse(verification!.value);
		expect(parsedState.serverContext?.ssoProviderReference?.providerId).toBe(
			"idp-initiated-shared",
		);
		expect(parsedState.ssoProviderId).toBeUndefined();
	});

	it("should redirect to the error page for providers without the flag", async () => {
		const res = await customFetchImpl(
			"http://localhost:3000/api/auth/sso/callback/strict-oidc?code=idp-issued-code",
			{ method: "GET", redirect: "manual" },
		);

		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toContain("state_not_found");
	});
});
