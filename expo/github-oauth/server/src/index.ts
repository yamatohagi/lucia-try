import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { auth, githubAuth } from "./auth";
import { OAuthRequestError } from "@lucia-auth/oauth";

const app = new Hono();

app.get("/user", async (c) => {
	const authRequest = auth.handleRequest(c);
	const session = await authRequest.validateBearerToken();
	if (!session) {
		return c.newResponse(null, 401);
	}
	return c.json(session.user);
});

app.get("/login/github", async (c) => {
	const redirect_uri = c.req.query("redirect_uri");
	const [authorizationUrl, state] = await githubAuth.getAuthorizationUrl();
	setCookie(c, "github_oauth_state", state, {
		path: "/",
		maxAge: 60 * 10,
		httpOnly: true,
		secure: process.env.NODE_ENV === "production"
	});
	console.log("redirect_uri", redirect_uri);
	//	return c.redirect(`${authorizationUrl.toString()}?redirect_uri=${redirect_uri}`);
	return c.redirect(authorizationUrl.toString());
});

app.get("/login/github/callback", async (c) => {
	console.log(c.req.url);
	const url = new URL(c.req.url);
	const code = url.searchParams.get("code");
	if (!code) return c.newResponse(null, 400);
	const state = url.searchParams.get("state");
	const storedState = getCookie(c, "github_oauth_state");
	if (!state || !storedState || state !== storedState) {
		return c.newResponse(null, 400);
	}
	try {
		const { getExistingUser, githubUser, createUser } =
			await githubAuth.validateCallback(code);
		let user = await getExistingUser();
		if (!user) {
			user = await createUser({
				attributes: {
					username: githubUser.login
				}
			});
		}
		const session = await auth.createSession({
			userId: user.userId,
			attributes: {}
		});
		return c.redirect(
			// change this part before starting your server
			`com.anonymous.luciatestyama:/login?session_token=${session.sessionId}`
		);
	} catch (e) {
		console.log(e);
		if (e instanceof OAuthRequestError) {
			// invalid code
			return c.newResponse(null, 400);
		}
		return c.newResponse(null, 500);
	}
});

app.post("/logout", async (c) => {
	const authRequest = auth.handleRequest(c);
	const session = await authRequest.validateBearerToken();
	if (!session) return c.newResponse(null, 401);
	await auth.invalidateSession(session.sessionId);
	return c.newResponse(null, 200);
});

serve(app);
