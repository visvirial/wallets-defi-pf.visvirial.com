/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.json`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import bcrypt from 'bcryptjs';

export const authorize = async (env: Env, body: any): Promise<boolean> => {
	const data = await env.WALLETS.get(body.email);
	if(!data) {
		return false;
	}
	const json = JSON.parse(data);
	return await bcrypt.compare(body.password, json.passwordHash);
};

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const method = request.method;
		const body = await (async () => {
			if(method === 'GET') {
				const json = {};
				for(const [key, value] of url.searchParams.entries()) {
					json[key] = value;
				}
				return json;
			}
			if(method === 'POST') {
				try {
					const body = await new Response(request.body).json();
					return body;
				} catch (e) {
					return new Response('Invalid JSON', { status: 400 });
				}
			}
		})();
		//console.log('Body:', body);
		if(body) {
			// Check if the email parameter is set.
			if(!body.email) {
				return new Response('Parameter "email" not set.', { status: 400 });
			}
			// Check if the password parameter is set.
			if(!body.password) {
				return new Response('Parameter "password" not set.', { status: 400 });
			}
		}
		if(url.pathname === '/register' && method === 'POST') {
			// POST /register.
			// If the user already exists, return 409.
			const _data = await env.WALLETS.get(body.email);
			if(_data) {
				return new Response('User already exists', { status: 409 });
			}
			// Create a new user.
			const passwordhash = await bcrypt.hash(body.password, 10);
			//console.log('Password hash:', passwordHash);
			const data = {
				passwordHash,
				wallets: '',
			};
			await env.WALLETS.put(body.email, JSON.stringify(data));
			return new Response('User created', { status: 201 });
		} else if(url.pathname === '/changepw' && method === 'POST') {
			// POST /changepw.
			// Check if the newPassword parameter is set.
			if(!body.newPassword) {
				return new Response('Parameter "newPassword" not set.', { status: 400 });
			}
			if(!await authorize(env, body)) {
				return new Response('Unauthorized', { status: 401 });
			}
			// Change the password.
			const passwordHash = await bcrypt.hash(body.newPassword, 10);
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			json.passwordHash = passwordHash;
			await env.WALLETS.put(body.email, JSON.stringify(json));
			return new Response('Password changed');
		} else if(url.pathname === '/get' && method === 'GET') {
			// GET /get.
			if(!await authorize(env, body)) {
				return new Response('Unauthorized', { status: 401 });
			}
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			return new Response(json.wallets);
		} else if(url.pathname === '/set' && method === 'POST') {
			// POST /set.
			// Check if the wallets parameter is set.
			if(!body.wallets) {
				return new Response('Parameter "wallets" not set.', { status: 400 });
			}
			if(!await authorize(env, body)) {
				return new Response('Unauthorized', { status: 401 });
			}
			// Set the wallets.
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			json.wallets = body.wallets;
			await env.WALLETS.put(body.email, JSON.stringify(json));
		} else if(url.pathname === '/get' && method === 'GET') {
			// GET /get.
			if(!await authorize(env, body)) {
				return new Response('Unauthorized', { status: 401 });
			}
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			return new Response(json.wallets);
		} else {
			return new Response('Not found', { status: 404 });
		}
	},
} satisfies ExportedHandler<Env>;

