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

import crypto from 'crypto';

import bcrypt from 'bcryptjs';
import aesjs from 'aes-js';

export const authorize = async (env: Env, body: any): Promise<boolean> => {
	const data = await env.WALLETS.get(body.email);
	if(!data) {
		return false;
	}
	const json = JSON.parse(data);
	return await bcrypt.compare(body.password, json.passwordHash);
};

const SALT = 'wallets-defi-pf.visvirial.com';

export const getKey = (password: string): Buffer => {
	const key = crypto.pbkdf2Sync(password, SALT, 100000, 32, 'sha256');
	return key;
}

export const encrypt = (plaintext: string, password: string): Promise<string> => {
	const key = getKey(password);
	const iv = crypto.randomBytes(16);
	const plaintextBytes = aesjs.utils.utf8.toBytes(plaintext);
	const aesCbc = new aesjs.ModeOfOperation.ctr(key, iv);
	const encryptedBytes = aesCbc.encrypt(plaintextBytes);
	const encryptedHex = iv.toString('hex') + aesjs.utils.hex.fromBytes(encryptedBytes);
	return encryptedHex;
};

export const decrypt = (ciphertext: string, password: string): Promise<string> => {
	const key = getKey(password);
	const encryptedBytes = aesjs.utils.hex.toBytes(ciphertext);
	const aesCbc = new aesjs.ModeOfOperation.ctr(key, encryptedBytes.slice(0, 16));
	const decryptedBytes = aesCbc.decrypt(encryptedBytes.slice(16));
	const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
	return decryptedText;
};

export const respond = (...args): Response => {
	const response = new Response(...args);
	response.headers.set('Access-Control-Allow-Origin', '*');
	response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
	return response;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		// Handle OPTIONS requests.
		if(request.method === 'OPTIONS') {
			if (
				request.headers.get('Origin') !== null &&
				request.headers.get('Access-Control-Request-Method') !== null &&
				request.headers.get('Access-Control-Request-Headers') !== null
			) {
				// Handle CORS preflight requests.
				return new Response(null, {
					headers: {
						'Access-Control-Allow-Origin': '*',
						'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
						'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers'),
					},
				});
			} else {
				// Handle standard OPTIONS request.
				return new Response(null, {
					headers: {
						Allow: 'GET, HEAD, POST, OPTIONS',
					},
				});
			}
		}
		// Read arguments.
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
					return respond('Invalid JSON', { status: 400 });
				}
			}
		})();
		//console.log('Body:', body);
		if(body) {
			// Check if the email parameter is set.
			if(!body.email) {
				return respond('Parameter "email" not set.', { status: 400 });
			}
			// Check if the password parameter is set.
			if(!body.password) {
				return respond('Parameter "password" not set.', { status: 400 });
			}
		}
		if(url.pathname === '/register' && method === 'POST') {
			// POST /register.
			// If the user already exists, return 409.
			const _data = await env.WALLETS.get(body.email);
			if(_data) {
				return respond('User already exists', { status: 409 });
			}
			// Create a new user.
			const passwordHash = await bcrypt.hash(body.password, 10);
			//console.log('Password hash:', passwordHash);
			const data = {
				passwordHash,
			};
			await env.WALLETS.put(body.email, JSON.stringify(data));
			return respond('User created', { status: 201 });
		} else if(url.pathname === '/changepw' && method === 'POST') {
			// POST /changepw.
			// Check if the newPassword parameter is set.
			if(!body.newPassword) {
				return respond('Parameter "newPassword" not set.', { status: 400 });
			}
			if(!await authorize(env, body)) {
				return respond('Unauthorized', { status: 401 });
			}
			// Change the password.
			const passwordHash = await bcrypt.hash(body.newPassword, 10);
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			json.passwordHash = passwordHash;
			await env.WALLETS.put(body.email, JSON.stringify(json));
			return respond('Password changed');
		} else if(url.pathname === '/get' && method === 'GET') {
			// GET /get.
			if(!await authorize(env, body)) {
				return respond('Unauthorized', { status: 401 });
			}
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			const walletsEncrypted = json.wallets;
			if(!walletsEncrypted) {
				return respond('Wallets not set', { status: 404 });
			}
			const wallets = decrypt(walletsEncrypted, body.password);
			return respond(wallets);
		} else if(url.pathname === '/set' && method === 'POST') {
			// POST /set.
			// Check if the wallets parameter is set.
			if(!body.wallets) {
				return respond('Parameter "wallets" not set.', { status: 400 });
			}
			if(!await authorize(env, body)) {
				return respond('Unauthorized', { status: 401 });
			}
			// Set the wallets.
			const data = await env.WALLETS.get(body.email);
			const json = JSON.parse(data);
			json.wallets = encrypt(body.wallets, body.password);
			await env.WALLETS.put(body.email, JSON.stringify(json));
			return respond('Wallets set');
		} else {
			return respond('Not found', { status: 404 });
		}
	},
} satisfies ExportedHandler<Env>;

