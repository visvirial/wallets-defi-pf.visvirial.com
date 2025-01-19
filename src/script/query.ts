
import fs from 'fs/promises';

const WALLETS_URL = process.env.WALLETS_URL || 'https://wallets-defi-pf.visvirial.com';

export const main = async () => {
	if(process.argv.length < 3) {
		console.log('Usage: node query.js <register|changepw|get|set> [<args...>]');
		return;
	}
	const method = process.argv[2];
	const args = process.argv.slice(3);
	if(method === 'register') {
		if(args.length < 2) {
			console.log('Usage: node query.js register <email> <password>');
			return;
		}
		const email = args[0];
		const password = args[1];
		const response = await fetch(`${WALLETS_URL}/register`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				email,
				password,
			}),
		});
		console.log(await response.text());
	} else if(method === 'changepw') {
		if(args.length < 3) {
			console.log('Usage: node query.js changepw <email> <oldPassword> <newPassword>');
			return;
		}
		const email = args[0];
		const password = args[1];
		const newPassword = args[2];
		const response = await fetch(`${WALLETS_URL}/changepw`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				email,
				password,
				newPassword,
			}),
		});
		console.log(await response.text());
	} else if(method === 'get') {
		if(args.length < 2) {
			console.log('Usage: node query.js get <email> <password>');
			return;
		}
		const email = args[0];
		const password = args[1];
		const params = new URLSearchParams();
		params.append('email', email);
		params.append('password', password);
		const response = await fetch(`${WALLETS_URL}/get?${params.toString()}`);
		console.log(await response.text());
	} else if(method === 'set') {
		if(args.length < 3) {
			console.log('Usage: node query.js set <email> <password> <wallet.yaml>');
			return;
		}
		const email = args[0];
		const password = args[1];
		const walletFile = args[2];
		const wallets = await fs.readFile(walletFile, 'utf8');
		const response = await fetch(`${WALLETS_URL}/set`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				email,
				password,
				wallets,
			}),
		});
		console.log(await response.text());
	} else {
		console.log('Invalid method:', method);
	}
};

main();

