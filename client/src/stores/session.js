import { defineStore } from 'pinia'
import srp from 'secure-remote-password/client.js';

export const useSession = defineStore('session', {
	state: () => ({
		initiated: false,
		valid: false,
		loggedIn: false,
		username: null,
		encryptionKey: null,
		authorization: null,
	}),
	actions: {
		hexToUint8Array(hex) {
			const bytes = new Uint8Array(hex.length / 2);
			for (let i = 0; i < bytes.length; i++) {
				bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
			}
			return bytes;
		},
		uint8ArrayToHex(uint8Array) {
			return Array.from(uint8Array).map(b => b.toString(16).padStart(2, '0')).join('');
		},
		makeRequest(method, path, body = null) {
			let abort = new AbortController();
			let headers = {};
			if (this.authorization) {
				headers.Authorization = this.authorization;
			}
			if (body) {
				headers['Content-Type'] = 'application/json';
				body = JSON.stringify(body);
			}
			if (this.encryptionKey) {
				headers['Encrypted'] = 'true';
				if (body) {
					const iv = crypto.getRandomValues(new Uint8Array(16));
					const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.encryptionKey, 'hex'), iv);
					let encrypted = cipher.update(body, 'utf8');
					encrypted += cipher.final();
					body = Buffer.concat([iv, Buffer.from(encrypted)]);
				}
			}
			let response = fetch('/api/v1' + path, {
				method,
				headers,
				body,
				signal: abort.signal
			}).then(async res => {
				if (!res.ok) {
					let content = res.headers.get('Content-Type');
					if (content && content.startsWith('application/json')) {
						let error = await res.json();
						throw new Error(error.error);
					}
					throw new Error(`Could not ${method} ${path} (${res.status} - ${res.statusText})`);
				}
				if (res.headers.get('Encrypted') === 'true') {
					const original = await res.arrayBuffer();
					const iv = original.slice(0, 16);
					const encrypted = original.slice(16);
					const keyBytes = this.hexToUint8Array(this.encryptionKey);
					const key = await crypto.subtle.importKey(
						'raw',
						keyBytes,
						{ name: 'AES-CBC' },
						false,
						['decrypt']
					);

					const decryptedData = await crypto.subtle.decrypt(
						{ name: 'AES-CBC', iv },
						key,
						encrypted
					);
					return new Response(decryptedData);
				}
				return res;
			})
			return [response, abort];
		},
		async init() {
			this.loadSession();
			if (this.session) {
				await this.verifySession();
			}
			this.initiated = true;
		},
		async verifySession() {
			let [response, abort] = this.makeRequest('GET', '/session');
			try {
				let session = await response;
				this.session = await session.json();
				this.valid = true;
				this.loggedIn = this.session.loggedIn;
				this.username = this.session.username;
			} catch (error) {
				this.session = null;
				this.valid = false;
				this.loggedIn = false;
			}
		},
		async loadSession() {
			this.authorization = localStorage.getItem('authorization');
			this.encryptionKey = localStorage.getItem('encryptionKey');
		},
		async saveSession() {
			localStorage.setItem('authorization', this.authorization);
			localStorage.setItem('encryptionKey', this.encryptionKey);
		},
		async deleteSession() {
			this.authorization = null;
			this.encryptionKey = null;
			localStorage.removeItem('authorization');
			localStorage.removeItem('encryptionKey');
		},
		async login(username, password) {
			const clientEphemeral = srp.generateEphemeral();
			let [response, abort] = this.makeRequest('POST', '/session', {
				username,
			});
			let loginAttempt = await response;
			loginAttempt = await loginAttempt.json();
			const { serverEphemeral, salt } = loginAttempt;
			username = loginAttempt.username; // converting email to username (could also be used for alt-names)
			this.authorization = loginAttempt.sessionId;
			const privateKey = srp.derivePrivateKey(salt, username, password);
			const clientSession = srp.deriveSession(clientEphemeral.secret, serverEphemeral, salt, username, privateKey);
			[response, abort] = this.makeRequest('PATCH', '/session', {
				clientEphemeral: clientEphemeral.public,
				proof: clientSession.proof,
			});
			let session = await response;
			session = await session.json();
			srp.verifySession(clientEphemeral.public, clientSession, session.proof);
			this.username = username;
			this.encryptionKey = clientSession.key;
			this.valid = true;
			this.loggedIn = true;
			this.saveSession();
		},
		async register(username, email, password) { // TEMP method for testing
			const salt = srp.generateSalt();
			const privateKey = srp.derivePrivateKey(salt, username, password);
			const verifier = srp.deriveVerifier(privateKey);
			let [response, abort] = this.makeRequest('POST', '/users', {
				email,
				username,
				salt,
				verifier,
			});
			let result = await response;
			return true;
		},
	},
})
