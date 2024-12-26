import { defineStore } from 'pinia'
import srp from 'secure-remote-password/client.js';
import aes from 'aes-js';

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
		makeRandom(length) { // utility method with fallback to Math.random
			if (crypto) {
				return crypto.getRandomValues(new Uint8Array(length));
			}
			let array = new Uint8Array(length);
			for (let i = 0; i < length; i++) {
				array[i] = Math.floor(Math.random() * 256); // this is not secure, but it's better than nothing
			}
			return array;
		},
		removePadding(bytes) {
			const start = bytes.slice(0, bytes.length - 16);
			let end = bytes.slice(bytes.length - 16);
			for(let i=16;i>0;i--){
                if (end.slice(end.length-i).every(e=>e==i)) {
                    end = end.slice(0, end.length-i);
                    break;
                }
            }
			let result = new Uint8Array(start.length + end.length);
			result.set(start);
			result.set(end, start.length);
			return result;
		},
		addPadding(bytes) {
			const padding = 16 - (bytes.length % 16);
			let result = new Uint8Array(bytes.length + padding);
			result.set(bytes);
			for (let i = 0; i < padding; i++) {
				result[bytes.length + i] = padding;
			}
			return result;
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
					const iv = this.makeRandom(16);
					const toEncrypt = aes.utils.utf8.toBytes(body);
					const aesCtr = new aes.ModeOfOperation.cbc(aes.utils.hex.toBytes(this.encryptionKey), Array.from(new Uint8Array(iv)));
					const encryptedBytes = aesCtr.encrypt(this.addPadding(toEncrypt));
					body = new Uint8Array(iv.length + encryptedBytes.length);
					body.set(iv);
					body.set(encryptedBytes, iv.length);
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
					const aesCtr = new aes.ModeOfOperation.cbc(aes.utils.hex.toBytes(this.encryptionKey), Array.from(new Uint8Array(iv)));
					const decryptedBytes = aesCtr.decrypt(new Uint8Array(encrypted));
					return new Response(this.removePadding(decryptedBytes).buffer);
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
