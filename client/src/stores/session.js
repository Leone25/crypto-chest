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
		makeRequest(method, path, body) {
			let abort = new AbortController();
			let headers = {};
			if (this.authorization) {
				headers.Authorization = this.authorization;
			}
			if (body) {
				headers['Content-Type'] = 'application/json';
			}
			let response = fetch('/api/v1' + path, {
				method,
				headers,
				body: body ? JSON.stringify(body) : undefined,
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
			const {serverEphemeral, salt} = loginAttempt;
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
			console.log(session);
			console.log(clientSession, serverEphemeral, session.proof);
			srp.verifySession(clientEphemeral.public, clientSession, session.proof);
			this.username = username;
			this.key = session.key;
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
