<script>
import { useSession } from '@/stores/session.js';
import { mapState, mapActions } from 'pinia';

export default {
	data() {
		return {
			email: 'test@example.com',
			username: 'enrico',
			password: 'password',
			loading: false,
			error: null,
		}
	},
	methods: {
		...mapActions(useSession, ['register']),
		async submit() {
			this.loading = true;
			this.error = null;
			this.register(this.username, this.email, this.password)
				.then(() => {
					this.$router.push('/login');
				})
				.catch((error) => {
					this.error = error;
					this.loading = false;
				});
		}
	}
}
</script>
<template>
	Register lol
	<div>
		<input v-model="email" placeholder="Email" />
		<input v-model="username" placeholder="Username"/>
		<input v-model="password" placeholder="Password" type="password"/>
		<button @click="submit" :disabled="loading">Register</button>
	</div>
</template>