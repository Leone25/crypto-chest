<script>
import { useSession } from '@/stores/session.js';
import { mapState, mapActions } from 'pinia';

export default {
	data() {
		return {
			username: 'enrico',
			password: 'password',
			loading: false,
			error: null,
		}
	},
	methods: {
		...mapActions(useSession, ['login']),
		async submit() {
			this.loading = true;
			this.error = null;
			this.login(this.username,this.password)
				.then(() => {
					this.$router.push('/');
				})
				.catch((error) => {
					console.log(error);
					this.error = error;
					this.loading = false;
				});
		}
	}
}
</script>
<template>
	Login asd
	<div>
		<input v-model="username" placeholder="Username"/>
		<input v-model="password" placeholder="Password" type="password"/>
		<button @click="submit" :disabled="loading">Login</button>
		<div v-if="error">{{ error }}</div>
	</div>
</template>