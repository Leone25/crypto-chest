<script setup>
import { RouterLink, RouterView } from 'vue-router'
import { useSession } from '@/stores/session.js';
import { mapState, mapActions } from 'pinia';
</script>
<script>
export default {
	data() {
		return {
			ready: false,
		}
	},
	computed: {
		...mapState(useSession, ['initiated', 'loggedIn']),
	},
	methods: {
		...mapActions(useSession, ['init']),
	},
	async mounted() {
		await this.init();
		if (this.loggedIn) {
			this.ready = true;
		} else {
			console.log(this.$route);
			if (!(['/register', '/login'].includes(this.$route.path))) {
				//this.$router.push('/login');
			}
			this.ready = true;
		}
	}
}
</script>
<template>
  <RouterView v-if="ready"/>
</template>

<style scoped>

</style>
