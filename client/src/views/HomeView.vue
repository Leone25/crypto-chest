<script setup>
</script>
<script>
import { useSession } from '@/stores/session.js';
import { mapState, mapActions } from 'pinia';

export default {
	methods: {
		...mapActions(useSession, ['makeRequest']),
		test() {
			let [request, abort] = this.makeRequest('GET', '/ping');
			request.then(res => res.text()).then((response) => {
				console.log(response);
			}).catch((error) => {
				console.log(error);
			});
		}
	}
}
</script>
<template>
  asd
  <button @click="test">Test</button>
</template>
