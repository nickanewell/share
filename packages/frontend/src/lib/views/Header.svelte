<script lang="ts">
	import { themeLogo } from '$lib/stores/theme'

	function reset() {
		window.location.reload()
	}
</script>

<header>
	<a on:click={reset} href="/">
		<img alt="logo" src={$themeLogo} />
	</a>
</header>

<style>
	a {
		border: none;
	}

	header {
		text-align: center;
		margin-top: 3rem;
		margin-bottom: 2rem;
	}

	img {
		object-fit: contain;
	}

	@media screen and (max-width: 30rem) {
		header {
			margin-top: 1rem;
			margin-bottom: 1rem;
		}

		header img {
			max-height: 4rem;
		}
	}

	header img {
		width: 100%;
		max-height: 8rem;
		transform: translateX(-1rem);
	}
</style>
