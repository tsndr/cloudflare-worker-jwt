import { defineConfig } from 'vitest/config'

export default defineConfig({
	test: {
		environment: 'edge-runtime',
		watch: false,
		reporters: ['verbose']
	}
})