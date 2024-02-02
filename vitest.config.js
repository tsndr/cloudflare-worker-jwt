import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		coverage: {
			provider: 'istanbul',
			reporter: ['text', 'lcov', 'cobertura'],
		},
		setupFiles: ['tests/setup-crypto.js'],
	},
});
