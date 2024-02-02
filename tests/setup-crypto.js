import crypto from 'node:crypto';
Object.defineProperty(global, 'crypto', { value: { subtle: crypto.webcrypto.subtle }})
