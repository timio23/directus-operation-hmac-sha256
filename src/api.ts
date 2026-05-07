/// <reference types="@directus/extensions/api.d.ts" />

import type { SandboxOperationConfig } from "directus:api";
import createCryptoModule, { type CryptoModule } from './crypto';
const crypto: CryptoModule = createCryptoModule();

interface OperationOptions {
	method: 'hmacSign' | 'hmacVerify' | 'hash' | 'encrypt' | 'decrypt' | 'key' | 'toBase64' | 'fromBase64' | 'toHex' | 'fromHex';
  message?: string;
  secret?: string;
	size?: number;
	signature?: string;
	encryption?: {
		data: string;
		hmac: string;
	}
}

const operation: SandboxOperationConfig = {
    id: 'directus-operation-hmac-sha256',
    handler: (options: OperationOptions) => {
			
			if (!options.method) {
				throw new Error("No method provided");
			}
			const method = options.method;

			if (['hmacVerify','hmacVerify','encrypt','decrypt'].includes(method) && !options.secret) {
				throw new Error("No secret provided");
			}

			if (!['key','decrypt'].includes(method) && !options.message) {
				throw new Error("No message provided");
			}

			if (method == 'key' && !options.size) {
				throw new Error("No size provided");
			}

			if (method == 'hmacVerify' && !options.signature) {
				throw new Error("No signature provided");
			}

			if (method == 'decrypt' && (!options.encryption || !options.encryption.data || !options.encryption.hmac)) {
				throw new Error("A Valid Encryption is required");
			}

			if(method == 'hash'){
				// SHA256 hash
				return crypto.sha256(options.message!);
			}
			else if(method == 'hmacSign'){
				// HMAC signing
				return crypto.hmacSign('sha256', options.message!, options.secret!);
			}
			else if(method == 'hmacVerify'){
				// HMAC verification
				return crypto.hmacVerify('sha256', options.message!, options.secret!, options.signature!);
			}
			else if(method == 'encrypt'){
				// Encryption with HMAC
				return crypto.encrypt(options.message!, options.secret!);
			}
			else if(method == 'decrypt'){
				// Decryption with HMAC verification
				return crypto.decrypt(options.encryption!.data, options.secret!, options.encryption!.hmac);
			}
			else if(method == 'key'){
				// Generate random key
				return crypto.generateKey(options.size ?? 32);
			}
			else if(method == 'toBase64'){
				// Base64 encoding/decoding
				return crypto.toBase64(options.message!);
			}
			else if(method == 'fromBase64'){
				return crypto.fromBase64(options.message!);
			}
			else if(method == 'toHex'){
				// Hex encoding/decoding
				return crypto.toHex(options.message!);
			}
			else if(method == 'fromHex'){
				return crypto.fromHex(options.message!);
			}
			else {
				throw new Error("No valid method provided");
			}
    },
};

export default operation;