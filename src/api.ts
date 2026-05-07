/// <reference types="@directus/extensions/api.d.ts" />

import type { SandboxOperationConfig } from "directus:api";
import crypto from 'crypto';

interface OperationOptions {
  message: string;
  secret: string;
}

const operation: SandboxOperationConfig = {
    id: 'directus-operation-hmac-sha256',
    handler: (options: OperationOptions) => {
			const { message, secret } = options;

			if (!message) {
				throw new Error("No message provided");
			}

			if (!secret) {
				throw new Error("No secret provided");
			}

			const signature = crypto
				.createHmac('sha256', secret)
				.update(message)
				.digest('hex');

			return signature;
    },
};

export default operation;