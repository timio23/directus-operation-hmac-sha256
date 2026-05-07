import { defineOperationApp } from '@directus/extensions-sdk';

export default defineOperationApp({
	id: 'directus-operation-hmac-sha256',
	name: 'HMAC-SHA256 Encryption',
	icon: 'key',
	description: 'Encrypt a message using a secret',
	overview: ({ message }) => [
		{
			label: 'Text',
			text: message,
		},
	],
	options: [
		{
			field: 'message',
			name: 'Message',
			type: 'string',
			meta: {
				required: true,
				width: 'full',
				interface: 'input',
			},
		},
		{
			field: 'secret',
			name: 'Secret',
			type: 'string',
			meta: {
				required: true,
				width: 'full',
				interface: 'input',
				note: 'The secret string to encrypt the message.',
				options: {
					masked: true,
				},
			},
		},
	],
});
