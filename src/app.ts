import { defineOperationApp } from '@directus/extensions-sdk';

export default defineOperationApp({
	id: 'directus-operation-hmac-sha256',
	name: 'Cryptography',
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
			field: 'method',
			name: 'Method',
			type: 'string',
			meta: {
				required: true,
				width: 'half',
				interface: 'select-dropdown',
				options: {
					choices: [
						{ text: 'HMAC Sign', value: 'hmacSign' },
						{ text: 'HMAC Verify', value: 'hmacVerify' },
						{ text: 'Hash', value: 'hash' },
						{ text: 'Encrypt', value: 'encrypt' },
						{ text: 'Decrypt', value: 'decrypt' },
						{ text: 'Random key', value: 'key' },
						{ text: 'To Base64', value: 'toBase64' },
						{ text: 'From Base64', value: 'fromBase64' },
						{ text: 'To Hex', value: 'toHex' },
						{ text: 'From Hex', value: 'fromHex' },
					],
				}
			}
		},
		{
			field: 'size',
			name: 'Size',
			type: 'integer',
			meta: {
				required: false,
				width: 'full',
				interface: 'input',
				hidden: true,
				conditions: [{ hidden: false, required: true, rule: { method: { _eq: 'key' } } }],
				options: {
					placeholder: '32',
				}
			},
		},
		{
			field: 'secret',
			name: 'Secret',
			type: 'string',
			meta: {
				required: false,
				width: 'full',
				interface: 'input',
				note: 'The secret string to encrypt the message.',
				options: {
					masked: true,
				},
				hidden: true,
				conditions: [{ hidden: false, required: true, rule: { method: { _in: ['hmacSign','hmacVerify','encrypt','decrypt'] } } }],
			},
		},
		{
			field: 'signature',
			name: 'HMAC Signature',
			type: 'string',
			meta: {
				required: false,
				width: 'full',
				interface: 'input',
				hidden: true,
				conditions: [{ hidden: false, required: true, rule: { method: { _eq: 'hmacVerify' } } }],
			},
		},
		{
			field: 'message',
			name: 'Message',
			type: 'string',
			meta: {
				required: true,
				width: 'full',
				interface: 'input',
				hidden: false,
				conditions: [{ hidden: true, required: false, rule: { method: { _in: ['key','decrypt'] } } }],
			},
		},
		{
			field: 'encryption',
			name: 'Encryption',
			type: 'json',
			meta: {
				required: false,
				width: 'full',
				interface: 'input-code',
				options: {
					language: 'json',
					template: '{"data":"XXXXXX","hmac":"XXXXXX"}',
					placeholder: '{"data":"XXXXXX","hmac":"XXXXXX"}',
				},
				hidden: true,
				conditions: [{ hidden: false, required: true, rule: { method: { _eq: 'decrypt' } } }],
			},
		},
	],
});
