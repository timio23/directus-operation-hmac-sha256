# Directus Cryptography Operation

A Directus operation extension that provides HMAC-SHA256 cryptographic functions for your Directus workflows. Perfect for secure data signing, verification, and encryption within your automation pipelines.

## Features

- **HMAC-SHA256 Signing** - Generate cryptographic signatures for data integrity
- **HMAC Verification** - Verify signatures to ensure data authenticity
- **AES XOR Encryption/Decryption** - Encrypt and decrypt sensitive data with HMAC authentication
- **Base64 & Hex Encoding** - Encode/decode data for safe transmission
- **SHA256 Hashing** - Generate SHA256 hashes of strings
- **Key Generation** - Securely generate random encryption keys
- **Zero Dependencies** - Pure JavaScript implementation, works in sandboxed environments

## Installation

Install through the Directus Marketplace or via NPM:

```bash
npm i @timio23/directus-operation-cryptography
```

## Usage

Add the Cryptography operation to your workflow and choose the method.

### HMAC Sign

Submit a message with an encryption key to receive a signature.

| Field | Type | Details |
| ----- | ---- | ------- |
| Message | string | Text to encrypt. Use something like TITLE:USER:TIMESTAMP |
| Secret | masked string | An encryption key |

The output will be the HMAC signature.

### HMAC Verify

Submit a signature with the same message and encyption key for comparison.

| Field | Type | Details |
| ----- | ---- | ------- |
| Message | string | Text from the original signature |
| Secret | masked string | The encryption key |
| HMAC Signature | string | Signature for verification |

The response is a boolean.

### Encrypt

Encypt your message using an encryption key.

| Field | Type | Details |
| ----- | ---- | ------- |
| Message | string | Text to encrypt |
| Secret | masked string | An encryption key |

The response is a json object:
```json
{ data: "base64-encoded-ciphertext", hmac: "signature" }
```

### Decrypt

Submit the same json object from the encryption as well as the secret.

| Field | Type | Details |
| ----- | ---- | ------- |
| Secret | masked string | The decryption key |
| Encryption | json | Must be `{ "data": "", "hmac": "" }`

Result will be the original string.

### Hash

Generate SHA256 Hash for a message. The result will be a string.

### To Base64

Encode the message into Base64. The response is the encoded string.

### From Base64

Decode the message from Base64. The response is the original string.

### Random Key

Generate a Random Key with a chosen size such as 32. The response is a string.

## Common Use Cases

### API Request Signing

Sign API requests with HMAC for verification:

1. Get webhook data
2. Create signing string: method + path + timestamp
3. Use HMAC Sign in Cryptography Operation with your secret
4. Add signature to request headers
5. Send authenticated request

### Data Integrity Verification

Verify that data hasn't been tampered with such as incoming Webhooks.

1. Receive data with signature
2. Use HMAC Verify in Cryptography Operation on the signature
3. If verification fails, reject request
4. If verification passes, process data

### Storing Sensitive Data

Encrypt sensitive information before storage:

1. Receive sensitive data (password, token, etc.)
2. Use encrypt in Cryptography Operation with your key
3. Store encrypted data and HMAC in database
4. Later: retrieve and decrypt with the same key

## Security Considerations

⚠️ Important Security Notes:

- Store secrets securely
- Be mindful not to output secrets in Flow outputs

### HMAC vs Encryption
- HMAC is for integrity verification, not confidentiality. Use encryption for sensitive data

### Key Management
- Keep encryption keys secure and rotate regularly

## Troubleshooting

### Signature Doesn't Match

- Verify the algorithm is set to sha256
- Ensure the data string is identical (whitespace matters)
- Check that the secret is correct
- Verify data encoding (UTF-8)

### Decryption Fails with "HMAC verification failed"

- Ensure you're using the same key used for encryption
- Verify the HMAC hasn't been modified
- Check that the ciphertext is valid Base64

### Key Generation Issues

- Ensure length parameter is a positive number
- Default length is 32 characters
- Generated keys are alphanumeric + digits

## Performance

- SHA256: ~1-5ms per hash (varies by input length)
- HMAC: ~2-10ms per signature
- Encryption: ~0.5-2ms per operation
- No external dependencies - Lightweight and fast

## License

MIT

## Support

For issues, questions, or feature requests:

- Check the Directus Extensions Documentation
- Review the extension code for implementation details
- Submit issues through your Directus instance
