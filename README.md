# Directus Operation HMAC-SHA256

Encrypt a message using a secret.

## Installation
This extension supports [Directus 11.x](https://directus.io/). In the root of your Directus server project run:

`$ npm i @timio23/directus-operation-hmac-sha256`

... and then restart Directus!

## Prerequisites

- Directus 11.x

## Usage

When creating or editing a flow:

1. Add a new operation and select HMAC-SHA256 Encryption from the list
2. Create a message to encrypt
3. Type (or paste) the secret

The response will be the result in plain text.

## License

MIT