interface EncryptedData {
  data: string;
  hmac: string;
}

interface CryptoModule {
  sha256(data: string): string;
  hmacSign(algorithm: string, data: string, secret: string): string;
  hmacVerify(algorithm: string, data: string, secret: string, signature: string): boolean;
  encrypt(plaintext: string, key: string): EncryptedData;
  decrypt(ciphertext: string, key: string, hmac: string): string;
  generateKey(length?: number): string;
  toHex(str: string): string;
  fromHex(hex: string): string;
  toBase64(str: string): string;
  fromBase64(b64: string): string;
}

function createCryptoModule(): CryptoModule {
  /**
   * Convert string to UTF-8 bytes
   */
  function stringToBytes(str: string): Uint8Array {
    const bytes: number[] = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6));
        bytes.push(0x80 | (code & 0x3f));
      } else if (code < 0xd800 || code >= 0xe000) {
        bytes.push(0xe0 | (code >> 12));
        bytes.push(0x80 | ((code >> 6) & 0x3f));
        bytes.push(0x80 | (code & 0x3f));
      } else {
        i++;
        const code2 = str.charCodeAt(i);
        const codePoint = 0x10000 + (((code & 0x3ff) << 10) | (code2 & 0x3ff));
        bytes.push(0xf0 | (codePoint >> 18));
        bytes.push(0x80 | ((codePoint >> 12) & 0x3f));
        bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
        bytes.push(0x80 | (codePoint & 0x3f));
      }
    }
    return new Uint8Array(bytes);
  }

  function utf8Encode(string: string) {
    string = string.replace(/\r\n/g, '\n')
    let utftext = ''

    for (let n = 0; n < string.length; n++) {
      const c = string.charCodeAt(n)

      if (c < 128) {
          utftext += String.fromCharCode(c)
      } else if ((c > 127) && (c < 2048)) {
          utftext += String.fromCharCode((c >> 6) | 192)
          utftext += String.fromCharCode((c & 63) | 128)
      } else {
          utftext += String.fromCharCode((c >> 12) | 224)
          utftext += String.fromCharCode(((c >> 6) & 63) | 128)
          utftext += String.fromCharCode((c & 63) | 128)
      }
    }

    return utftext
  }

  function utf8Decode(utftext: string) {
    var string = "";
    var i = 0;
    var c = 0, c1 = 0, c2 = 0;
    while ( i < utftext.length ) {
      c = utftext.charCodeAt(i);
      if (c < 128) {
        string += String.fromCharCode(c);
        i++;
      } else if((c > 191) && (c < 224)) {
        c1 = utftext.charCodeAt(i+1);
        string += String.fromCharCode(((c & 31) << 6) | (c1 & 63));
        i += 2;
      } else {
        c1 = utftext.charCodeAt(i+1);
        c2 = utftext.charCodeAt(i+2);
        string += String.fromCharCode(((c & 15) << 12) | ((c1 & 63) << 6) | (c2 & 63));
        i += 3;
      }
    };
    return string;
  }

  /**
   * Hex string to bytes
   */
  function hexToBytes(hex: string): Uint8Array {
    const bytes: number[] = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
  }

  /**
   * Right rotate a 32-bit integer
   */
  function rightRotate(n: number, d: number): number {
    return ((n >>> d) | (n << (32 - d))) >>> 0;
  }

  /**
   * Convert 32-bit number to 8-character hex string
   */
  function toHex32(n: number): string {
    return ('00000000' + (n >>> 0).toString(16)).slice(-8);
  }

  /**
   * Internal SHA256 that works with byte arrays
   */
  function sha256Internal(data: Uint8Array): string {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    // Initial hash values
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;

    // Pre-processing
    const msgLen = data.length;
    const bitLen = msgLen * 8;

    // Create padded message
    const padded = new Uint8Array(Math.ceil((msgLen + 9) / 64) * 64);
    padded.set(data);
    padded[msgLen] = 0x80;

    // Append length in bits as 64-bit big-endian
    let lengthBits = BigInt(bitLen);
    for (let i = 0; i < 8; i++) {
      padded[padded.length - 8 + i] = Number((lengthBits >> BigInt(56 - i * 8)) & BigInt(0xff));
    }

    // Process each 512-bit chunk
    for (let chunkStart = 0; chunkStart < padded.length; chunkStart += 64) {
      const w = new Uint32Array(64);

      // Break chunk into 16 32-bit big-endian words
      for (let i = 0; i < 16; i++) {
        w[i] = ((padded[chunkStart + i * 4] as number) << 24) |
               ((padded[chunkStart + i * 4 + 1] as number) << 16) |
               ((padded[chunkStart + i * 4 + 2] as number) << 8) |
               (padded[chunkStart + i * 4 + 3] as number);
      }

      // Extend the 16 32-bit words into 64 32-bit words
      for (let i = 16; i < 64; i++) {
        const s0 = rightRotate(w[i - 15] as number, 7) ^ rightRotate(w[i - 15] as number, 18) ^ ((w[i - 15]  as number) >>> 3);
        const s1 = rightRotate(w[i - 2] as number, 17) ^ rightRotate(w[i - 2] as number, 19) ^ ((w[i - 2] as number) >>> 10);
        w[i] = ((w[i - 16] as number) + s0 + (w[i - 7] as number) + s1) >>> 0;
      }

      // Initialize working variables
      let a = h0;
      let b = h1;
      let c = h2;
      let d = h3;
      let e = h4;
      let f = h5;
      let g = h6;
      let h = h7;

      // Main loop
      for (let i = 0; i < 64; i++) {
        const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + (K[i] as number) + (w[i] as number)) >>> 0;
        const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      // Add compressed chunk to current hash value
      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    // Produce the final hash value
    return toHex32(h0) + toHex32(h1) + toHex32(h2) + toHex32(h3) +
           toHex32(h4) + toHex32(h5) + toHex32(h6) + toHex32(h7);
  }

  /**
   * SHA256 public function - works with strings
   */
  function sha256(message: string): string {
    return sha256Internal(stringToBytes(message));
  }

  /**
   * HMAC-SHA256
   */
  function hmacSign(algorithm: string, data: string, secret: string): string {
    if (algorithm.toLowerCase() !== 'sha256') {
      throw new Error('Only sha256 algorithm is supported');
    }

    const blockSize = 64;
    let keyBytes = Array.from(stringToBytes(secret));

    // If key is longer than block size, hash it
    if (keyBytes.length > blockSize) {
      const hashedKey = sha256(secret);
      keyBytes = Array.from(hexToBytes(hashedKey));
    }

    // Pad key to block size
    while (keyBytes.length < blockSize) {
      keyBytes.push(0);
    }

    // Create inner and outer padded keys
    const ipadKey = new Uint8Array(blockSize);
    const opadKey = new Uint8Array(blockSize);

    for (let i = 0; i < blockSize; i++) {
      ipadKey[i] = (keyBytes[i] as number) ^ 0x36;
      opadKey[i] = (keyBytes[i] as number) ^ 0x5c;
    }

    // Inner hash: H((K XOR ipad) || message)
    const dataBytes = stringToBytes(data);
    const innerData = new Uint8Array(blockSize + dataBytes.length);
    innerData.set(ipadKey);
    innerData.set(dataBytes, blockSize);
    const innerHash = sha256Internal(innerData);

    // Outer hash: H((K XOR opad) || innerHash)
    const innerHashBytes = hexToBytes(innerHash);
    const outerData = new Uint8Array(blockSize + innerHashBytes.length);
    outerData.set(opadKey);
    outerData.set(innerHashBytes, blockSize);
    const outerHash = sha256Internal(outerData);

    return outerHash;
  }

  /**
   * Verify HMAC signature
   */
  function hmacVerify(algorithm: string, data: string, secret: string, signature: string): boolean {
    const expected = hmacSign(algorithm, data, secret);
    if (expected.length !== signature.length) return false;

    let match = 0;
    for (let i = 0; i < expected.length; i++) {
      match |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return match === 0;
  }

  /**
   * Convert string to hex
   */
  function toHex(str: string): string {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
      hex += ('00' + str.charCodeAt(i).toString(16)).slice(-2);
    }
    return hex;
  }

  /**
   * Convert hex to string
   */
  function fromHex(hex: string): string {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  }

  /**
   * Convert string to Base64
   */
  function toBase64(str: string): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let output = '';
    let chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    let i = 0;

    str = utf8Encode(str);

    while (i < str.length) {
        chr1 = str.charCodeAt(i++);
        chr2 = str.charCodeAt(i++);
        chr3 = str.charCodeAt(i++);

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }

        output = output +
          chars.charAt(enc1) + chars.charAt(enc2) +
          chars.charAt(enc3) + chars.charAt(enc4);
    }

    return output
  }

  /**
   * Convert Base64 to string
   */
  function fromBase64(b64: string): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = "";
    var chr1, chr2, chr3;
    var enc1, enc2, enc3, enc4;
    var i = 0;
    b64 = b64.replace(/[^A-Za-z0-9\+\/\=]/g, "");
    while (i < b64.length) {
      enc1 = chars.indexOf(b64.charAt(i++));
      enc2 = chars.indexOf(b64.charAt(i++));
      enc3 = chars.indexOf(b64.charAt(i++));
      enc4 = chars.indexOf(b64.charAt(i++));
      chr1 = (enc1 << 2) | (enc2 >> 4);
      chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
      chr3 = ((enc3 & 3) << 6) | enc4;
      output = output + String.fromCharCode(chr1);
      if (enc3 != 64) {
        output = output + String.fromCharCode(chr2);
      };
      if (enc4 != 64) {
        output = output + String.fromCharCode(chr3);
      }
    };
    output = utf8Decode(output);
    return output;
  }

  /**
   * XOR encryption with HMAC
   */
  function encrypt(plaintext: string, key: string): EncryptedData {
    const hmac = hmacSign('sha256', plaintext, key);

    let ciphertext = '';
    for (let i = 0; i < plaintext.length; i++) {
      const keyChar = key.charCodeAt(i % key.length);
      const plaintextChar = plaintext.charCodeAt(i);
      ciphertext += String.fromCharCode(plaintextChar ^ keyChar);
    }

    return {
      data: toBase64(ciphertext),
      hmac: hmac
    };
  }

  /**
   * XOR decryption with HMAC verification
   */
  function decrypt(ciphertext: string, key: string, hmac: string): string {
    const binaryData = fromBase64(ciphertext);

    let plaintext = '';
    for (let i = 0; i < binaryData.length; i++) {
      const keyChar = key.charCodeAt(i % key.length);
      const ciphertextChar = binaryData.charCodeAt(i);
      plaintext += String.fromCharCode(ciphertextChar ^ keyChar);
    }

    if (!hmacVerify('sha256', plaintext, key, hmac)) {
      throw new Error('HMAC verification failed');
    }

    return plaintext;
  }

  /**
   * Generate random key
   */
  function generateKey(length: number = 32): string {
    let key = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < length; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return key;
  }

  return {
    sha256,
    hmacSign,
    hmacVerify,
    encrypt,
    decrypt,
    generateKey,
    toHex,
    fromHex,
    toBase64,
    fromBase64
  };
}

export default createCryptoModule;
export type { CryptoModule, EncryptedData };