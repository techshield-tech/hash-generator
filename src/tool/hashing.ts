// Pure, framework-free hashing helpers built on @noble/hashes. Tool-specific.

import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hmac } from '@noble/hashes/hmac.js';
import { md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512, sha512_256 } from '@noble/hashes/sha2.js';
import { keccak_256, sha3_224, sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3.js';
import type { CHash } from '@noble/hashes/utils.js';

export type AlgorithmId =
  | 'md5'
  | 'sha1'
  | 'sha224'
  | 'sha256'
  | 'sha384'
  | 'sha512'
  | 'sha512_256'
  | 'sha3_224'
  | 'sha3_256'
  | 'sha3_384'
  | 'sha3_512'
  | 'keccak256'
  | 'ripemd160'
  | 'blake2b'
  | 'blake2s'
  | 'blake3';

export interface Algorithm {
  id: AlgorithmId;
  label: string;
  hash: CHash;
  /** Digest size in bits. */
  bits: number;
  /** Supports standard RFC 2104 HMAC. */
  hmac: boolean;
  /** Broken or deprecated for security use (collisions are practical). */
  weak?: boolean;
}

export const ALGORITHMS: Algorithm[] = [
  { id: 'md5', label: 'MD5', hash: md5, bits: 128, hmac: true, weak: true },
  { id: 'sha1', label: 'SHA-1', hash: sha1, bits: 160, hmac: true, weak: true },
  { id: 'sha224', label: 'SHA-224', hash: sha224, bits: 224, hmac: true },
  { id: 'sha256', label: 'SHA-256', hash: sha256, bits: 256, hmac: true },
  { id: 'sha384', label: 'SHA-384', hash: sha384, bits: 384, hmac: true },
  { id: 'sha512', label: 'SHA-512', hash: sha512, bits: 512, hmac: true },
  { id: 'sha512_256', label: 'SHA-512/256', hash: sha512_256, bits: 256, hmac: true },
  { id: 'sha3_224', label: 'SHA3-224', hash: sha3_224, bits: 224, hmac: true },
  { id: 'sha3_256', label: 'SHA3-256', hash: sha3_256, bits: 256, hmac: true },
  { id: 'sha3_384', label: 'SHA3-384', hash: sha3_384, bits: 384, hmac: true },
  { id: 'sha3_512', label: 'SHA3-512', hash: sha3_512, bits: 512, hmac: true },
  { id: 'keccak256', label: 'Keccak-256', hash: keccak_256, bits: 256, hmac: true },
  { id: 'ripemd160', label: 'RIPEMD-160', hash: ripemd160, bits: 160, hmac: true },
  { id: 'blake2b', label: 'BLAKE2b-512', hash: blake2b, bits: 512, hmac: true },
  { id: 'blake2s', label: 'BLAKE2s-256', hash: blake2s, bits: 256, hmac: true },
  { id: 'blake3', label: 'BLAKE3', hash: blake3, bits: 256, hmac: false },
];

export const HMAC_ALGORITHMS = ALGORITHMS.filter((algorithm) => algorithm.hmac);

export function getAlgorithm(id: AlgorithmId): Algorithm {
  const algorithm = ALGORITHMS.find((a) => a.id === id);
  if (!algorithm) throw new Error(`Unknown algorithm: ${id}`);
  return algorithm;
}

// ---------------------------------------------------------------------------
// Byte encodings
// ---------------------------------------------------------------------------

export type OutputEncoding = 'hex' | 'HEX' | 'base64' | 'base64url' | 'binary';
export type InputEncoding = 'utf8' | 'hex' | 'base64';

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function encodeDigest(bytes: Uint8Array, encoding: OutputEncoding): string {
  switch (encoding) {
    case 'hex':
      return bytesToHex(bytes);
    case 'HEX':
      return bytesToHex(bytes).toUpperCase();
    case 'base64':
      return bytesToBase64(bytes);
    case 'base64url':
      return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    case 'binary':
      return Array.from(bytes, (byte) => byte.toString(2).padStart(8, '0')).join('');
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '').replace(/[\s:-]/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Hex input contains non-hex characters.');
  if (clean.length % 2 !== 0) throw new Error('Hex input must have an even number of digits.');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) {
    throw new Error('Invalid Base64 input.');
  }
  const binary = atob(clean + '='.repeat((4 - (clean.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Converts user input to bytes. Throws with a readable message on malformed hex/base64. */
export function decodeInput(value: string, encoding: InputEncoding): Uint8Array {
  if (encoding === 'hex') return hexToBytes(value);
  if (encoding === 'base64') return base64ToBytes(value);
  return new TextEncoder().encode(value);
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

export function hashBytes(algorithm: Algorithm, data: Uint8Array): Uint8Array {
  return algorithm.hash(data);
}

export function hmacBytes(algorithm: Algorithm, key: Uint8Array, message: Uint8Array): Uint8Array {
  if (!algorithm.hmac) throw new Error(`${algorithm.label} does not support HMAC.`);
  return hmac(algorithm.hash, key, message);
}

export type DigestMap = Partial<Record<AlgorithmId, Uint8Array>>;

export function hashAll(data: Uint8Array): DigestMap {
  const result: DigestMap = {};
  for (const algorithm of ALGORITHMS) result[algorithm.id] = hashBytes(algorithm, data);
  return result;
}

export interface HashFileProgress {
  bytesRead: number;
  totalBytes: number;
}

export interface Chunked {
  size: number;
  readChunk: (start: number, end: number) => Promise<Uint8Array>;
}

const FILE_CHUNK_BYTES = 4 * 1024 * 1024;

/** Incrementally hashes a large source with every algorithm; resolves to null if aborted. */
export async function hashChunked(
  source: Chunked,
  onProgress: (progress: HashFileProgress) => void,
  signal: AbortSignal,
): Promise<DigestMap | null> {
  const hashers = ALGORITHMS.map((algorithm) => ({ id: algorithm.id, state: algorithm.hash.create() }));
  for (let offset = 0; offset < source.size || offset === 0; offset += FILE_CHUNK_BYTES) {
    if (signal.aborted) return null;
    const chunk = await source.readChunk(offset, Math.min(offset + FILE_CHUNK_BYTES, source.size));
    for (const hasher of hashers) hasher.state.update(chunk);
    onProgress({ bytesRead: Math.min(offset + FILE_CHUNK_BYTES, source.size), totalBytes: source.size });
    // Let the browser paint the progress bar between chunks.
    await new Promise((resolve) => setTimeout(resolve, 0));
    if (source.size === 0) break;
  }
  const result: DigestMap = {};
  for (const hasher of hashers) result[hasher.id] = hasher.state.digest();
  return result;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/** Loosely normalises a pasted checksum: trims, drops `0x`, whitespace, colons and padding. */
function normalizeExpected(expected: string): string {
  return expected.trim().replace(/^0x/i, '').replace(/[\s:]/g, '').replace(/=+$/, '');
}

/** True if `expected` equals `digest` in any supported output encoding (hex is case-insensitive). */
export function digestMatches(digest: Uint8Array, expected: string): boolean {
  const target = normalizeExpected(expected);
  if (!target) return false;
  const hex = bytesToHex(digest);
  if (target.toLowerCase() === hex) return true;
  const b64 = bytesToBase64(digest).replace(/=+$/, '');
  if (target === b64) return true;
  if (target === b64.replace(/\+/g, '-').replace(/\//g, '_')) return true;
  return target === encodeDigest(digest, 'binary');
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
