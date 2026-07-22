/**
 * Utility functions for SD-JWT decoding and validation
 * Provides cross-platform encoding, decoding, and compression helpers
 */

import pako from 'pako';
import { base64urlToBytes } from '../shared';

// Constants for Unix epoch time conversion
const MILLISECONDS_PER_SECOND = 1000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Decompress a DEFLATE-compressed string
 */
export function decompressString(compressedBase64urlString: string): string {
  // Decode base64url to bytes
  const compressedBytes = base64urlToBytes(compressedBase64urlString);
  // Decompress and decode
  const decompressed = pako.inflateRaw(compressedBytes);
  return decoder.decode(decompressed);
}

/**
 * Get current Unix epoch time in seconds
 */
export function getCurrentUnixTime(): number {
  return Math.trunc(Date.now() / MILLISECONDS_PER_SECOND);
}

/**
 * Compute SHA hash of a string and encode to base64url
 */
export async function computeHash(str: string, algorithm: string): Promise<Uint8Array> {
  const data = encoder.encode(str);

  // Map algorithm names to Web Crypto API algorithm names
  const algoMap: Record<string, string> = {
    'sha-256': 'SHA-256',
    'sha-384': 'SHA-384',
    'sha-512': 'SHA-512',
  };

  const cryptoAlgo = algoMap[algorithm.toLowerCase()];
  if (!cryptoAlgo) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }

  const hashBuffer = await crypto.subtle.digest(cryptoAlgo, data);
  return new Uint8Array(hashBuffer);
}
