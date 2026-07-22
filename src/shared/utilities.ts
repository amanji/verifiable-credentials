/**
 * Shared Utilities
 * Common utility functions used across vclib modules
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Decode a base64url-encoded string to a Uint8Array
 * Uses standard Web APIs for browser and Node.js compatibility
 */
export function base64urlToBytes(str: string): Uint8Array {
  // Add padding if needed
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  // Replace base64url characters with standard base64
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  // Decode and convert to bytes
  const decoded = atob(base64);
  return new Uint8Array(decoded.split('').map((c) => c.charCodeAt(0)));
}

/**
 * Decode a base64url-encoded string to UTF-8 string
 * Uses standard Web APIs for browser and Node.js compatibility
 */
export function base64urlToString(str: string): string {
  return decoder.decode(base64urlToBytes(str));
}

/**
 * Encode a Uint8Array to base64url string
 * Uses standard Web APIs for browser and Node.js compatibility
 */
export function uint8ArrayToBase64url(buffer: Uint8Array): string {
  const binaryString = Array.from(buffer)
    .map((byte) => String.fromCharCode(byte))
    .join('');
  // Encode to base64 and convert to base64url
  return btoa(binaryString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Encode a string to base64url format (cross-platform compatible)
 */
export function stringToBase64url(str: string): string {
  const bytes = encoder.encode(str);
  const binaryString = Array.from(bytes)
    .map((byte) => String.fromCharCode(byte))
    .join('');
  return btoa(binaryString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Convert base 64 tring to bytes
 */

export function base64ToBytes(value: string): Uint8Array {
  const decoded = atob(value);
  return new Uint8Array(decoded.split('').map((c) => c.charCodeAt(0)));
}

/**
 * Convert bytes to base 64
 */

export function byteArrayToBase64(byteArray: Uint8Array): string {
  const binary = Array.from(byteArray)
    .map((byte) => String.fromCharCode(byte))
    .join('');

  return btoa(binary);
}
