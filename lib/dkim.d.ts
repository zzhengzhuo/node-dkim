import Key from "dkim-key";
import Signature from "dkim-signature";

export { Key, Signature };

export function configKey(key: null | Key);

export function getKey(
  domain: any,
  selector: any,
  isDns: boolean,
  callback: (error: Error, key: Key) => any
): void;
export function getKey(
  domain: any,
  callback: (error: Error, key: Key) => any
): void;

export function processBody(message: string | Buffer, method?: string): string;

export function processHeader(
  headers: string[],
  signHeaders: any[],
  method: string
): string;
export function processHeader(headers: string[], method: string): string;

export interface VerifyResult {
  verified: false;
  status: string;
  error: null;
  signature: null;
  key: null;
  processedHeader: string;
}

export function verify(
  message: Buffer,
  isDns: boolean,
  callback: (error: Error, result: VerifyResult) => any
): void;

export function verifySignature(
  body: Buffer,
  headers: any[],
  isDns: boolean,
  callback: (error: Error, result: VerifyResult) => any
): void;

export function fixBody(message: Buffer): Buffer;
