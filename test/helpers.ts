import fs from 'fs';
import path from 'path';
import os from 'os';

export const repoRoot = path.resolve(__dirname, '..');

export function fixture(rel: string): string {
  return path.join(__dirname, 'fixtures', rel);
}

export function example(rel: string): string {
  return path.join(repoRoot, 'examples', rel);
}

export function readFixture(rel: string): string {
  return fs.readFileSync(fixture(rel), 'utf-8');
}

export function readExample(rel: string): string {
  return fs.readFileSync(example(rel), 'utf-8');
}

/**
 * Run a callback with a fresh temp directory. The directory is removed
 * (recursively) when the callback returns or throws.
 */
export async function withTempDir<T>(fn: (dir: string) => T | Promise<T>): Promise<T> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reaper-test-'));
  try {
    return await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
