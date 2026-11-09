export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      const value = part.slice(idx + 1).trim();
      return /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined;
    }
  }
  return undefined;
}

export interface CookieOptions {
  path: string;
  maxAgeSeconds: number;
  secure: boolean;
}

export function serializeCookie(name: string, value: string, o: CookieOptions): string {
  const parts = [
    `${name}=${value}`,
    `Path=${o.path}`,
    `Max-Age=${o.maxAgeSeconds}`,
    'HttpOnly',
    'SameSite=Strict',
  ];
  if (o.secure) parts.push('Secure');
  return parts.join('; ');
}

export const clearCookie = (name: string, path: string, secure: boolean) =>
  serializeCookie(name, '', { path, maxAgeSeconds: 0, secure });
