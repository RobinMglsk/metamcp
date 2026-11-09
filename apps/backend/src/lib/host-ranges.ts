import { isIP } from "net";

const LOCAL_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain"];

function isPrivateV4(ip: string): boolean {
  const [a, b, c] = ip.split(".").map(Number);
  return (
    a === 0 || // "this" network / 0.0.0.0
    a === 10 ||
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) || // link-local, cloud metadata (169.254.169.254)
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224 // multicast / reserved / broadcast
  );
}

function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;

  // IPv4-mapped (::ffff:a.b.c.d, or the ::ffff:xxxx:xxxx form URL() normalises to)
  const dotted = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return isPrivateV4(dotted[1]);
  const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return isPrivateV4(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }

  const first = parseInt(lower.split(":")[0] || "0", 16);
  return (
    (first & 0xfe00) === 0xfc00 || // fc00::/7 unique local
    (first & 0xffc0) === 0xfe80 // fe80::/10 link-local
  );
}

/**
 * True for hostnames that point at the machine itself or a private network:
 * localhost-style names and loopback / private / link-local / reserved IPs
 * (IPv4, IPv6 and IPv4-mapped IPv6). Only real IP literals are matched against
 * the ranges, so a domain such as "10.example.com" is not treated as private.
 */
export function isPrivateOrLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || LOCAL_SUFFIXES.some((s) => host.endsWith(s))) {
    return true;
  }
  const version = isIP(host);
  if (version === 4) return isPrivateV4(host);
  if (version === 6) return isPrivateV6(host);
  return false;
}

function isLinkLocalOrMetadataV4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return (
    (a === 169 && b === 254) || // link-local, incl. 169.254.169.254 (AWS/GCP/Azure/...)
    ip === "100.100.100.200" || // Alibaba Cloud metadata
    ip === "168.63.129.16" // Azure wire server
  );
}

/**
 * Addresses that should never be contacted from the server, whatever the
 * deployment: link-local (cloud instance metadata) and well known metadata
 * IPs, for IPv4, IPv6 and IPv4-mapped IPv6.
 */
export function isLinkLocalOrMetadataAddress(address: string): boolean {
  const ip = address.toLowerCase().replace(/^\[|\]$/g, "");
  const version = isIP(ip);
  if (version === 4) return isLinkLocalOrMetadataV4(ip);
  if (version !== 6) return false;

  const dotted = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return isLinkLocalOrMetadataV4(dotted[1]);
  const hex = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return isLinkLocalOrMetadataV4(
      `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`,
    );
  }
  const first = parseInt(ip.split(":")[0] || "0", 16);
  return (
    (first & 0xffc0) === 0xfe80 || // fe80::/10
    ip === "fd00:ec2::254" // AWS IPv6 instance metadata
  );
}
