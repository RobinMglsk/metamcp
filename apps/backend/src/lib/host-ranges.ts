import { isIP } from "net";

/** Expands an IPv6 literal into its eight 16-bit groups (no zone ids / dotted tails). */
function ipv6Groups(ip: string): number[] | null {
  let text = ip.toLowerCase();
  // dotted tail (::ffff:1.2.3.4) -> two hex groups
  const tail = text.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (tail) {
    const [a, b, c, d] = tail.slice(1).map(Number);
    text = text.replace(
      tail[0],
      `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`,
    );
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...rest].map((g) =>
    parseInt(g, 16),
  );
  return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff)
    ? groups
    : null;
}

const v4From = (hi: number, lo: number) =>
  `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/**
 * IPv4 address embedded in an IPv6 one: IPv4-mapped (::ffff:a.b.c.d),
 * IPv4-compatible (::a.b.c.d), NAT64 (64:ff9b::/96) and 6to4 (2002::/16).
 * Such addresses reach the embedded IPv4 host through a gateway/translator.
 */
export function embeddedIPv4(address: string): string | null {
  const ip = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (isIP(ip) !== 6) return null;
  const g = ipv6Groups(ip);
  if (!g) return null;
  const firstFiveZero = g.slice(0, 5).every((x) => x === 0);
  if (firstFiveZero && g[5] === 0xffff) return v4From(g[6], g[7]); // mapped
  if (firstFiveZero && g[5] === 0 && (g[6] !== 0 || g[7] > 1)) {
    return v4From(g[6], g[7]); // compatible (excluding :: and ::1)
  }
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) {
    return v4From(g[6], g[7]); // NAT64
  }
  if (g[0] === 0x2002) return v4From(g[1], g[2]); // 6to4
  return null;
}

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

  // IPv4 embedded in the IPv6 address (mapped, compatible, NAT64, 6to4)
  const embedded = embeddedIPv4(lower);
  if (embedded) return isPrivateV4(embedded);

  const first = parseInt(lower.split(":")[0] || "0", 16);
  return (
    (first & 0xfe00) === 0xfc00 || // fc00::/7 unique local
    (first & 0xffc0) === 0xfe80 // fe80::/10 link-local
  );
}

/**
 * True for hostnames that point at the machine itself or a private network:
 * localhost-style names and loopback / private / link-local / reserved IPs
 * (IPv4, IPv6 and IPv6 forms embedding an IPv4 address). Only real IP literals are matched against
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

  const embedded = embeddedIPv4(ip);
  if (embedded) return isLinkLocalOrMetadataV4(embedded);
  const first = parseInt(ip.split(":")[0] || "0", 16);
  return (
    (first & 0xffc0) === 0xfe80 || // fe80::/10
    ip === "fd00:ec2::254" // AWS IPv6 instance metadata
  );
}
