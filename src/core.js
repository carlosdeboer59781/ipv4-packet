// IPv4 datagram parser.
//
// Scope decision: this parser decodes the IPv4 header (including options)
// and reports where the payload begins. It does NOT reassemble fragments,
// validate checksums, or interpret transport-layer payloads. Those are
// separate concerns and would drag in state that a single-buffer parser
// should not own.

/**
 * Error thrown for malformed or truncated IPv4 buffers.
 *
 * We use a dedicated class rather than Error so callers can distinguish
 * "this is not a valid IPv4 datagram" from "something else went wrong".
 */
export class IPv4PacketError extends Error {
  constructor(message) {
    super(message);
    this.name = 'IPv4PacketError';
  }
}

/**
 * IANA protocol numbers we care to name. Anything not listed is reported
 * as its numeric value; we deliberately do not pretend to know every
 * assignment.
 */
export const PROTOCOLS = Object.freeze({
  1: 'ICMP',
  2: 'IGMP',
  6: 'TCP',
  17: 'UDP',
  41: 'IPv6',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  89: 'OSPF',
  132: 'SCTP',
});

const MIN_HEADER_BYTES = 20;
const MAX_HEADER_BYTES = 60; // IHL is 4 bits, so 15 * 4 bytes.

function readUInt16BE(buffer, offset) {
  return ((buffer[offset] << 8) | buffer[offset + 1]) >>> 0;
}

/**
 * Parse an IPv4 datagram from a Buffer or Uint8Array.
 *
 * Returns a plain object with the decoded header fields. The payload is
 * NOT copied; `payloadOffset` tells the caller where it starts, and
 * `payloadLength` tells them how many bytes belong to it.
 *
 * @param {Buffer|Uint8Array} buffer
 * @returns {{
 *   version: number,
 *   ihl: number,
 *   headerLength: number,
 *   dscp: number,
 *   ecn: number,
 *   totalLength: number,
 *   identification: number,
 *   flags: {{ reserved: boolean, dontFragment: boolean, moreFragments: boolean }},
 *   fragmentOffset: number,
 *   ttl: number,
 *   protocol: number,
 *   protocolName: string,
 *   headerChecksum: number,
 *   source: string,
 *   destination: string,
 *   options: Uint8Array,
 *   payloadOffset: number,
 *   payloadLength: number,
 * }}
 */
export function parseIPv4(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new IPv4PacketError('expected a Uint8Array or Buffer');
  }
  if (buffer.length < MIN_HEADER_BYTES) {
    throw new IPv4PacketError(
      `buffer too short for an IPv4 header: ${buffer.length} bytes`
    );
  }

  const version = buffer[0] >>> 4;
  if (version !== 4) {
    throw new IPv4PacketError(`not an IPv4 packet: version ${version}`);
  }

  const ihl = buffer[0] & 0x0f;
  const headerLength = ihl * 4;
  if (headerLength < MIN_HEADER_BYTES) {
    throw new IPv4PacketError(
      `invalid IHL: ${ihl} (header length ${headerLength} bytes)`
    );
  }
  if (headerLength > MAX_HEADER_BYTES) {
    throw new IPv4PacketError(
      `invalid IHL: ${ihl} (header length ${headerLength} bytes)`
    );
  }
  if (buffer.length < headerLength) {
    throw new IPv4PacketError(
      `buffer truncated: need ${headerLength} header bytes, have ${buffer.length}`
    );
  }

  const totalLength = readUInt16BE(buffer, 2);
  if (totalLength < headerLength) {
    throw new IPv4PacketError(
      `total length ${totalLength} is smaller than header length ${headerLength}`
    );
  }
  if (totalLength > buffer.length) {
    throw new IPv4PacketError(
      `total length ${totalLength} exceeds buffer length ${buffer.length}`
    );
  }

  const dscp = buffer[1] >>> 2;
  const ecn = buffer[1] & 0x03;
  const identification = readUInt16BE(buffer, 4);
  const flagsAndOffset = readUInt16BE(buffer, 6);
  const reserved = (flagsAndOffset & 0x8000) !== 0;
  const dontFragment = (flagsAndOffset & 0x4000) !== 0;
  const moreFragments = (flagsAndOffset & 0x2000) !== 0;
  const fragmentOffset = flagsAndOffset & 0x1fff;
  const ttl = buffer[8];
  const protocol = buffer[9];
  const headerChecksum = readUInt16BE(buffer, 10);
  const source = formatIPv4(buffer, 12);
  const destination = formatIPv4(buffer, 16);

  // Options live between the fixed 20-byte header and the end of the
  // header as declared by IHL. We copy them so the caller can keep the
  // slice without retaining the whole datagram.
  const options = new Uint8Array(buffer.buffer, buffer.byteOffset + 20, headerLength - 20).slice();

  const payloadOffset = headerLength;
  const payloadLength = totalLength - headerLength;

  return {
    version,
    ihl,
    headerLength,
    dscp,
    ecn,
    totalLength,
    identification,
    flags: { reserved, dontFragment, moreFragments },
    fragmentOffset,
    ttl,
    protocol,
    protocolName: PROTOCOLS[protocol] ?? `unknown(${protocol})`,
    headerChecksum,
    source,
    destination,
    options,
    payloadOffset,
    payloadLength,
  };
}

function formatIPv4(buffer, offset) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}
