import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIPv4, IPv4PacketError, PROTOCOLS } from '../src/index.js';

// Build a minimal IPv4 header for tests. Options default to empty.
function buildPacket({
  version = 4,
  ihl = 5,
  dscp = 0,
  ecn = 0,
  totalLength,
  identification = 0x1234,
  df = false,
  mf = false,
  fragmentOffset = 0,
  ttl = 64,
  protocol = 6,
  checksum = 0xabcd,
  source = [192, 0, 2, 1],
  destination = [198, 51, 100, 2],
  options = [],
  payload = [],
} = {}) {
  const headerLength = ihl * 4;
  const payloadLength = payload.length;
  const computedTotal = totalLength ?? headerLength + payloadLength;
  const buf = Buffer.alloc(headerLength + payloadLength);

  buf[0] = ((version & 0x0f) << 4) | (ihl & 0x0f);
  buf[1] = ((dscp & 0x3f) << 2) | (ecn & 0x03);
  buf.writeUInt16BE(computedTotal, 2);
  buf.writeUInt16BE(identification, 4);
  let flagsAndOffset = fragmentOffset & 0x1fff;
  if (df) flagsAndOffset |= 0x4000;
  if (mf) flagsAndOffset |= 0x2000;
  buf.writeUInt16BE(flagsAndOffset, 6);
  buf[8] = ttl;
  buf[9] = protocol;
  buf.writeUInt16BE(checksum, 10);
  buf[12] = source[0];
  buf[13] = source[1];
  buf[14] = source[2];
  buf[15] = source[3];
  buf[16] = destination[0];
  buf[17] = destination[1];
  buf[18] = destination[2];
  buf[19] = destination[3];
  for (let i = 0; i < options.length; i++) buf[20 + i] = options[i];
  for (let i = 0; i < payload.length; i++) buf[headerLength + i] = payload[i];
  return buf;
}

test('parses a minimal TCP packet with no payload', () => {
  const buf = buildPacket({ protocol: 6 });
  const p = parseIPv4(buf);
  assert.equal(p.version, 4);
  assert.equal(p.ihl, 5);
  assert.equal(p.headerLength, 20);
  assert.equal(p.totalLength, 20);
  assert.equal(p.protocol, 6);
  assert.equal(p.protocolName, 'TCP');
  assert.equal(p.source, '192.0.2.1');
  assert.equal(p.destination, '198.51.100.2');
  assert.equal(p.payloadOffset, 20);
  assert.equal(p.payloadLength, 0);
  assert.equal(p.options.length, 0);
});

test('reports payload offset and length for a UDP packet with payload', () => {
  const buf = buildPacket({ protocol: 17, payload: [1, 2, 3, 4, 5] });
  const p = parseIPv4(buf);
  assert.equal(p.protocolName, 'UDP');
  assert.equal(p.payloadOffset, 20);
  assert.equal(p.payloadLength, 5);
  assert.equal(p.totalLength, 25);
});

test('decodes DSCP and ECN from the second byte', () => {
  const buf = buildPacket({ dscp: 0x2e, ecn: 0x03 });
  const p = parseIPv4(buf);
  assert.equal(p.dscp, 0x2e);
  assert.equal(p.ecn, 0x03);
});

test('decodes fragmentation flags and offset', () => {
  const buf = buildPacket({ df: true, mf: true, fragmentOffset: 0x1abc });
  const p = parseIPv4(buf);
  assert.equal(p.flags.reserved, false);
  assert.equal(p.flags.dontFragment, true);
  assert.equal(p.flags.moreFragments, true);
  assert.equal(p.fragmentOffset, 0x1abc);
});

test('exposes header options when IHL is greater than 5', () => {
  const options = [0x01, 0x01, 0x00, 0x00];
  const buf = buildPacket({ ihl: 6, options, payload: [9, 9] });
  const p = parseIPv4(buf);
  assert.equal(p.ihl, 6);
  assert.equal(p.headerLength, 24);
  assert.equal(p.options.length, 4);
  assert.deepEqual(Array.from(p.options), options);
  assert.equal(p.payloadOffset, 24);
  assert.equal(p.payloadLength, 2);
});

test('options slice is a copy, not a view of the input', () => {
  const options = [0xaa, 0xbb, 0xcc, 0xdd];
  const buf = buildPacket({ ihl: 6, options });
  const p = parseIPv4(buf);
  buf[20] = 0x00;
  assert.equal(p.options[0], 0xaa);
});

test('unknown protocol numbers are reported as unknown(N)', () => {
  const buf = buildPacket({ protocol: 200 });
  const p = parseIPv4(buf);
  assert.equal(p.protocol, 200);
  assert.equal(p.protocolName, 'unknown(200)');
  assert.equal(PROTOCOLS[200], undefined);
});

test('rejects buffers shorter than the minimum header', () => {
  assert.throws(() => parseIPv4(Buffer.alloc(19)), IPv4PacketError);
});

test('rejects non-IPv4 versions', () => {
  const buf = buildPacket({ version: 6 });
  assert.throws(() => parseIPv4(buf), IPv4PacketError);
});

test('rejects IHL that declares fewer than 20 header bytes', () => {
  const buf = buildPacket({ ihl: 4 });
  assert.throws(() => parseIPv4(buf), IPv4PacketError);
});

test('rejects a total length smaller than the header length', () => {
  const buf = buildPacket({ totalLength: 10 });
  assert.throws(() => parseIPv4(buf), IPv4PacketError);
});

test('rejects a total length larger than the buffer', () => {
  const buf = buildPacket({ totalLength: 100 });
  assert.throws(() => parseIPv4(buf), IPv4PacketError);
});

test('rejects a buffer truncated inside the declared header', () => {
  const buf = buildPacket({ ihl: 6, options: [0, 0, 0, 0] }).subarray(0, 22);
  assert.throws(() => parseIPv4(buf), IPv4PacketError);
});

test('rejects non-Uint8Array input', () => {
  assert.throws(() => parseIPv4('not a buffer'), IPv4PacketError);
  assert.throws(() => parseIPv4(null), IPv4PacketError);
});

test('accepts a Uint8Array view with a non-zero byteOffset', () => {
  const inner = buildPacket({ payload: [7, 7, 7] });
  const padded = Buffer.concat([Buffer.from([0xff, 0xff]), inner]);
  const view = new Uint8Array(padded.buffer, padded.byteOffset + 2, inner.length);
  const p = parseIPv4(view);
  assert.equal(p.source, '192.0.2.1');
  assert.equal(p.payloadLength, 3);
});
