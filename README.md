# ipv4-packet

Decode an IPv4 datagram buffer into its header fields and locate its payload.

```js
import { parseIPv4, IPv4PacketError, PROTOCOLS } from 'ipv4-packet';

const buffer = Buffer.from([
  0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00,
  0x40, 0x06, 0xab, 0xcd, 0xc0, 0x00, 0x02, 0x01,
  0xc6, 0x33, 0x64, 0x02, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
]);

const packet = parseIPv4(buffer);

packet.version;        // 4
packet.ihl;            // 5
packet.headerLength;   // 20
packet.totalLength;    // 40
packet.protocol;       // 6
packet.protocolName;   // 'TCP'
packet.source;         // '192.0.2.1'
packet.destination;    // '198.51.100.2'
packet.options;        // Uint8Array of header options (empty when IHL is 5)
packet.payloadOffset;  // 20
packet.payloadLength;  // 20

buffer.subarray(packet.payloadOffset, packet.payloadOffset + packet.payloadLength);
```

`parseIPv4` throws `IPv4PacketError` when the buffer is not a valid IPv4
datagram: wrong version, truncated header, IHL below 5, or a total length
that does not fit the buffer.

## Why this exists

Most packet-decoding code either pulls in a full protocol stack or reaches
for a hex dump and a regex. This library sits in the middle: it decodes
exactly one IPv4 header from one buffer, with no allocation of the payload
and no transport-layer interpretation. The trade-off is that callers are
responsible for slicing the payload themselves using `payloadOffset` and
`payloadLength`; in exchange, the parser never copies payload bytes and
never holds state between calls.

## The awkward edge

`totalLength` can be smaller than the buffer. That is normal — Ethernet
frames are often padded to a minimum size — so the parser trusts
`totalLength` for `payloadLength` and does not require it to equal
`buffer.length`. It does reject a `totalLength` larger than the buffer,
because that means the datagram is truncated and the payload is not all
there.

Options are returned as a `Uint8Array` copy. If you need the raw option
bytes in place, read them from the original buffer at `headerLength - 20`
bytes starting at offset 20.
