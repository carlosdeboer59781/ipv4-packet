// Public API surface for ipv4-packet.
// Re-exporting from core keeps the entry point stable even if the
// internal layout changes.
export {
  parseIPv4,
  IPv4PacketError,
  PROTOCOLS,
} from './core.js';
