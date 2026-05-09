# Reverse Engineering Protocols

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 62_finding_vulnerabilities.md
**What You Will Learn:** How to use NeoDAX to understand custom network protocols and data formats.

## Why Protocol RE Is Valuable

Many applications communicate using undocumented protocols. Understanding these protocols is necessary for:

- Building compatible clients or servers
- Security testing of the protocol
- Analyzing malware command-and-control communication
- Interoperability projects

## Finding Network Code

Start by looking for network-related imports:

```bash
./neodax -y /binary | grep -E "socket|connect|send|recv|htons|htonl"
```

The functions that call these imports are the network I/O functions. They are your starting point.

## Tracing Data Flow

Once you have the send/receive functions, trace the data flow:

1. Find where received data is stored (what buffer does `recv` write into?).
2. Find what code reads from that buffer.
3. That code is the protocol parser.

Work from the receive call outward through cross-references:

```bash
./neodax -r /binary
```

Find xrefs from the address where `recv@plt` is called. The function containing that call is the receive handler.

## Identifying Protocol Structure

Look for patterns in the parsing code:

**Fixed header:** Code reads a fixed number of bytes first, then uses values in those bytes to determine what follows. The header size and field offsets are visible as constants.

**Length-prefixed fields:** A field read pattern where the length is read first, then that many bytes are read. The length field offset is a constant.

**Magic numbers:** Values compared with specific constants at the start of messages. These are message type codes or protocol magic.

**State machine dispatch:** A switch statement that dispatches based on a message type field. The switch table contains one case per message type.

## Extracting Protocol Definitions

As you identify fields, build a protocol definition:

```
Packet header (16 bytes):
  offset 0: uint32 magic (0xDEADBEEF)
  offset 4: uint16 message_type
  offset 6: uint16 flags
  offset 8: uint32 sequence_number
  offset 12: uint32 payload_length

Payload: payload_length bytes
```

## Documenting as You Go

Create a markdown file documenting what you find. Use NeoDAX's string extraction to find error messages that confirm your understanding:

```bash
./neodax -t /binary | grep -i "invalid\|unknown\|error\|bad"
```

Error message strings often name protocol concepts: "invalid magic", "unknown message type", "bad length".

## Practice

1. Find a binary that makes network connections.
2. Identify the send and receive functions.
3. Trace what happens to received data.
4. Document at least the first 8 bytes of the protocol header.

## Next

Continue to `64_android_binary_analysis.md`.
