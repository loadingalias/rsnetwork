// Writes the reading of llhttp, the HTTP/1.1 parser of Node.js, of each request of the corpora to
// standard output: one line for each input, with its name, its bytes in hexadecimal, each part,
// and the end, separated by tabs. `tests/h1_differential.rs` compares rsnetwork with these
// readings. The parser has its strict defaults, as a Node.js server has them.
//
// Run it from the root of the repository, with the root of the corpora as an optional argument:
//
//   node --expose-internals --no-warnings tests/differential/llhttp.mjs > tests/differential/llhttp.txt

import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const { internalBinding } = require('internal/test/binding');
const { HTTPParser, allMethods } = internalBinding('http_parser');

// The head of the request that carries each chunked body of `fuzz/seeds/chunked`.
const CHUNKED = Buffer.from('POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n', 'latin1');

// The bytes as text. Each visible ASCII byte stays, except `%`, `,`, and `=`. Each other byte
// becomes `%` and two hexadecimal digits.
function text(bytes) {
  return Array.from(bytes, (byte) =>
    byte > 0x20 && byte < 0x7f && byte !== 0x25 && byte !== 0x2c && byte !== 0x3d
      ? String.fromCharCode(byte)
      : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`,
  ).join('');
}

// Node.js gives each byte of a head as one character of a string.
const bytes = (string) => Buffer.from(string, 'latin1');

// Field lines as text: `name=value` for each line, in order, with a comma between them. Node.js
// gives the lines as one array of names and values.
function fields(lines) {
  const pairs = [];
  for (let at = 0; at < lines.length; at += 2) {
    pairs.push(`${text(bytes(lines[at]))}=${text(bytes(lines[at + 1]))}`);
  }
  return pairs.join(',');
}

// The parts and the end of the reading of `input`, in the form of `tests/h1_differential.rs`.
function read(input) {
  const parser = new HTTPParser();
  const parts = [];
  // The current message, the field lines and the target that arrive before its head is complete,
  // and its trailer field lines.
  let message = null;
  let last = null;
  let lines = [];
  let url = '';
  let trailers = [];
  parser[HTTPParser.kOnHeaders] = (headers, chunk) => {
    if (message === null) {
      lines.push(...headers);
      url += chunk;
    } else {
      trailers.push(...headers);
    }
  };
  parser[HTTPParser.kOnHeadersComplete] = (major, minor, headers, method, chunk, _status, _reason, upgrade, keep) => {
    lines.push(...(headers ?? []));
    url += chunk ?? '';
    const version = `HTTP/${major}.${minor}`;
    const head = `${text(bytes(allMethods[method]))} ${text(bytes(url))} ${version} ${keep ? 'keep' : 'close'}`;
    message = { head: `${head} ${fields(lines)}`, body: [], upgrade };
    lines = [];
    url = '';
    return 0;
  };
  parser[HTTPParser.kOnBody] = (chunk) => {
    message.body.push(Buffer.from(chunk));
  };
  parser[HTTPParser.kOnMessageComplete] = () => {
    parts.push(`${message.head} ${text(Buffer.concat(message.body))} ${fields(trailers)}`);
    last = message;
    message = null;
    trailers = [];
  };
  parser.initialize(HTTPParser.REQUEST, {}, 0, HTTPParser.kLenientNone);
  const read = parser.execute(input);
  if (read instanceof Error) {
    // After a message with no persistence, the connection closes, and llhttp refuses more bytes.
    return [...parts, read.code === 'HPE_CLOSED_CONNECTION' ? 'done' : 'refused'];
  }
  if (message === null && last !== null && last.upgrade) {
    // The bytes after the request belong to the new protocol.
    return [...parts, `switch ${text(input.subarray(read))}`, 'done'];
  }
  if (read !== input.length) {
    throw new Error(`llhttp stopped at byte ${read} of ${input.length} with no error`);
  }
  return [...parts, parser.finish() instanceof Error ? 'cut' : 'done'];
}

const root = process.argv[2] ?? '.';
const inputs = [];
for (const [corpus, prefix, skip] of [
  ['request', Buffer.alloc(0), 2],
  ['chunked', CHUNKED, 1],
]) {
  const dir = join(root, 'fuzz/seeds', corpus);
  for (const file of readdirSync(dir)) {
    const input = Buffer.concat([prefix, readFileSync(join(dir, file)).subarray(skip)]);
    inputs.push([`${corpus}/${file}`, input]);
  }
}
inputs.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
for (const [name, input] of inputs) {
  process.stdout.write(`${[name, input.toString('hex'), ...read(input)].join('\t')}\n`);
}
