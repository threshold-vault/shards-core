const MAX_SECRET_CHARACTERS = 256;
export const SPLIT_SECRET_CHARACTER_LIMIT = MAX_SECRET_CHARACTERS;
const VERSION = "shards-1";
const COMPACT_VERSION = "shards-code-1";
const AES_KEY_LENGTH = 32;
const AES_GCM_IV_LENGTH = 12;
const AES_GCM_TAG_BITS = 128;
const SECRET_SHARE_LIMIT = 255;
const DEFAULT_HOLDER_PREFIX = "Holder";
const LEGACY_QR_PREFIX = "SHARDSQR1:";
const COMPACT_PAYLOAD_VERSION = 1;
const COMPACT_FLAG_GZIP = 1;
const COMPACT_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export type CompressionMode = "none" | "gzip";

export type SplitSecretInput = {
  secret: string;
  required: number;
  total: number;
  holderLabels?: string[];
  ceremonyId?: string;
};

export type ShardRecord = {
  version: typeof VERSION;
  ceremonyId: string;
  index: number;
  total: number;
  required: number;
  holderLabel: string;
  secretLength: number;
  compression: CompressionMode;
  iv: string;
  ciphertext: string;
  share: string;
};

export type ParsedShard = ShardRecord & {
  fingerprint: string;
  canonicalPayload: string;
  qrPayload: string;
  compactCode: string;
  compactBody: string;
  compactCheckCode: string;
  compactVisualLabel: string;
};

export type SplitSecretResult = {
  ceremonyId: string;
  total: number;
  required: number;
  secretLength: number;
  shards: ParsedShard[];
};

export type RecoverSecretResult = {
  ceremonyId: string;
  total: number;
  required: number;
  secret: string;
  usedShards: ParsedShard[];
};

export type ValidationResult =
  | {
      valid: true;
      shard: ParsedShard;
    }
  | {
      valid: false;
      error: string;
    };

export type CompactRecoveryCodeParts = {
  header: string;
  body: string;
  bodyGroups: string[];
  checkCode: string;
  fullCode: string;
  legacyPipeCode: string;
};

export type CompactLengthEstimate = {
  payloadBytesUpperBound: number;
  bodyCharactersUpperBound: number;
  groupedBodyCharactersUpperBound: number;
  checkCharacters: number;
  totalCharactersUpperBound: number;
};

export type ShardInputKind =
  | "compact-recovery-code"
  | "legacy-shards-1"
  | "legacy-qr"
  | "legacy-json"
  | "legacy-share-only"
  | "invalid";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  assert(value.length % 2 === 0, "Malformed hex value.");
  const bytes = new Uint8Array(value.length / 2);

  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array {
  assert(/^[A-Za-z0-9\-_]+$/u.test(value), "Malformed base64url value.");
  const paddingLength = (4 - (value.length % 4 || 4)) % 4;
  const padded = `${value}${"=".repeat(paddingLength)}`
    .replaceAll("-", "+")
    .replaceAll("_", "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function chunkString(value: string, chunkSize: number): string[] {
  const chunks: string[] = [];

  for (let offset = 0; offset < value.length; offset += chunkSize) {
    chunks.push(value.slice(offset, offset + chunkSize));
  }

  return chunks;
}

function generateCeremonyId(): string {
  return bytesToHex(randomBytes(8));
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function sha256Bytes(value: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(value));
  return new Uint8Array(digest);
}

function formatFingerprintBytes(bytes: Uint8Array): string {
  assert(bytes.length >= 8, "Fingerprint source is too short.");
  return chunkString(bytesToHex(bytes.slice(0, 8)), 4).join(":");
}

function canonicalPayload(record: ShardRecord): string {
  const normalizedHolder = record.holderLabel.replace(/\r\n/gu, "\n");

  return JSON.stringify({
    version: VERSION,
    ceremonyId: record.ceremonyId,
    index: record.index,
    total: record.total,
    required: record.required,
    holderLabel: normalizedHolder,
    secretLength: record.secretLength,
    compression: record.compression,
    iv: record.iv,
    ciphertext: record.ciphertext,
    share: record.share
  });
}

function fingerprintPayload(record: ShardRecord): string {
  return JSON.stringify({
    version: VERSION,
    ceremonyId: record.ceremonyId,
    index: record.index,
    total: record.total,
    required: record.required,
    secretLength: record.secretLength,
    compression: record.compression,
    iv: record.iv,
    ciphertext: record.ciphertext,
    share: record.share
  });
}

function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return "";
  }

  let value = 0n;

  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte);
  }

  let output = "";

  while (value > 0n) {
    const remainder = Number(value % 58n);
    output = `${COMPACT_ALPHABET[remainder]}${output}`;
    value /= 58n;
  }

  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }

    output = `${COMPACT_ALPHABET[0]}${output}`;
  }

  return output || COMPACT_ALPHABET.charAt(0);
}

function decodeBase58(value: string): Uint8Array {
  assert(value.length > 0, "Compact recovery code body is missing.");
  let numericValue = 0n;

  for (const character of value) {
    const digit = COMPACT_ALPHABET.indexOf(character);
    assert(digit >= 0, "Compact recovery code contains an invalid character.");
    numericValue = numericValue * 58n + BigInt(digit);
  }

  const bytes: number[] = [];

  while (numericValue > 0n) {
    bytes.unshift(Number(numericValue & 0xffn));
    numericValue >>= 8n;
  }

  for (const character of value) {
    if (character !== COMPACT_ALPHABET[0]) {
      break;
    }

    bytes.unshift(0);
  }

  return Uint8Array.from(bytes);
}

function writeUint16(bytes: Uint8Array, offset: number, value: number) {
  assert(Number.isInteger(value) && value >= 0 && value <= 0xffff, "Malformed uint16 value.");
  bytes[offset] = (value >> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

function readUint16(bytes: Uint8Array, offset: number): number {
  const high = bytes[offset];
  const low = bytes[offset + 1];
  assert(high !== undefined && low !== undefined, "Malformed compact payload.");
  return (high << 8) | low;
}

function shardLabelToken(index: number): string {
  assert(index >= 1, "Shard index must be at least 1.");
  let current = index;
  let token = "";

  while (current > 0) {
    current -= 1;
    token = `${String.fromCharCode(65 + (current % 26))}${token}`;
    current = Math.floor(current / 26);
  }

  return token;
}

function normalizeCompactBody(input: string): string {
  return input.replace(/[\s-]+/gu, "");
}

function headerToken(index: number, required: number, total: number): string {
  return `${shardLabelToken(index)}-${required}of${total}`;
}

async function compressBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([toArrayBuffer(bytes)]).stream().pipeThrough(new CompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

async function decompressBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([toArrayBuffer(bytes)]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

function normalizeHolderLabel(holderLabel: string | undefined, index: number): string {
  const trimmed = holderLabel?.trim();
  return trimmed && trimmed.length > 0
    ? trimmed
    : `${DEFAULT_HOLDER_PREFIX} ${index}`;
}

function validateSplitInput(input: SplitSecretInput): void {
  assert(input.secret.length > 0, "Secret is required.");
  assert(
    input.secret.length <= MAX_SECRET_CHARACTERS,
    `Secret exceeds ${MAX_SECRET_CHARACTERS} characters.`
  );
  assert(Number.isInteger(input.required), "Threshold M must be an integer.");
  assert(Number.isInteger(input.total), "Threshold N must be an integer.");
  assert(input.required >= 2, "Threshold M must be at least 2.");
  assert(input.total >= input.required, "Threshold N must be at least M.");
  assert(
    input.total <= SECRET_SHARE_LIMIT,
    `Threshold N must be ${SECRET_SHARE_LIMIT} or less.`
  );
}

function gfMul(left: number, right: number): number {
  let a = left;
  let b = right;
  let product = 0;

  while (b > 0) {
    if ((b & 1) === 1) {
      product ^= a;
    }

    a <<= 1;

    if ((a & 0x100) !== 0) {
      a ^= 0x11b;
    }

    b >>= 1;
  }

  return product;
}

function gfPow(base: number, exponent: number): number {
  let result = 1;

  for (let index = 0; index < exponent; index += 1) {
    result = gfMul(result, base);
  }

  return result;
}

function gfInv(value: number): number {
  assert(value !== 0, "Cannot invert zero in GF(256).");
  return gfPow(value, 254);
}

function splitKey(secret: Uint8Array, total: number, required: number): Uint8Array[] {
  const shares = Array.from({ length: total }, () => new Uint8Array(secret.length));

  for (let byteIndex = 0; byteIndex < secret.length; byteIndex += 1) {
    const coefficients = new Uint8Array(required);
    const secretByte = secret[byteIndex];
    assert(secretByte !== undefined, "Secret byte is missing.");
    coefficients[0] = secretByte;

    if (required > 1) {
      coefficients.set(randomBytes(required - 1), 1);
    }

    for (let shareIndex = 0; shareIndex < total; shareIndex += 1) {
      const x = shareIndex + 1;
      let y = 0;

      for (let exponent = 0; exponent < coefficients.length; exponent += 1) {
        const coefficient = coefficients[exponent] ?? 0;
        const term = exponent === 0 ? coefficient : gfMul(coefficient, gfPow(x, exponent));
        y ^= term;
      }

      const share = shares[shareIndex];
      assert(share, "Share slot is missing.");
      share[byteIndex] = y;
    }
  }

  return shares;
}

function recoverKey(shares: Array<{ index: number; bytes: Uint8Array }>): Uint8Array {
  assert(shares.length > 0, "At least one shard is required.");
  const secretLength = shares[0]?.bytes.length ?? 0;
  const recovered = new Uint8Array(secretLength);

  for (let byteIndex = 0; byteIndex < secretLength; byteIndex += 1) {
    let value = 0;

    for (let sourceIndex = 0; sourceIndex < shares.length; sourceIndex += 1) {
      const source = shares[sourceIndex];
      assert(source, "Shard source is missing.");
      let basis = 1;

      for (let otherIndex = 0; otherIndex < shares.length; otherIndex += 1) {
        if (sourceIndex === otherIndex) {
          continue;
        }

        const other = shares[otherIndex];
        assert(other, "Shard source is missing.");
        const numerator = other.index;
        const denominator = other.index ^ source.index;
        basis = gfMul(basis, gfMul(numerator, gfInv(denominator)));
      }

      value ^= gfMul(source.bytes[byteIndex] ?? 0, basis);
    }

    recovered[byteIndex] = value;
  }

  return recovered;
}

async function importAesKey(rawKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(rawKey),
    { name: "AES-GCM" },
    false,
    usages
  );
}

async function encryptSecret(secret: Uint8Array, rawKey: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const key = await importAesKey(rawKey, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: AES_GCM_TAG_BITS },
    key,
    toArrayBuffer(secret)
  );
  return new Uint8Array(ciphertext);
}

async function decryptSecret(
  ciphertext: Uint8Array,
  rawKey: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const key = await importAesKey(rawKey, ["decrypt"]);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: AES_GCM_TAG_BITS },
      key,
      toArrayBuffer(ciphertext)
    );

    return new Uint8Array(plaintext);
  } catch {
    throw new Error("Shard set could not be recovered. Wrong set or insufficient valid shards.");
  }
}

function parseLineShard(source: string): Record<string, string> {
  const lines = source
    .trim()
    .split(/\r?\n/gu)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  assert(lines[0] === VERSION.toUpperCase(), "Malformed shard header.");
  const values: Record<string, string> = {};

  for (const line of lines.slice(1)) {
    const separator = line.indexOf(":");
    assert(separator > 0, "Malformed shard line.");
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    values[key] = value;
  }

  return values;
}

function parseShardRecord(value: unknown): ShardRecord {
  assert(value && typeof value === "object", "Malformed shard payload.");
  const record = value as Record<string, unknown>;
  const shardRecord: ShardRecord = {
    version: VERSION,
    ceremonyId: String(record.ceremonyId ?? ""),
    index: Number(record.index),
    total: Number(record.total),
    required: Number(record.required),
    holderLabel: String(record.holderLabel ?? ""),
    secretLength: Number(record.secretLength),
    compression: record.compression === "gzip" ? "gzip" : "none",
    iv: String(record.iv ?? ""),
    ciphertext: String(record.ciphertext ?? ""),
    share: String(record.share ?? "")
  };

  assert(
    record.version === VERSION || record.version === undefined,
    "Unsupported shard version."
  );
  assert(/^[0-9a-f]{16}$/u.test(shardRecord.ceremonyId), "Malformed ceremony ID.");
  assert(Number.isInteger(shardRecord.index), "Malformed shard index.");
  assert(Number.isInteger(shardRecord.total), "Malformed total shard count.");
  assert(Number.isInteger(shardRecord.required), "Malformed threshold.");
  assert(shardRecord.index >= 1, "Shard index must be at least 1.");
  assert(shardRecord.total >= shardRecord.required, "Shard total must be at least threshold.");
  assert(shardRecord.index <= shardRecord.total, "Shard index exceeds shard total.");
  assert(shardRecord.required >= 2, "Threshold must be at least 2.");
  assert(shardRecord.secretLength >= 1, "Malformed secret length.");
  assert(shardRecord.secretLength <= MAX_SECRET_CHARACTERS, "Secret length exceeds limit.");
  assert(shardRecord.holderLabel.length <= 120, "Holder label is too long.");
  assert(fromBase64Url(shardRecord.iv).length === AES_GCM_IV_LENGTH, "Malformed IV.");
  assert(
    fromBase64Url(shardRecord.share).length === AES_KEY_LENGTH,
    "Malformed shard payload length."
  );
  assert(fromBase64Url(shardRecord.ciphertext).length > 16, "Malformed ciphertext.");

  return shardRecord;
}

function encodeCompactPayload(record: ShardRecord): Uint8Array {
  const ceremonyBytes = hexToBytes(record.ceremonyId);
  const ivBytes = fromBase64Url(record.iv);
  const shareBytes = fromBase64Url(record.share);
  const ciphertextBytes = fromBase64Url(record.ciphertext);
  assert(ceremonyBytes.length === 8, "Malformed ceremony ID.");
  assert(ivBytes.length === AES_GCM_IV_LENGTH, "Malformed IV.");
  assert(shareBytes.length === AES_KEY_LENGTH, "Malformed share bytes.");
  assert(ciphertextBytes.length <= 0xffff, "Ciphertext exceeds compact encoding limit.");

  const payload = new Uint8Array(61 + ciphertextBytes.length);
  payload[0] = COMPACT_PAYLOAD_VERSION;
  payload[1] = record.compression === "gzip" ? COMPACT_FLAG_GZIP : 0;
  payload[2] = record.index;
  payload[3] = record.total;
  payload[4] = record.required;
  writeUint16(payload, 5, record.secretLength);
  payload.set(ceremonyBytes, 7);
  payload.set(ivBytes, 15);
  payload.set(shareBytes, 27);
  writeUint16(payload, 59, ciphertextBytes.length);
  payload.set(ciphertextBytes, 61);
  return payload;
}

function decodeCompactPayload(payload: Uint8Array): ShardRecord {
  assert(payload.length >= 61, "Compact recovery code payload is too short.");
  assert(payload[0] === COMPACT_PAYLOAD_VERSION, "Unsupported compact recovery code version.");
  const flags = payload[1] ?? 0;
  const ciphertextLength = readUint16(payload, 59);
  assert(payload.length === 61 + ciphertextLength, "Compact recovery code payload length mismatch.");

  return parseShardRecord({
    version: VERSION,
    ceremonyId: bytesToHex(payload.slice(7, 15)),
    index: payload[2],
    total: payload[3],
    required: payload[4],
    holderLabel: "",
    secretLength: readUint16(payload, 5),
    compression: (flags & COMPACT_FLAG_GZIP) !== 0 ? "gzip" : "none",
    iv: toBase64Url(payload.slice(15, 27)),
    ciphertext: toBase64Url(payload.slice(61)),
    share: toBase64Url(payload.slice(27, 59))
  });
}

async function buildCompactRecoveryCodeParts(
  record: ShardRecord
): Promise<CompactRecoveryCodeParts> {
  const payload = encodeCompactPayload(record);
  const digest = await sha256Bytes(payload);
  const body = encodeBase58(payload);
  const bodyGroups = chunkString(body, 4);
  const checkCode = encodeBase58(digest.slice(0, 2)).padStart(4, COMPACT_ALPHABET[0] ?? "1");
  const header = headerToken(record.index, record.required, record.total);

  return {
    header,
    body,
    bodyGroups,
    checkCode,
    fullCode: `${header} ${bodyGroups.join("-")} ${checkCode}`,
    legacyPipeCode: `${header} | ${bodyGroups.join("-")} | ${checkCode}`
  };
}

async function buildParsedShard(record: ShardRecord): Promise<ParsedShard> {
  const canonical = canonicalPayload(record);
  const fingerprint = formatFingerprintBytes(
    await sha256Bytes(new TextEncoder().encode(fingerprintPayload(record)))
  );
  const compact = await buildCompactRecoveryCodeParts(record);

  return {
    ...record,
    canonicalPayload: canonical,
    fingerprint,
    qrPayload: compact.fullCode,
    compactCode: compact.fullCode,
    compactBody: compact.body,
    compactCheckCode: compact.checkCode,
    compactVisualLabel: compact.header
  };
}

async function parseCompactOrThrow(input: string): Promise<ShardRecord | null> {
  const normalized = input.trim().replace(/\r\n?/gu, "\n");
  const headerMatch = normalized.match(/^([A-Z]+)-([0-9]+)of([0-9]+)([\s\S]*)$/u);

  if (!headerMatch) {
    return null;
  }

  const [, labelToken, requiredText, totalText, remainder = ""] = headerMatch;
  const compactPayload = remainder.replace(/^[\s|-]+/u, "").trim();

  if (compactPayload.length === 0) {
    return null;
  }

  const tokens = compactPayload
    .split(/[|\s]+/u)
    .flatMap((segment) => segment.split("-"))
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0);

  if (tokens.length === 0) {
    return null;
  }

  let declaredCheckCode = "";
  let body = "";

  if (tokens.length === 1) {
    const [singleToken] = tokens;

    if (!singleToken || singleToken.length <= 4) {
      return null;
    }

    declaredCheckCode = singleToken.slice(-4);
    body = singleToken.slice(0, -4);
  } else {
    declaredCheckCode = tokens[tokens.length - 1] ?? "";
    body = tokens.slice(0, -1).join("");
  }

  if (body.length === 0 || declaredCheckCode.length !== 4) {
    return null;
  }

  body = normalizeCompactBody(body);
  const payload = decodeBase58(body);
  const digest = await sha256Bytes(payload);
  const expectedCheckCode = encodeBase58(digest.slice(0, 2)).padStart(
    4,
    COMPACT_ALPHABET[0] ?? "1"
  );
  assert(
    declaredCheckCode === expectedCheckCode,
    "Check code does not match. Re-check this recovery code."
  );

  const record = decodeCompactPayload(payload);
  assert(
    headerToken(record.index, record.required, record.total) === `${labelToken}-${requiredText}of${totalText}`,
    "Compact recovery code header does not match the encoded shard payload."
  );
  assert(Number(record.required) === Number(requiredText), "Compact recovery code threshold mismatch.");
  assert(Number(record.total) === Number(totalText), "Compact recovery code total mismatch.");
  return record;
}

function parseLoosePayload(input: string): {
  record: ShardRecord;
  declaredFingerprint?: string;
} {
  const trimmed = input.trim();

  if (trimmed.startsWith(LEGACY_QR_PREFIX)) {
    return {
      record: parseShardRecord(JSON.parse(trimmed.slice(LEGACY_QR_PREFIX.length)))
    };
  }

  if (trimmed.startsWith("{")) {
    return { record: parseShardRecord(JSON.parse(trimmed)) };
  }

  if (trimmed.startsWith(VERSION.toUpperCase())) {
    const lines = parseLineShard(trimmed);
    return {
      record: parseShardRecord({
        version: VERSION,
        ceremonyId: lines.ceremonyId,
        index: Number(lines.index),
        total: Number(lines.total),
        required: Number(lines.required),
        holderLabel: lines.holderLabel ?? "",
        secretLength: Number(lines.secretLength),
        compression: lines.compression === "gzip" ? "gzip" : "none",
        iv: lines.iv,
        ciphertext: lines.ciphertext,
        share: lines.share
      }),
      declaredFingerprint: lines.fingerprint
    };
  }

  throw new Error("Malformed shard payload.");
}

export function detectLegacyOrInvalidInput(input: string): ShardInputKind {
  const trimmed = input.trim();

  if (trimmed.length === 0) {
    return "invalid";
  }

  if (trimmed.startsWith(LEGACY_QR_PREFIX)) {
    return "legacy-qr";
  }

  if (trimmed.startsWith(VERSION.toUpperCase())) {
    return "legacy-shards-1";
  }

  if (trimmed.startsWith("{")) {
    return "legacy-json";
  }

  if (
    /^[A-Z]+-[0-9]+of[0-9]+/u.test(trimmed.replace(/\s+/gu, "")) ||
    trimmed.includes("|")
  ) {
    return "compact-recovery-code";
  }

  if (/^[A-Za-z0-9\-_]{20,}$/u.test(trimmed)) {
    try {
      if (fromBase64Url(trimmed).length === AES_KEY_LENGTH) {
        return "legacy-share-only";
      }
    } catch {
      return "invalid";
    }
  }

  return "invalid";
}

export async function splitSecret(input: SplitSecretInput): Promise<SplitSecretResult> {
  validateSplitInput(input);
  const secretBytes = new TextEncoder().encode(input.secret);
  const compressedSecret = await compressBytes(secretBytes);
  const rawKey = randomBytes(AES_KEY_LENGTH);
  const iv = randomBytes(AES_GCM_IV_LENGTH);
  const ciphertext = await encryptSecret(compressedSecret, rawKey, iv);
  const ceremonyId = input.ceremonyId ?? generateCeremonyId();
  const shares = splitKey(rawKey, input.total, input.required);
  const shards = await Promise.all(
    shares.map((shareBytes, index) =>
      buildParsedShard({
        version: VERSION,
        ceremonyId,
        index: index + 1,
        total: input.total,
        required: input.required,
        holderLabel: normalizeHolderLabel(input.holderLabels?.[index], index + 1),
        secretLength: input.secret.length,
        compression: "gzip",
        iv: toBase64Url(iv),
        ciphertext: toBase64Url(ciphertext),
        share: toBase64Url(shareBytes)
      })
    )
  );

  return {
    ceremonyId,
    total: input.total,
    required: input.required,
    secretLength: input.secret.length,
    shards
  };
}

export async function parseShard(input: string): Promise<ParsedShard> {
  const kind = detectLegacyOrInvalidInput(input);

  if (kind === "compact-recovery-code") {
    const record = await parseCompactOrThrow(input);
    assert(record, "Malformed compact recovery code.");
    return buildParsedShard(record);
  }

  if (kind === "legacy-share-only") {
    throw new Error(
      "This looks like a share fragment only. Enter a full compact recovery code or a legacy SHARDS-1 block."
    );
  }

  const { record, declaredFingerprint } = parseLoosePayload(input);
  const shard = await buildParsedShard(record);

  if (declaredFingerprint) {
    const legacyFingerprint = formatFingerprintBytes(
      await sha256Bytes(new TextEncoder().encode(canonicalPayload(record)))
    );
    assert(
      declaredFingerprint === shard.fingerprint || declaredFingerprint === legacyFingerprint,
      "Shard fingerprint mismatch."
    );
  }

  return shard;
}

export async function validateShard(input: string): Promise<ValidationResult> {
  try {
    const shard = await parseShard(input);
    return { valid: true, shard };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : "Malformed shard."
    };
  }
}

export async function fingerprintShard(input: string | ShardRecord | ParsedShard): Promise<string> {
  if (typeof input === "string") {
    return (await parseShard(input)).fingerprint;
  }

  if ("fingerprint" in input) {
    return input.fingerprint;
  }

  return (await buildParsedShard(input)).fingerprint;
}

export async function formatCompactRecoveryShard(
  input: ParsedShard | ShardRecord
): Promise<string> {
  const record: ShardRecord = {
    version: VERSION,
    ceremonyId: input.ceremonyId,
    index: input.index,
    total: input.total,
    required: input.required,
    holderLabel: input.holderLabel,
    secretLength: input.secretLength,
    compression: input.compression ?? "none",
    iv: input.iv,
    ciphertext: input.ciphertext,
    share: input.share
  };
  return (await buildCompactRecoveryCodeParts(record)).fullCode;
}

export async function compactRecoveryCodeParts(
  input: ParsedShard | ShardRecord
): Promise<CompactRecoveryCodeParts> {
  const record: ShardRecord = {
    version: VERSION,
    ceremonyId: input.ceremonyId,
    index: input.index,
    total: input.total,
    required: input.required,
    holderLabel: input.holderLabel,
    secretLength: input.secretLength,
    compression: input.compression ?? "none",
    iv: input.iv,
    ciphertext: input.ciphertext,
    share: input.share
  };
  return buildCompactRecoveryCodeParts(record);
}

export function buildQrPayload(input: ShardRecord | ParsedShard): string {
  if ("qrPayload" in input) {
    return input.qrPayload;
  }

  if ("compactCode" in input && typeof input.compactCode === "string") {
    return input.compactCode;
  }

  throw new Error("QR payload requires a parsed shard with a computed compact recovery code.");
}

export async function parseQrPayload(input: string): Promise<ParsedShard> {
  if (input.startsWith(LEGACY_QR_PREFIX)) {
    return parseShard(input);
  }

  return parseShard(input);
}

export async function formatShard(input: ParsedShard | ShardRecord): Promise<string> {
  const record: ShardRecord = {
    version: VERSION,
    ceremonyId: input.ceremonyId,
    index: input.index,
    total: input.total,
    required: input.required,
    holderLabel: input.holderLabel,
    secretLength: input.secretLength,
    compression: input.compression ?? "none",
    iv: input.iv,
    ciphertext: input.ciphertext,
    share: input.share
  };
  const fingerprint =
    "fingerprint" in input ? input.fingerprint : await fingerprintShard(record);

  return [
    VERSION.toUpperCase(),
    `ceremonyId: ${record.ceremonyId}`,
    `index: ${record.index}`,
    `total: ${record.total}`,
    `required: ${record.required}`,
    `holderLabel: ${record.holderLabel}`,
    `secretLength: ${record.secretLength}`,
    `compression: ${record.compression}`,
    `iv: ${record.iv}`,
    `ciphertext: ${record.ciphertext}`,
    `share: ${record.share}`,
    ...(fingerprint ? [`fingerprint: ${fingerprint}`] : [])
  ].join("\n");
}

export async function recoverSecret(inputs: string[]): Promise<RecoverSecretResult> {
  assert(inputs.length > 0, "At least one shard is required.");
  const parsed = await Promise.all(inputs.map((input) => parseShard(input)));
  const uniqueByFingerprint = new Map<string, ParsedShard>();

  for (const shard of parsed) {
    assert(!uniqueByFingerprint.has(shard.fingerprint), "Duplicate shard detected.");
    uniqueByFingerprint.set(shard.fingerprint, shard);
  }

  const shards = [...uniqueByFingerprint.values()];
  const first = shards[0];
  assert(first, "At least one valid shard is required.");

  for (const shard of shards) {
    assert(
      shard.ceremonyId === first.ceremonyId &&
        shard.total === first.total &&
        shard.required === first.required &&
        shard.iv === first.iv &&
        shard.ciphertext === first.ciphertext &&
        shard.secretLength === first.secretLength &&
        shard.compression === first.compression,
      "These shards belong to different groups."
    );
  }

  const uniqueIndices = new Set<number>();

  for (const shard of shards) {
    assert(!uniqueIndices.has(shard.index), "Duplicate shard index detected.");
    uniqueIndices.add(shard.index);
  }

  assert(
    shards.length >= first.required,
    `At least ${first.required} valid shards are required to recover this secret.`
  );

  const key = recoverKey(
    shards.map((shard) => ({
      index: shard.index,
      bytes: fromBase64Url(shard.share)
    }))
  );
  const decryptedBytes = await decryptSecret(
    fromBase64Url(first.ciphertext),
    key,
    fromBase64Url(first.iv)
  );
  const plainBytes =
    first.compression === "gzip" ? await decompressBytes(decryptedBytes) : decryptedBytes;
  const secret = new TextDecoder().decode(plainBytes);
  assert(secret.length === first.secretLength, "Recovered secret length mismatch.");

  return {
    ceremonyId: first.ceremonyId,
    total: first.total,
    required: first.required,
    secret,
    usedShards: shards
  };
}

export function shardWords(input: ParsedShard | ShardRecord): string[] {
  if ("compactCheckCode" in input) {
    return [
      input.compactVisualLabel,
      ...chunkString(input.compactBody, 4),
      input.compactCheckCode
    ];
  }

  throw new Error("Use compactRecoveryCodeParts() for unparsed shard records.");
}

export function estimateCompactRecoveryCodeLength(
  secretLength: number,
  required: number,
  total: number
): CompactLengthEstimate {
  assert(Number.isInteger(secretLength) && secretLength > 0, "Secret length must be a positive integer.");
  assert(Number.isInteger(required) && required >= 2, "Threshold M must be at least 2.");
  assert(Number.isInteger(total) && total >= required, "Threshold N must be at least M.");

  const gzipUpperBound = secretLength + 23;
  const ciphertextUpperBound = gzipUpperBound + 16;
  const payloadBytesUpperBound = 61 + ciphertextUpperBound;
  const bodyCharactersUpperBound = Math.ceil((payloadBytesUpperBound * 8) / Math.log2(58));
  const groupedBodyCharactersUpperBound =
    bodyCharactersUpperBound + Math.max(Math.ceil(bodyCharactersUpperBound / 4) - 1, 0);
  const header = `${headerToken(total, required, total)}`;
  const totalCharactersUpperBound =
    header.length + 3 + groupedBodyCharactersUpperBound + 3 + 4;

  return {
    payloadBytesUpperBound,
    bodyCharactersUpperBound,
    groupedBodyCharactersUpperBound,
    checkCharacters: 4,
    totalCharactersUpperBound
  };
}

export const CRYPTO_PACKAGE_STATUS = "active";
