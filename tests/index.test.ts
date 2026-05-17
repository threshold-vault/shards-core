import { describe, expect, test } from "vitest";
import {
  buildQrPayload,
  compactRecoveryCodeParts,
  detectLegacyOrInvalidInput,
  estimateCompactRecoveryCodeLength,
  fingerprintShard,
  formatCompactRecoveryShard,
  formatShard,
  parseQrPayload,
  parseShard,
  recoverSecret,
  SPLIT_SECRET_CHARACTER_LIMIT,
  shardWords,
  splitSecret,
  validateShard
} from "./index.js";

const SECRET = "correct horse battery staple 🧩";

function expectDefined<T>(value: T | undefined): T {
  expect(value).toBeDefined();
  return value as T;
}

function combinations<T>(values: T[], size: number): T[][] {
  if (size === 0) {
    return [[]];
  }

  if (values.length < size) {
    return [];
  }

  const first = values[0];
  const rest = values.slice(1);

  if (first === undefined) {
    return [];
  }

  return [
    ...combinations(rest, size - 1).map((subset) => [first, ...subset]),
    ...combinations(rest, size)
  ];
}

describe("shards crypto", () => {
  test("roundtrips a split and recovery flow", async () => {
    const result = await splitSecret({
      secret: SECRET,
      required: 3,
      total: 5,
      holderLabels: ["Spouse", "Adult child", "Lawyer", "Safe", "Executor"]
    });
    const formatted = await Promise.all(
      result.shards.slice(0, 3).map((shard) => formatShard(shard))
    );
    const recovered = await recoverSecret(formatted);

    expect(recovered.secret).toBe(SECRET);
    expect(recovered.required).toBe(3);
    expect(recovered.total).toBe(5);
  });

  test("supports all threshold combinations for 2-of-3, 3-of-5, and 5-of-7", async () => {
    const configs = [
      { required: 2, total: 3 },
      { required: 3, total: 5 },
      { required: 5, total: 7 }
    ];

    for (const config of configs) {
      const result = await splitSecret({
        secret: `combo:${config.required}/${config.total}`,
        required: config.required,
        total: config.total
      });
      const everyCombination = combinations(result.shards, config.required);

      for (const combo of everyCombination) {
        const formatted = await Promise.all(combo.map((shard) => formatShard(shard)));
        const recovered = await recoverSecret(formatted);
        expect(recovered.secret).toBe(`combo:${config.required}/${config.total}`);
      }
    }
  });

  test("fails recovery with M-1 shards", async () => {
    const result = await splitSecret({
      secret: SECRET,
      required: 3,
      total: 5
    });
    const formatted = await Promise.all(
      result.shards.slice(0, 2).map((shard) => formatShard(shard))
    );

    await expect(recoverSecret(formatted)).rejects.toThrow(
      "At least 3 valid shards are required to recover this secret."
    );
  });

  test("rejects duplicate shards", async () => {
    const result = await splitSecret({
      secret: SECRET,
      required: 2,
      total: 3
    });
    const formatted = await formatShard(expectDefined(result.shards[0]));

    await expect(recoverSecret([formatted, formatted])).rejects.toThrow("Duplicate shard detected.");
  });

  test("rejects wrong-set shards", async () => {
    const first = await splitSecret({
      secret: SECRET,
      required: 2,
      total: 3
    });
    const second = await splitSecret({
      secret: "another secret",
      required: 2,
      total: 3
    });
    const inputs = await Promise.all([
      formatShard(expectDefined(first.shards[0])),
      formatShard(expectDefined(second.shards[1]))
    ]);

    await expect(recoverSecret(inputs)).rejects.toThrow(
      "These shards belong to different groups."
    );
  });

  test("rejects malformed shard input", async () => {
    const validation = await validateShard("not a shard");

    expect(validation.valid).toBe(false);
    expect(validation).toMatchObject({
      error: expect.any(String)
    });
  });

  test("keeps fingerprint stable across parse and format", async () => {
    const result = await splitSecret({
      secret: SECRET,
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const formatted = await formatShard(firstShard);
    const parsed = await parseShard(formatted);
    const fingerprint = await fingerprintShard(parsed);

    expect(fingerprint).toBe(firstShard.fingerprint);
    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
  });

  test("roundtrips QR payload parsing", async () => {
    const result = await splitSecret({
      secret: SECRET,
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const payload = buildQrPayload(firstShard);
    const parsed = await parseQrPayload(payload);

    expect(payload).toBe(await formatCompactRecoveryShard(firstShard));
    expect(parsed.ceremonyId).toBe(firstShard.ceremonyId);
    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
    expect(payload).not.toContain(SECRET);
  });

  test("recovers with one QR-derived shard plus one compact-code shard", async () => {
    const result = await splitSecret({
      secret: "qr equivalence threshold test",
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const secondShard = expectDefined(result.shards[1]);
    const qrParsed = await parseQrPayload(buildQrPayload(firstShard));
    const recovered = await recoverSecret([
      await formatCompactRecoveryShard(qrParsed),
      await formatCompactRecoveryShard(secondShard)
    ]);

    expect(recovered.secret).toBe("qr equivalence threshold test");
  });

  test("formats human-readable shard words from the encoded share", async () => {
    const result = await splitSecret({
      secret: SECRET,
      required: 2,
      total: 3
    });

    expect(shardWords(expectDefined(result.shards[0])).length).toBeGreaterThan(1);
  });

  test("roundtrips a compact recovery code", async () => {
    const result = await splitSecret({
      secret: "alpha bravo compact code",
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const compact = await formatCompactRecoveryShard(firstShard);
    const parsed = await parseShard(compact);

    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
    expect(parsed.compactCode).toBe(compact);
    expect(compact).not.toContain("|");
  });

  test("supports any-pair recovery for compact 2-of-3 shards", async () => {
    const result = await splitSecret({
      secret: "abandon ability able about above absent absorb abstract absurd abuse access accident",
      required: 2,
      total: 3
    });
    const everyCombination = combinations(result.shards, 2);

    for (const combo of everyCombination) {
      const compactInputs = await Promise.all(
        combo.map((shard) => formatCompactRecoveryShard(shard))
      );
      const recovered = await recoverSecret(compactInputs);
      expect(recovered.secret).toBe(
        "abandon ability able about above absent absorb abstract absurd abuse access accident"
      );
    }
  });

  test("rejects malformed compact recovery check codes", async () => {
    const result = await splitSecret({
      secret: "check-code test secret",
      required: 2,
      total: 3
    });
    const compact = await formatCompactRecoveryShard(expectDefined(result.shards[0]));
    const tampered = compact.replace(/.{4}$/u, "1111");
    const validation = await validateShard(tampered);

    expect(validation.valid).toBe(false);
    expect(validation).toMatchObject({
      error: "Check code does not match. Re-check this recovery code."
    });
  });

  test("accepts space-separated compact recovery codes", async () => {
    const result = await splitSecret({
      secret: "space separated compact code",
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const compact = await formatCompactRecoveryShard(firstShard);
    const parsed = await parseShard(compact);

    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
  });

  test("accepts legacy pipe-separated compact recovery codes", async () => {
    const result = await splitSecret({
      secret: "legacy pipe compact code",
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const compact = await formatCompactRecoveryShard(firstShard);
    const piped = compact.replace(/^(\S+)\s+(\S+)\s+(\S+)$/u, "$1 | $2 | $3");
    const parsed = await parseShard(piped);

    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
  });

  test("accepts hyphen-separated compact recovery codes without pipes", async () => {
    const result = await splitSecret({
      secret: "hyphen separated compact code",
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const compact = await formatCompactRecoveryShard(firstShard);
    const hyphenated = compact.replace(/\s+/gu, "-");
    const parsed = await parseShard(hyphenated);

    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
  });

  test("accepts compact recovery codes with extra spaces and line breaks", async () => {
    const result = await splitSecret({
      secret: "whitespace-tolerant compact code",
      required: 2,
      total: 3
    });
    const firstShard = expectDefined(result.shards[0]);
    const compact = await formatCompactRecoveryShard(firstShard);
    const spaced = compact.replace(
      /^(\S+)\s+(\S+)\s+(\S+)$/u,
      (_, header: string, body: string, checkCode: string) =>
        `${header}\n${body.replaceAll("-", "- ")}\n${checkCode}`
    );
    const parsed = await parseShard(spaced);

    expect(parsed.fingerprint).toBe(firstShard.fingerprint);
  });

  test("rejects share-only legacy fragments with a helpful error", async () => {
    const result = await splitSecret({
      secret: "legacy share only test",
      required: 2,
      total: 3
    });
    const shareOnly = expectDefined(result.shards[0]).share;
    const validation = await validateShard(shareOnly);

    expect(detectLegacyOrInvalidInput(shareOnly)).toBe("legacy-share-only");
    expect(validation.valid).toBe(false);
    expect(validation).toMatchObject({
      error: expect.stringContaining("full compact recovery code")
    });
  });

  test("documents compact recovery code component sizes", async () => {
    const result = await splitSecret({
      secret: "hello world",
      required: 2,
      total: 3
    });
    const parts = await compactRecoveryCodeParts(expectDefined(result.shards[0]));
    const estimate = estimateCompactRecoveryCodeLength(11, 2, 3);

    expect(parts.header).toBe("A-2of3");
    expect(parts.checkCode.length).toBe(4);
    expect(parts.bodyGroups.length).toBeGreaterThan(10);
    expect(estimate.totalCharactersUpperBound).toBeGreaterThan(parts.fullCode.length);
  });

  test("documents compact recovery code estimates for a seed phrase and short note", async () => {
    const seed = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const note = "This is a short note used to estimate compact recovery code size for printed shard cards.";
    const seedResult = await splitSecret({
      secret: seed,
      required: 2,
      total: 3
    });
    const noteResult = await splitSecret({
      secret: note,
      required: 2,
      total: 3
    });
    const seedCode = await formatCompactRecoveryShard(expectDefined(seedResult.shards[0]));
    const noteCode = await formatCompactRecoveryShard(expectDefined(noteResult.shards[0]));
    const seedEstimate = estimateCompactRecoveryCodeLength(seed.length, 2, 3);
    const noteEstimate = estimateCompactRecoveryCodeLength(note.length, 2, 3);

    expect(seedCode.length).toBeGreaterThan(240);
    expect(seedCode.length).toBeLessThan(320);
    expect(noteCode.length).toBeGreaterThan(280);
    expect(noteCode.length).toBeLessThan(420);
    expect(seedEstimate.totalCharactersUpperBound).toBeGreaterThanOrEqual(seedCode.length);
    expect(noteEstimate.totalCharactersUpperBound).toBeGreaterThanOrEqual(noteCode.length);
  });

  test("keeps 24-word seeds inside the current plaintext split limit", () => {
    const twentyFourWordSeed =
      "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual";
    const estimate = estimateCompactRecoveryCodeLength(twentyFourWordSeed.length, 3, 5);

    expect(twentyFourWordSeed.length).toBeLessThanOrEqual(SPLIT_SECRET_CHARACTER_LIMIT);
    expect(estimate.totalCharactersUpperBound).toBeLessThan(500);
  });

  test("rejects secrets beyond the current plaintext split limit", async () => {
    const tooLong = "x".repeat(SPLIT_SECRET_CHARACTER_LIMIT + 1);

    await expect(
      splitSecret({
        secret: tooLong,
        required: 3,
        total: 5
      })
    ).rejects.toThrow(`Secret exceeds ${SPLIT_SECRET_CHARACTER_LIMIT} characters.`);
  });
});
