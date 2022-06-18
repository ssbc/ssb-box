// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros <contact@staltz.com>
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape');
const {check} = require('ssb-encryption-format');
const ssbKeys = require('ssb-keys');

const format = require('../format');

test('passes ssb-encryption-format', (t) => {
  check(format, (err) => {
    t.error(err, 'no error');
    t.end();
  });
});

test('supports bendybutt-v1 recipient', (t) => {
  const keys = ssbKeys.generate(null, null, 'bendybutt-v1');
  const plaintext = Buffer.from('hello world');
  const ciphertext = format.encrypt(plaintext, {recps: [keys.id], keys});
  const decrypted = format.decrypt(ciphertext, {keys});
  t.same(decrypted, plaintext);
  t.end();
});

test('supports buttwoo-v1 recipient', (t) => {
  const keys = ssbKeys.generate(null, null, 'buttwoo-v1');
  const plaintext = Buffer.from('hello world');
  const ciphertext = format.encrypt(plaintext, {recps: [keys.id], keys});
  const decrypted = format.decrypt(ciphertext, {keys});
  t.same(decrypted, plaintext);
  t.end();
});

test('rejects unknown recipients', (t) => {
  const keys = ssbKeys.generate();
  const plaintext = Buffer.from('hello world');
  try {
    format.encrypt(plaintext, {recps: [keys.id, 'foo'], keys});
    t.fail('should have thrown');
  } catch (err) {
    t.ok(err, 'threw error');
    t.match(err.message, /does not support recipient "foo"/);
    t.end();
  }
});
