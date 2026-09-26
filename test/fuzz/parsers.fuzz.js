/* eslint-disable no-console */
// Mutation fuzzer for everything nspv-js parses from untrusted peers:
// transactions, blocks, P2P messages and nSPV responses.
//
// A parser passes if, for every input, it returns or throws an Error within
// SLOW_MS and heap usage stays bounded. Anything else is reported.
//
//   node test/fuzz/parsers.fuzz.js [iterations] [seed]

const crypto = require('crypto')
const Transaction = require('../../src/transaction')
const Block = require('../../src/block')
const networks = require('../../src/networks')
const { kmdMessages } = require('../../net/kmdmessages')
const kmdtypes = require('../../net/kmdtypes')
const txFixtures = require('../fixtures/transaction.json')
const blockFixtures = require('../fixtures/block.json')

const ITER = Number(process.argv[2] || 20000)
let seed = Number(process.argv[3] || Date.now() % 1e9)
const SLOW_MS = 250
const HEAP_LIMIT = 1024 * 1024 * 1024

const rand = () => {
  // mulberry32 so failures are reproducible from the printed seed
  seed |= 0; seed = seed + 0x6D2B79F5 | 0
  let t = Math.imul(seed ^ seed >>> 15, 1 | seed)
  t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t
  return ((t ^ t >>> 14) >>> 0) / 4294967296
}
const rint = n => Math.floor(rand() * n)

const txSeeds = txFixtures.valid.map(f => Buffer.from(f.hex, 'hex'))
const blockSeeds = blockFixtures.valid.map(f => Buffer.from(f.hex, 'hex'))
const interesting = [0x00, 0xff, 0xfd, 0xfe, 0x7f, 0x80]

function mutate (buf) {
  const b = Buffer.from(buf)
  const ops = 1 + rint(8)
  let out = b
  for (let i = 0; i < ops; i++) {
    const choice = rint(7)
    if (out.length === 0) out = Buffer.from([rint(256)])
    const pos = rint(out.length)
    if (choice === 0) out[pos] ^= 1 << rint(8)
    else if (choice === 1) out[pos] = interesting[rint(interesting.length)]
    else if (choice === 2) out = out.slice(0, pos) // truncate
    else if (choice === 3) out = Buffer.concat([out.slice(0, pos), crypto.randomBytes(rint(16)), out.slice(pos)])
    else if (choice === 4) {
      // huge varint length prefix: 0xff + 8 bytes
      const v = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])
      out = Buffer.concat([out.slice(0, pos), v, out.slice(pos + 1)])
    } else if (choice === 5) out = Buffer.concat([out, out.slice(0, rint(out.length))])
    else out = crypto.randomBytes(rint(512))
  }
  return out
}

const targets = [
  ['Transaction.fromBuffer(TOKEL)', () => mutate(txSeeds[rint(txSeeds.length)]), b => Transaction.fromBuffer(b, networks.TOKEL)],
  ['Transaction.fromBuffer(bitcoin)', () => mutate(txSeeds[rint(txSeeds.length)]), b => Transaction.fromBuffer(b)],
  ['Block.fromBuffer(TOKEL)', () => mutate(blockSeeds[rint(blockSeeds.length)]), b => Block.fromBuffer(b, networks.TOKEL)],
  ['kmdtypes.nspvResp.decode', () => mutate(crypto.randomBytes(8 + rint(400))), b => kmdtypes.nspvResp.decode(b)],
  ['kmdtypes.kmdheader.decode', () => mutate(crypto.randomBytes(140 + rint(1400))), b => kmdtypes.kmdheader.decode(b)],
  ['kmdtypes.txProof.decode', () => mutate(crypto.randomBytes(rint(600))), b => kmdtypes.txProof.decode(b)]
]
for (const name of Object.keys(kmdMessages)) {
  const codec = kmdMessages[name]
  if (codec && typeof codec.decode === 'function') {
    targets.push([`kmdMessages.${name}.decode`, () => mutate(crypto.randomBytes(rint(600))), b => codec.decode(b)])
  }
}

const findings = new Map()
const report = (target, kind, input, detail) => {
  const key = `${target} ${kind} ${detail}`.slice(0, 160)
  if (!findings.has(key)) findings.set(key, { target, kind, detail, input: input.toString('hex').slice(0, 400), len: input.length })
}

const startSeed = seed
const t0 = Date.now()
const stats = {}
for (let i = 0; i < ITER; i++) {
  const [name, gen, fn] = targets[i % targets.length]
  const input = gen()
  const s = process.hrtime.bigint()
  try {
    fn(input)
    stats[name] = stats[name] || { ok: 0, err: 0 }; stats[name].ok++
  } catch (e) {
    stats[name] = stats[name] || { ok: 0, err: 0 }; stats[name].err++
    if (!(e instanceof Error)) report(name, 'NON_ERROR_THROW', input, String(e))
    else if (e instanceof RangeError && /Array buffer allocation|Invalid array length|Maximum call stack/.test(e.message)) report(name, 'RESOURCE', input, e.message)
  }
  const ms = Number(process.hrtime.bigint() - s) / 1e6
  if (ms > SLOW_MS) report(name, 'SLOW', input, `${ms.toFixed(0)}ms`)
  if (i % 500 === 0 && process.memoryUsage().heapUsed > HEAP_LIMIT) {
    report(name, 'HEAP', input, `${(process.memoryUsage().heapUsed / 1e6).toFixed(0)}MB`)
    break
  }
}

console.log(`seed ${startSeed}, ${ITER} inputs across ${targets.length} parsers in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
for (const [n, s] of Object.entries(stats)) console.log(`  ${n.padEnd(40)} parsed ${String(s.ok).padStart(6)}  rejected ${String(s.err).padStart(6)}`)
if (findings.size === 0) {
  console.log('FINDINGS: none')
} else {
  console.log(`FINDINGS: ${findings.size}`)
  for (const f of findings.values()) console.log(`  [${f.kind}] ${f.target}: ${f.detail}\n      len=${f.len} input=${f.input}`)
  process.exitCode = 1
}
