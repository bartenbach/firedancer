# [Firedancer](https://jumpcrypto.com/firedancer/) 🔥💃

Firedancer is a new validator client for Solana.

* **Fast** Designed from the ground up to be *fast*. The concurrency
model draws from experience in the low latency trading space, and the code
contains many novel high-performance reimplementations of core Solana
primitives.
* **Secure** The architecture of the validator allows it to run with a
highly restrictive sandbox and almost no system calls.
* **Independent** Firedancer is written from scratch. This brings client
diversity to the Solana network and helps it stay resilient to supply
chain attacks in build tooling or dependencies.

## Agave RPC compatibility patch (this branch)

This branch is `firedancer-geo-aware-lsched` plus a few commits that add
Agave JSON-RPC methods the Firedancer RPC tile answered with HTTP 501.
It is an operator patch, not an official Firedancer release, and it has
not been reviewed by the Firedancer team.

### Added by this patch

| Method | Answered from | Limits |
|---|---|---|
| `getBlocks`, `getBlocksWithLimit` | SlotHistory sysvar | Covers the last ~1M slots. |
| `getBlockCommitment` | constant | Always `commitment: null, totalStake: 0`, which is what Agave returns under Alpenglow. |
| `getFirstAvailableBlock`, `minimumLedgerSlot` | block time table | Oldest slot replayed since this node started. Firedancer keeps no block store. |
| `getMaxShredInsertSlot` | retransmit high-water mark | A lower bound: the highest slot retransmitted. |
| `isBlockhashValid` | RecentBlockhashes sysvar | |
| `getInflationRate` | bank inflation parameters | Assumes inflation started at slot 0. Wrong on a cluster that enabled inflation later (mainnet). |
| `getFeeForMessage` | the message itself | A message that sets a compute unit price without a compute unit limit is refused with an error. |
| `getRecentPrioritizationFees` | per-slot fee totals | Lists only blocks whose priority fees were zero. A block that paid priority fees is left out, because its minimum fee is not known to the tile. The account list argument is validated and otherwise ignored. |
| `getProgramAccounts` | full account scan | `memcmp` and `dataSize` filters (max 4), `dataSlice`, `withContext`. No `jsonParsed` except vote accounts. |
| `getLargestAccounts` | full account scan | The `filter` argument is ignored. |
| `getSupply` | full account scan | Everything is reported as circulating; the non-circulating list is empty. |
| `getTokenAccountBalance`, `getTokenSupply` | account read | |
| `getTokenAccountsByOwner`, `getTokenAccountsByDelegate`, `getTokenLargestAccounts` | full account scan | No `jsonParsed`. |
| `getSignatureStatuses` | recent transaction window | Only transactions replayed since this node started that are still in the window (the last 524,288). A failed transaction is reported as failed, but when an instruction failed the error is `{"InstructionError":[null,null]}`: which instruction and why is not known to the tile. `confirmations` is the number of slots since the transaction's slot, not Agave's count. `searchTransactionHistory` is ignored. |
| `getBlock` | recent transaction window | **Signatures only.** `transactionDetails` must be `"signatures"` or `"none"` and `rewards` must be `false`; the default call (full detail, with rewards) returns an error. Only blocks replayed since this node started, and only while every transaction of the block is still in the window; otherwise "Block not available". |
| `sendTransaction` | UDP to upcoming leaders | The transaction is parsed, its signatures verified and, unless `skipPreflight`, its blockhash checked. It is then sent as a UDP datagram to the TPU port of the leaders of the next 4 rotations and resent every rotation until it is seen in a block or 150 slots pass. **There is no simulation**: a transaction that would fail on chain is still sent. A leader that advertises no TPU UDP port (Agave takes QUIC only) is skipped, and so is this node itself when it is the leader. `maxRetries`, `preflightCommitment` and `minContextSlot` are ignored. At most 256 transactions are kept for resending. |
| `jsonParsed` encoding | vote accounts only (v4 vote state) | Accounts Agave does not parse fall back to base64, as in Agave. Accounts Agave does parse (stake, token, sysvar, config, nonce, BPF loader, lookup table) return an error instead of unparsed data. |

### Already in the base branch (not part of this patch)

`getVoteAccounts`, `getBlockProduction`, `getBlockTime`,
`getEpochSchedule`, `getRecentPerformanceSamples`.

On the test cluster, `getVoteAccounts` from the base branch listed the
vote accounts in the epoch's voting set only (60 of the 65 Agave
listed) and the stake the leader schedule was built from rather than
current stake. This patch does not change that.

### Still not implemented

| Method | Why |
|---|---|
| `getTransaction` | The tile is told a transaction's result code, fee and compute units, but not balance changes, logs or inner instructions. |
| `getSignaturesForAddress` | The window is not indexed by address, and addresses loaded through lookup tables are not resolved. |
| `getInflationReward` | No per-epoch reward history. |
| `getStakeMinimumDelegation` | The answer comes from executing the on-chain stake program. |
| `getHighestSnapshotSlot` | The tile is not told which snapshots are on disk. |
| `simulateTransaction` | Needs a transaction executor in the RPC tile. |
| `requestAirdrop` | Needs a faucet. |

### Things to know before running it

- **Account scans block the RPC tile.** There is no index of accounts
  by owner, so `getProgramAccounts`, `getLargestAccounts`, `getSupply`
  and the token scans walk every account. On a database of about 2.8
  million accounts one call took 3 to 9 seconds, during which the tile
  answers nothing else and does not drain its input from replay. Do not
  expose these to untrusted callers. Behaviour under sustained scan
  load, or on a mainnet-sized database, has not been tested.
- **The patch touches the tile wiring.** For `getSignatureStatuses`
  and `getBlock` the RPC tile becomes a reader of the `replay_out`
  link (one line in `topology.c`). It reads it unreliably, so it cannot
  backpressure replay, and it discards a transaction it was too slow to
  read; such a transaction is then missing from the window. The window
  adds about 65 MB to the RPC tile.
- **A scan is not a point-in-time view.** Accounts written while a scan
  runs may or may not be included.
- **How it was checked.** Each call was issued to an Agave 4.5.0-beta.0
  node and to a Firedancer node running this patch on the Alpenglow
  community cluster, and the answers compared. That is one small
  cluster with Alpenglow active. Nothing here has been run on mainnet
  or testnet, with pre-v4 vote accounts, or with Token-2022 accounts.
- `sendTransaction` was checked for decoding, signature verification
  and its error paths by resubmitting a transaction that had already
  landed. **It has not been seen landing a new transaction.**
- `getSignatureStatuses` matched Agave for successful transactions.
  The cluster produced no failed transactions during the check, so the
  failed-transaction path has not been seen working.
- Agave on the test cluster does not serve `getBlock`, so `getBlock`
  was checked for internal consistency only (blockhash chain, height,
  time, and each signature's slot via `getSignatureStatuses`).
- The base branch's RPC unit test passes with the patch applied. The
  patch adds no unit tests of its own.

## Documentation
If you are an operator or looking to run the validator, see the Getting
Started guide in the [Firedancer
docs](https://docs.firedancer.io/)

## Releases
If you are an operator looking to run the validator, see the [Releases
Guide](https://docs.firedancer.io/guide/getting-started.html#releases)
in the documentation.

## Developing
Firedancer currently only supports Linux and requires a relatively new
kernel, at least v4.18 to build.

```console
$ git clone https://github.com/firedancer-io/firedancer.git
$ cd firedancer
$ ./deps.sh                        # install system dependencies
$ make -j                          # build `firedancer-dev`
$ ./build/firedancer-dev --testnet # join testnet
```

`firedancer-dev` (without args) configures your system for validator
operation and creates a new local development cluster. First it creates
a genesis block, some keys, a faucet, and then it starts a validator on
the local machine. `firedancer-dev` will use `sudo` to make privileged
changes to system configuration where needed. If `sudo` is not available,
you may need to run the command as root.

If you wish to join this cluster with other validators, you can define
`[gossip.entrypoints]` in the configuration file to point at your first
validator and join with `firedancer-dev run`.

## License
Firedancer is available under the [Apache 2
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See [LICENSE](LICENSE) for the full license text.
