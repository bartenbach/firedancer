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
| `getSignatureStatuses` | recent transaction window | See "The recent transaction window" below. A failed transaction carries the failed instruction and its error, as Agave prints it. Without `searchTransactionHistory` only the last 300 slots are searched, as in Agave; with it, the whole window. |
| `getTransaction` | recent transaction window, plus what the exec tiles report | Encodings `json`, `base64`, `base58`. **No `jsonParsed`.** `meta` has the result, fee, `computeUnitsConsumed`, `costUnits`, lamport balances before and after, loaded addresses, `logMessages`, `innerInstructions` and `returnData`. **Token balances are not reported**: `preTokenBalances` and `postTokenBalances` are `[]` when no token program or token-owned account is involved and `null` otherwise. Logs and inner instructions are `null` for a transaction whose report the tile missed or no longer keeps (see "Logs and inner instructions" below). |
| `getBlock` | recent transaction window | `transactionDetails` `full`, `signatures` or `none` (**not `accounts`**). Transactions as for `getTransaction`. **Block rewards are not reported**: `rewards` is `[]` for a block that collected no fees and paid no epoch rewards, `null` otherwise (Agave lists the fee reward and, at the start of an epoch, the vote and stake rewards). A block is served only while every one of its transactions is in the window; otherwise "Block not available". |
| `getSignaturesForAddress` | recent transaction window | Matches addresses written in the transaction itself. **A transaction that only reaches the address through a lookup table is not found.** `limit`, `before`, `until` are supported. Each call walks the whole window. |
| `getInflationReward` | rewards recorded as replay pays them | See "Epoch rewards" below. Up to 32 addresses, the previous epoch by default or `epoch`. Only the two most recent reward epochs, and only if the node was running when they were paid; otherwise "Block not available". `commission` and `blockRewardAmount` are always null. |
| `signatureSubscribe`, `signatureUnsubscribe` (websocket) | recent transaction window | One notification when the transaction reaches the requested commitment, then the subscription ends. A transaction that is already there is notified on the next slot. `enableReceivedNotification` is ignored. At most 256 pending subscriptions in total; the oldest is dropped beyond that. |
| `accountSubscribe`, `accountUnsubscribe` (websocket) | account read on every commitment change | The account is re-read each time the subscribed commitment level moves and a notification is sent if it changed. Encodings as `getAccountInfo`. At most 256 subscriptions in total. |
| `simulateTransaction` | a private runtime inside the RPC tile | See "The transaction simulator" below. `sigVerify`, `replaceRecentBlockhash`, `accounts` (base64 only), `encoding` base58/base64. Returns `err`, `logs`, `unitsConsumed`, `returnData`, `fee`, `loadedAccountsDataSize`, `loadedAddresses`, lamport and token balances before and after, the requested accounts, and `innerInstructions` when asked for. Inner instructions are given in compiled form (account indexes, base58 data); Agave gives them parsed for programs it knows. A transaction that already landed is simulated again rather than reported as `AlreadyProcessed`. |
| `getStakeMinimumDelegation` | the simulator | Simulates the stake program's `GetMinimumDelegation` instruction and returns what the program answers, as Agave does. |
| `getHighestSnapshotSlot` | the snapshot writer's messages | The newest full snapshot the node has on disk and the newest incremental built on it. Only on a node that writes snapshots (`[layout] enable_snapshot_production = true`, which the Firedancer defaults mark as unsupported); otherwise "No snapshot". With it on, the check node reported the same full snapshot slot as Agave and its incremental slot followed each new file. |
| `sendTransaction` | UDP to upcoming leaders | The transaction is parsed, its signatures verified and, unless `skipPreflight`, its blockhash checked. It is then sent as a UDP datagram to the TPU port of the leaders of the next 4 rotations and resent every rotation until it is seen in a block or 150 slots pass. **There is no simulation**: a transaction that would fail on chain is still sent. A leader that advertises no TPU UDP port (Agave takes QUIC only) is skipped, and so is this node itself when it is the leader. `maxRetries`, `preflightCommitment` and `minContextSlot` are ignored. At most 256 transactions are kept for resending. |
| `jsonParsed` encoding | account data | Parsed: vote accounts (v4 vote state), stake accounts, plain SPL token mints (82 bytes) and accounts (165 bytes) of either token program, nonce accounts, address lookup tables, upgradeable-loader program and programData accounts, validator info records, and the sysvars clock, epochSchedule, rent, lastRestartSlot, epochRewards, recentBlockhashes, slotHashes, slotHistory and stakeHistory. Accounts Agave does not parse fall back to base64, as in Agave. Not parsed, and returned as an error rather than as unparsed data: Token-2022 accounts with extensions, token multisigs, loader buffer accounts, uninitialized nonce accounts, pre-v4 vote states. `rentEpoch` is always printed as 18446744073709551615, where Agave prints 0 for accounts not rewritten since genesis. A sysvar is parsed only where its address is known to the encoder (`getAccountInfo`, `getMultipleAccounts`, `getProgramAccounts`). |

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
| `getTransaction`, `getBlock` with `jsonParsed` | Needs an instruction parser for every program Agave knows. |
| `getBlock` with `transactionDetails: "accounts"` | Not written. |
| Token balances and block rewards in transaction history | See the `getTransaction` and `getBlock` rows. |
| `logsSubscribe`, `programSubscribe`, `blockSubscribe`, `rootSubscribe` and the other websocket subscriptions | Not written. Only slot, vote, signature and account subscriptions exist. |
| `requestAirdrop` | Needs a faucet. |

### Things to know before running it

- **Account scans block the RPC tile.** There is no index of accounts
  by owner, so `getProgramAccounts`, `getLargestAccounts`, `getSupply`
  and the token scans walk every account. On a database of about 2.8
  million accounts one call took 3 to 9 seconds, during which the tile
  answers nothing else and does not drain its input from replay. Do not
  expose these to untrusted callers. Behaviour under sustained scan
  load, or on a mainnet-sized database, has not been tested.
- **The recent transaction window.** `getTransaction`, `getBlock`,
  `getSignaturesForAddress` and `getSignatureStatuses` answer from the
  last 131,072 transactions this node replayed, held in memory (about
  330 MB in the RPC tile). There is no history from before the node
  started, none survives a restart, and nothing older than the window
  is known. The RPC tile reads replay's per-transaction messages from
  the `replay_out` link unreliably, so it cannot backpressure replay,
  and it discards a message it was too slow to read; that transaction
  is then missing, and `getBlock` refuses its block.
- **Blocks this node produces as leader have not been checked.** The
  window is fed by replay. The check node was not a leader, so whether
  a node's own blocks reach the window is unknown.
- **The transaction simulator.** `simulateTransaction` does not use the
  validator's execution path. The RPC tile holds a second, private
  runtime (accounts database, program cache, status cache, bank) built
  from `fd_svm_mini`, the environment Firedancer's own runtime tests
  use; that file moves from the test library into `fd_flamenco` for
  this. For each call the tile resets the private runtime, copies in
  the bank's sysvars and recent blockhashes, the transaction's
  accounts, the programdata of any upgradeable program among them and
  whatever its lookup tables resolve to, runs the transaction with the
  live feature set, and reads off the result. Nothing is shared with
  replay or the exec tiles, so a simulation cannot change what the
  validator executes or commits.
  - It reserves about 5.4 GB of address space, paged in lazily; what
    is actually used depends on the programs and accounts simulated.
  - The first simulation after start took 2.6 s; later ones well under
    100 ms including the network round trip.
  - It runs in the tile's sandbox with no new system calls allowed.
  - The private bank carries the feature set, rent, epoch schedule,
    slot and blockhashes of the live bank, and nothing else of it. A
    program that depends on other bank state (stake or vote program
    instructions that read epoch stakes, for instance) may behave
    differently than on chain. That has not been explored.
- **The patch is not confined to the RPC tile.** It also changes:
  - the execution tiles (`fd_execrp_tile.c`, `fd_execrp.h`): each
    reports a transaction's balances and failed-instruction detail to
    replay, and publishes its logs, instruction trace and return data
    on a new `execrp_rpc` link that only the RPC tile reads;
  - **program log collection is switched on in the execution tiles**
    whenever the RPC tile is in the topology. Stock Firedancer runs
    with it off. Its cost on a busy cluster has not been measured;
  - replay (`fd_replay_tile.c`): passes the above along and publishes
    epoch rewards in batches;
  - the runtime (`fd_rewards.c`, `fd_rewards.h`, `fd_accdb_svm.c`): a
    thread-local hook that records each vote and stake reward as it is
    credited. It is NULL, and does nothing, in every tile but replay;
  - `topology.c`: the links.

  These changes copy data out; they do not change what is executed or
  committed. The node ran in step with the cluster with them in place,
  and Firedancer's own reward and execution unit tests pass, but this
  is the execution path of a validator: review it before running it on
  anything that matters.
- **Logs and inner instructions.** Kept in a 256 MB ring in the RPC
  tile (paged in as it fills), matched to a transaction by signature
  and slot. They come over an unreliable link, so a transaction the
  tile was too slow to read has `null` logs. Transactions in blocks
  this node produced itself as leader go through a different execution
  tile and have none. Inner instructions are in compiled form (account
  indexes, base58 data), which is what Agave returns for the `json`,
  `base64` and `base58` encodings.
- **Epoch rewards.** Two tables of 4 million entries each (about 270 MB
  each, paged in as they fill) hold the rewards of the two most recent
  epochs. Like the transaction window they are memory only: after a
  restart the node answers "Block not available" for an epoch until it
  has watched one being paid from the start. If the tile misses a batch
  the whole epoch is marked incomplete and answers the same error
  rather than a wrong `null`. A vote account whose reward was zero
  comes back `null` where Agave returns an entry with amount 0.
- **A scan is not a point-in-time view.** Accounts written while a scan
  runs may or may not be included.
- **How it was checked.** Each call was issued to an Agave 4.5.0-beta.0
  node and to a Firedancer node running this patch on the Alpenglow
  community cluster, and the answers compared. That is one small
  cluster with Alpenglow active. Nothing here has been run on mainnet
  or testnet, with pre-v4 vote accounts, or with Token-2022 accounts.
- `sendTransaction` landed one transaction: a `solana transfer` from
  the 4.5.0-beta.0 CLI pointed at the patched node, finalized and
  confirmed on the Agave node too. That is one transaction, sent from
  a node that was not a leader, while some leaders ran Firedancer.
  Decoding, signature verification and the error paths were also
  checked by resubmitting a transaction that had already landed.
- The 4.5 CLI sends **v1 transactions** (message first, signatures
  last, fee settings in the header). `getFeeForMessage`,
  `sendTransaction` and the history calls handle them. The `json`
  rendering of a v1 transaction matches Agave's (checked once Agave's
  transaction history was switched on).
- Twenty read-only `solana` CLI commands (`validators`,
  `block-production`, `stakes`, `vote-account`, `supply`, `block`,
  `largest-accounts`, ...) ran against the patched node without error.
- Transaction history was compared with an Agave node that records
  history, on five fresh transactions (three transfers, a lookup
  table extend with an inner call, and a nonce withdrawal that fails
  with `InsufficientFunds`). `getTransaction` matched field for field
  in `json` and `base64`, including logs, inner instructions, compute
  units and the error of the failed one; so did
  `getSignatureStatuses` and `getSignaturesForAddress`. `getBlock`
  matched except for `rewards`. Every transaction was in the v1
  format with a single signer; v0 transactions, lookup tables in use,
  return data in a landed transaction and blocks with many
  transactions have not been seen.
- **An earlier version of this patch printed the block cost as
  `computeUnitsConsumed`.** That is fixed: the cost is `costUnits` and
  `computeUnitsConsumed` is what the programs used.
- Websocket: with `signatureSubscribe` (three commitment levels) and
  `accountSubscribe` (base64 and jsonParsed) open on both nodes, one
  transfer produced the same notifications from each. Unsubscribe and
  the error replies matched too.
- `simulateTransaction` was compared with Agave on 14 cases: a system
  transfer (ok, more than the balance, to a new account, unknown fee
  payer, stale blockhash, bad signature with `sigVerify`), two
  instructions with the second failing, an SPL token transfer through
  the on-chain token program (ok and failing), the stake program's
  `GetMinimumDelegation` (return data), requested accounts, too many
  requested accounts, and base58 input. 13 matched field for field
  including logs, compute units and loaded data size; the other
  differed only in `rentEpoch` of the system program account. Not
  tried: v0 transactions with lookup tables, large programs,
  Token-2022.
- Nonce, lookup table, program, programData and validator info
  parsing matched Agave on every such account on the cluster (one
  nonce account and one lookup table, both created for the purpose; 26
  loader accounts; 52 validator info records).
- A real lookup-table extend transaction (v1 format, with a call into
  the system program) was simulated on both: result, logs, compute
  units and balances matched; inner instructions carried the same
  instruction in the two different forms.
- Parsed sysvars were compared with Agave at the same finalized slot:
  all nine matched, including the million-bit slot history, apart
  from `rentEpoch` on three of them.
- Parsed stake, token and vote output was compared with Agave over
  whole programs: all 12 token accounts, all 76 vote accounts, 27,730
  delegated and 4,285 undelegated stake accounts. They matched apart
  from fields that changed between the two calls and `rentEpoch` on
  one genesis account. No Token-2022 accounts, frozen or delegated
  token accounts, or wrapped-SOL accounts exist on the cluster, so
  those branches are unverified.
- `getStakeMinimumDelegation` returned 1 SOL, as Agave does there.
- The `test_rpc_tile`, `test_execrp_tile`, `test_svm_mini`,
  `test_inflation_rewards` and `test_accdb_svm` unit tests pass.
  `test_replay_tile` and `test_sched` could not be run on the test
  machine (no huge pages).
- The patch adds no unit tests of its own.

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
