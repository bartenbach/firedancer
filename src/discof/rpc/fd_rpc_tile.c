#include "../replay/fd_replay_tile.h"
#include "../genesis/fd_genesi_tile.h"
#include "../votor/fd_votor_tile.h"
#include "../../choreo/votor/fd_cert.h"

#include "../../ballet/base64/fd_base64.h"
#include "fd_rpc_sim.h"
#include "../backup/fd_snapmk_tile.h"
#include "../replay/fd_execrp.h"
#include "../../flamenco/rewards/fd_epoch_inflation_account.h"
#include "../../ballet/txn/fd_txn_v1.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/json/fd_jtok.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_dns_resolve.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/fd_clock_tile.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/waker/fd_waker.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/features/fd_features.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../flamenco/runtime/fd_runtime_const.h"
#include "../../flamenco/runtime/fd_runtime_err.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/alpenglow/fd_alpenglow.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec_tmpl.h"
#include "../../tango/fseq/fd_fseq.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../util/net/fd_ip4.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../waltz/http/fd_url.h"

#include <stddef.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <sys/mman.h>
#include <stdlib.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include "../../util/archive/fd_tar.h"
#include "../../third_party/bzip2/bzlib.h"

#include <linux/futex.h>
#include "generated/fd_rpc_tile_seccomp.h"

#define FD_RPC_AGAVE_API_VERSION "4.4.0"

#define FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN       8192UL

/* FD_RPC_ID_MAX_SZ is the longest JSON-RPC request id (as raw JSON
   text) that is echoed back in responses. */
#define FD_RPC_ID_MAX_SZ                         (256UL)
#define FD_HTTP_SERVER_RPC_MAX_WS_SEND_FRAME_CNT  128UL

#define IN_KIND_REPLAY      (0)
#define IN_KIND_GENESI      (1)
#define IN_KIND_GOSSIP_OUT  (2)
#define IN_KIND_EPOCH       (5)
#define IN_KIND_VOTOR       (6)
#define IN_KIND_REPLAY_TXN   (7)
#define IN_KIND_SNAPMK       (8)
#define IN_KIND_EXECRP_META  (9)

/* From bzip2 docs:
      To guarantee that the compressed data will fit in its buffer,
      allocate an output buffer of size 1% larger than the uncompressed
      data, plus six hundred extra bytes.
*/
FD_FN_CONST static inline ulong
fd_rpc_genesis_tar_max_sz( ulong max_message_size ) {
  return max_message_size + 4UL*FD_TAR_BLOCK_SZ;
}

FD_FN_CONST static inline ulong
fd_rpc_genesis_tar_bz_max_sz( ulong max_message_size ) {
  ulong tar_max_sz = fd_rpc_genesis_tar_max_sz( max_message_size );
  return tar_max_sz + ((tar_max_sz + 100UL - 1UL) / 100UL) + 600UL;
}

#define FD_RPC_BASE58_ENCODED_128_LEN (175UL) /* ceil(128*log58(256)) */
#define FD_RPC_ZSTD_LEVEL 1
/* levels 4-15 are compiled out of libfd_zstd (third_party/zstd/Local.mk) */
FD_STATIC_ASSERT( FD_RPC_ZSTD_LEVEL<=3 || FD_RPC_ZSTD_LEVEL>=16, zstd_level );

#define FD_RPC_COMMITMENT_PROCESSED (0)
#define FD_RPC_COMMITMENT_CONFIRMED (1)
#define FD_RPC_COMMITMENT_FINALIZED (2)

#define FD_RPC_ENCODING_BASE58      (0)
#define FD_RPC_ENCODING_BASE64      (1)
#define FD_RPC_ENCODING_BASE64_ZSTD (2)
#define FD_RPC_ENCODING_BINARY      (3)
#define FD_RPC_ENCODING_JSON_PARSED (4)

#define FD_RPC_HEALTH_STATUS_OK      (0)
#define FD_RPC_HEALTH_STATUS_BEHIND  (1)
#define FD_RPC_HEALTH_STATUS_UNKNOWN (2)

/* Matches Agave's default health_check_slot_distance. */
#define FD_RPC_HEALTH_CHECK_SLOT_DISTANCE (128UL)

#define FD_RPC_METHOD_GET_ACCOUNT_INFO                       ( 0)
#define FD_RPC_METHOD_GET_BALANCE                            ( 1)
#define FD_RPC_METHOD_GET_BLOCK                              ( 2)
#define FD_RPC_METHOD_GET_BLOCK_COMMITMENT                   ( 3)
#define FD_RPC_METHOD_GET_BLOCK_HEIGHT                       ( 4)
#define FD_RPC_METHOD_GET_BLOCK_PRODUCTION                   ( 5)
#define FD_RPC_METHOD_GET_BLOCKS                             ( 6)
#define FD_RPC_METHOD_GET_BLOCKS_WITH_LIMIT                  ( 7)
#define FD_RPC_METHOD_GET_BLOCK_TIME                         ( 8)
#define FD_RPC_METHOD_GET_CLUSTER_NODES                      ( 9)
#define FD_RPC_METHOD_GET_EPOCH_INFO                         (10)
#define FD_RPC_METHOD_GET_EPOCH_SCHEDULE                     (11)
#define FD_RPC_METHOD_GET_FEE_FOR_MESSAGE                    (12)
#define FD_RPC_METHOD_GET_FIRST_AVAILABLE_BLOCK              (13)
#define FD_RPC_METHOD_GET_GENESIS_HASH                       (14)
#define FD_RPC_METHOD_GET_HEALTH                             (15)
#define FD_RPC_METHOD_GET_HIGHEST_SNAPSHOT_SLOT              (16)
#define FD_RPC_METHOD_GET_IDENTITY                           (17)
#define FD_RPC_METHOD_GET_INFLATION_GOVERNOR                 (18)
#define FD_RPC_METHOD_GET_INFLATION_RATE                     (19)
#define FD_RPC_METHOD_GET_INFLATION_REWARD                   (20)
#define FD_RPC_METHOD_GET_LARGEST_ACCOUNTS                   (21)
#define FD_RPC_METHOD_GET_LATEST_BLOCKHASH                   (22)
#define FD_RPC_METHOD_GET_LEADER_SCHEDULE                    (23)
#define FD_RPC_METHOD_GET_MAX_RETRANSMIT_SLOT                (24)
#define FD_RPC_METHOD_GET_MAX_SHRED_INSERT_SLOT              (25)
#define FD_RPC_METHOD_GET_MINIMUM_BALANCE_FOR_RENT_EXEMPTION (26)
#define FD_RPC_METHOD_GET_MULTIPLE_ACCOUNTS                  (27)
#define FD_RPC_METHOD_GET_PROGRAM_ACCOUNTS                   (28)
#define FD_RPC_METHOD_GET_RECENT_PERFORMANCE_SAMPLES         (29)
#define FD_RPC_METHOD_GET_RECENT_PRIORITIZATION_FEES         (30)
#define FD_RPC_METHOD_GET_SIGNATURES_FOR_ADDRESS             (31)
#define FD_RPC_METHOD_GET_SIGNATURE_STATUSES                 (32)
#define FD_RPC_METHOD_GET_SLOT                               (33)
#define FD_RPC_METHOD_GET_SLOT_LEADER                        (34)
#define FD_RPC_METHOD_GET_SLOT_LEADERS                       (35)
#define FD_RPC_METHOD_GET_STAKE_MINIMUM_DELEGATION           (36)
#define FD_RPC_METHOD_GET_SUPPLY                             (37)
#define FD_RPC_METHOD_GET_TOKEN_ACCOUNT_BALANCE              (38)
#define FD_RPC_METHOD_GET_TOKEN_ACCOUNTS_BY_DELEGATE         (39)
#define FD_RPC_METHOD_GET_TOKEN_ACCOUNTS_BY_OWNER            (40)
#define FD_RPC_METHOD_GET_TOKEN_LARGEST_ACCOUNTS             (41)
#define FD_RPC_METHOD_GET_TOKEN_SUPPLY                       (42)
#define FD_RPC_METHOD_GET_TRANSACTION                        (43)
#define FD_RPC_METHOD_GET_TRANSACTION_COUNT                  (44)
#define FD_RPC_METHOD_GET_VERSION                            (45)
#define FD_RPC_METHOD_GET_VOTE_ACCOUNTS                      (46)
#define FD_RPC_METHOD_IS_BLOCKHASH_VALID                     (47)
#define FD_RPC_METHOD_MINIMUM_LEDGER_SLOT                    (48)
#define FD_RPC_METHOD_REQUEST_AIRDROP                        (49)
#define FD_RPC_METHOD_SEND_TRANSACTION                       (50)
#define FD_RPC_METHOD_SIMULATE_TRANSACTION                   (51)

// Keep in sync with https://github.com/solana-labs/solana-web3.js/blob/master/src/errors.ts
// and https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs
#define FD_RPC_ERROR_BLOCK_CLEANED_UP                            (-32001)
#define FD_RPC_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE          (-32002)
#define FD_RPC_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE  (-32003)
#define FD_RPC_ERROR_BLOCK_NOT_AVAILABLE                         (-32004)
#define FD_RPC_ERROR_NODE_UNHEALTHY                              (-32005)
#define FD_RPC_ERROR_TRANSACTION_PRECOMPILE_VERIFICATION_FAILURE (-32006)
#define FD_RPC_ERROR_SLOT_SKIPPED                                (-32007)
#define FD_RPC_ERROR_NO_SNAPSHOT                                 (-32008)
#define FD_RPC_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED              (-32009)
#define FD_RPC_ERROR_KEY_EXCLUDED_FROM_SECONDARY_INDEX           (-32010)
#define FD_RPC_ERROR_TRANSACTION_HISTORY_NOT_AVAILABLE           (-32011)
#define FD_RPC_ROR                                               (-32012)
#define FD_RPC_ERROR_TRANSACTION_SIGNATURE_LEN_MISMATCH          (-32013)
#define FD_RPC_ERROR_BLOCK_STATUS_NOT_AVAILABLE_YET              (-32014)
#define FD_RPC_ERROR_UNSUPPORTED_TRANSACTION_VERSION             (-32015)
#define FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED                (-32016)
#define FD_RPC_ERROR_EPOCH_REWARDS_PERIOD_ACTIVE                 (-32017)
#define FD_RPC_ERROR_SLOT_NOT_EPOCH_BOUNDARY                     (-32018)
#define FD_RPC_ERROR_LONG_TERM_STORAGE_UNREACHABLE               (-32019)
#define FD_RPC_ERROR_NO_SLOT_HISTORY                             (-32021)

/* fd_rpc_val_t is a JSON value captured from a request as a raw input
   slice plus its kind.  Kinds mirror the serde names Agave uses in its
   error messages.  INT is a number literal that fits in a ulong or a
   long, any other number literal is FLOAT.  NONE denotes an absent
   value (missing member or array element). */

#define FD_RPC_VAL_NONE  (0)
#define FD_RPC_VAL_STR   (1)
#define FD_RPC_VAL_MAP   (2)
#define FD_RPC_VAL_SEQ   (3)
#define FD_RPC_VAL_BOOL  (4)
#define FD_RPC_VAL_FLOAT (5)
#define FD_RPC_VAL_INT   (6)
#define FD_RPC_VAL_NULL  (7)

struct fd_rpc_val {
  int           kind;
  char const *  raw;
  ulong         raw_sz;
  fd_jtok_str_t str; /* STR only: view of the contents between the quotes */
  int           neg; /* INT only: value is negative */
  ulong         u;   /* INT only: value if !neg */
};

typedef struct fd_rpc_val fd_rpc_val_t;

static void
fd_rpc_val_read( fd_jtok_t *    j,
                 fd_rpc_val_t * v ) {
  *v = (fd_rpc_val_t){ .kind = FD_RPC_VAL_NONE };
  int kind = fd_jtok_peek( j );
  char const * raw;
  ulong        raw_sz;
  fd_jtok_raw( j, &raw, &raw_sz );
  if( FD_UNLIKELY( fd_jtok_err( j ) ) ) return;
  v->raw    = raw;
  v->raw_sz = raw_sz;
  switch( kind ) {
  case FD_JTOK_OBJ:  v->kind = FD_RPC_VAL_MAP;   break;
  case FD_JTOK_ARR:  v->kind = FD_RPC_VAL_SEQ;   break;
  case FD_JTOK_BOOL: v->kind = FD_RPC_VAL_BOOL;  break;
  case FD_JTOK_NULL: v->kind = FD_RPC_VAL_NULL;  break;
  case FD_JTOK_NUM:  v->kind = FD_RPC_VAL_FLOAT; break;
  case FD_JTOK_STR:
    v->kind = FD_RPC_VAL_STR;
    v->str  = (fd_jtok_str_t){ .ptr = raw+1, .sz = raw_sz-2UL }; /* raw is the token including both quotes */
    break;
  case FD_JTOK_INT: {
    fd_jtok_t n[1];
    ulong u;
    fd_jtok_ulong( fd_jtok_init( n, raw, raw_sz ), &u );
    if( FD_LIKELY( !fd_jtok_err( n ) ) ) { v->kind = FD_RPC_VAL_INT; v->u = u; break; }
    long l;
    fd_jtok_long( fd_jtok_init( n, raw, raw_sz ), &l );
    if( FD_LIKELY( !fd_jtok_err( n ) ) ) { v->kind = FD_RPC_VAL_INT; v->neg = l<0L; v->u = l<0L ? 0UL : (ulong)l; break; }
    v->kind = FD_RPC_VAL_FLOAT;
    break;
  }
  default: break;
  }
}

/* fd_rpc_val_cstr decodes a STR value into the out_sz byte buffer at
   out.  Returns 1 on success, 0 if v is not a string or does not fit
   (out is then an empty string). */

static int
fd_rpc_val_cstr( fd_rpc_val_t const * v,
                 char *               out,
                 ulong                out_sz ) {
  out[0] = '\0';
  if( v->kind!=FD_RPC_VAL_STR ) return 0;
  fd_jtok_t j[1];
  fd_jtok_cstr( fd_jtok_init( j, v->raw, v->raw_sz ), out, out_sz );
  return !fd_jtok_err( j );
}

/* fd_rpc_params_t is the "params" member of a request.  kind is the
   kind of the params value itself.  For a SEQ, cnt is the element
   count and v holds the first FD_RPC_PARAM_MAX elements (NONE beyond
   cnt). */

#define FD_RPC_PARAM_MAX (3UL)

struct fd_rpc_params {
  int          kind;
  ulong        cnt;
  fd_rpc_val_t v[ FD_RPC_PARAM_MAX ];
};

typedef struct fd_rpc_params fd_rpc_params_t;

static void
fd_rpc_params_read( fd_rpc_val_t const * params,
                    fd_rpc_params_t *    out ) {
  out->kind = params->kind;
  out->cnt  = 0UL;
  for( ulong i=0UL; i<FD_RPC_PARAM_MAX; i++ ) out->v[ i ].kind = FD_RPC_VAL_NONE;
  if( params->kind!=FD_RPC_VAL_SEQ ) return;
  fd_jtok_t j[1];
  fd_jtok_arr_enter( fd_jtok_init( j, params->raw, params->raw_sz ) );
  while( fd_jtok_arr_next( j ) ) {
    if( out->cnt<FD_RPC_PARAM_MAX ) fd_rpc_val_read( j, &out->v[ out->cnt ] );
    out->cnt++;
  }
}

/* fd_rpc_config_t holds the members of a config object that any
   handler looks at.  For duplicate members the first occurrence wins,
   unknown members are skipped. */

struct fd_rpc_config {
  fd_rpc_val_t commitment;
  fd_rpc_val_t encoding;
  fd_rpc_val_t data_slice;
  fd_rpc_val_t min_context_slot;
  fd_rpc_val_t identity;
  fd_rpc_val_t vote_pubkey;
  fd_rpc_val_t keep_unstaked_delinquents;
  fd_rpc_val_t delinquent_slot_distance;
  fd_rpc_val_t range;
};

typedef struct fd_rpc_config fd_rpc_config_t;

static void
fd_rpc_config_read( fd_rpc_val_t const * config,
                    fd_rpc_config_t *    out ) {
  out->commitment.kind       = FD_RPC_VAL_NONE;
  out->encoding.kind         = FD_RPC_VAL_NONE;
  out->data_slice.kind       = FD_RPC_VAL_NONE;
  out->min_context_slot.kind = FD_RPC_VAL_NONE;
  out->identity.kind         = FD_RPC_VAL_NONE;
  out->vote_pubkey.kind               = FD_RPC_VAL_NONE;
  out->keep_unstaked_delinquents.kind = FD_RPC_VAL_NONE;
  out->delinquent_slot_distance.kind  = FD_RPC_VAL_NONE;
  out->range.kind                     = FD_RPC_VAL_NONE;
  if( config->kind!=FD_RPC_VAL_MAP ) return;
  fd_jtok_t j[1];
  fd_jtok_str_t key;
  fd_jtok_obj_enter( fd_jtok_init( j, config->raw, config->raw_sz ) );
  while( fd_jtok_obj_next( j, &key ) ) {
    fd_rpc_val_t * member;
    if(      fd_jtok_str_eq( &key, "commitment"     ) ) member = &out->commitment;
    else if( fd_jtok_str_eq( &key, "encoding"       ) ) member = &out->encoding;
    else if( fd_jtok_str_eq( &key, "dataSlice"      ) ) member = &out->data_slice;
    else if( fd_jtok_str_eq( &key, "minContextSlot" ) ) member = &out->min_context_slot;
    else if( fd_jtok_str_eq( &key, "identity"       ) ) member = &out->identity;
    else if( fd_jtok_str_eq( &key, "votePubkey"              ) ) member = &out->vote_pubkey;
    else if( fd_jtok_str_eq( &key, "keepUnstakedDelinquents" ) ) member = &out->keep_unstaked_delinquents;
    else if( fd_jtok_str_eq( &key, "delinquentSlotDistance"  ) ) member = &out->delinquent_slot_distance;
    else if( fd_jtok_str_eq( &key, "range"                   ) ) member = &out->range;
    else continue;
    if( member->kind==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, member );
  }
}

static fd_http_server_params_t
derive_http_params( fd_topo_tile_t const * tile ) {
  return (fd_http_server_params_t) {
    .max_connection_cnt    = tile->rpc.max_http_connections,
    .max_ws_connection_cnt = tile->rpc.max_websocket_connections,
    .max_request_len       = FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN,
    .max_ws_recv_frame_len = FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN,
    .max_ws_send_frame_cnt = FD_HTTP_SERVER_RPC_MAX_WS_SEND_FRAME_CNT,
    .outgoing_buffer_sz    = tile->rpc.send_buffer_size_mb * (1UL<<20UL),
    .compress_websocket    = 0,
  };
}

struct fd_rpc_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_rpc_in fd_rpc_in_t;

struct fd_rpc_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_rpc_out fd_rpc_out_t;

struct bank_info {
  ulong slot; /* default ULONG_MAX */
  ulong bank_idx;
  fd_accdb_fork_id_t accdb_fork_id;
  ulong epoch;
  ulong slot_in_epoch;
  ulong slots_per_epoch;

  ulong transaction_count;
  uchar block_hash[ 32 ];
  ulong block_height;

  struct {
    double initial;
    double terminal;
    double taper;
    double foundation;
    double foundation_term;
  } inflation;

  struct {
    ulong lamports_per_uint8_year;
    double exemption_threshold;
    uchar burn_percent;
  } rent;
};

typedef struct bank_info bank_info_t;

struct fd_rpc_meta_ent {
  uchar sig[ 64 ];
  ulong slot;
  uint  log_sz;
  uint  inner_sz;
  uint  return_sz;
  uchar has_return;
  uchar inner_truncated;
  uchar has_token;
  uchar has_cu;
  uint  cu_consumed;
  uchar return_program[ 32 ];
  /* inner_sz, log_sz and return_sz bytes follow, in that order */
};
typedef struct fd_rpc_meta_ent fd_rpc_meta_ent_t;

/* Epoch reward store.  One open addressed table per reward epoch, the
   two most recent epochs are kept.  An account can appear more than
   once if competing blocks paid it; the query picks the entry whose
   block is on the queried fork.  The memory is anonymous and only
   paged in as it fills. */

#define FD_RPC_REWARD_EPOCH_CNT (2UL)
#define FD_RPC_REWARD_ENT_CNT   (1UL<<22)
#define FD_RPC_REWARD_ENT_MAX   (3UL<<20) /* stop filling at 75% load */

struct fd_rpc_reward_ent {
  uchar pubkey[ 32 ];
  ulong slot;          /* 0 if the entry is unused */
  ulong amount;
  ulong post_balance;
};
typedef struct fd_rpc_reward_ent fd_rpc_reward_ent_t;

struct fd_rpc_reward_epoch {
  ulong                 epoch;      /* epoch the rewards were earned in, ULONG_MAX if unused */
  ulong                 cnt;
  int                   incomplete; /* some rewards of this epoch were not seen */
  ulong                 slot_lo;    /* first and last slot a reward of this epoch was paid in */
  ulong                 slot_hi;
  fd_rpc_reward_ent_t * ents;       /* NULL if the memory could not be reserved */
};
typedef struct fd_rpc_reward_epoch fd_rpc_reward_epoch_t;

struct fd_rpc_cluster_node {
  int valid;
  fd_pubkey_t identity;
  fd_gossip_contact_info_t ci[ 1 ];

  struct { ulong prev, next; } dlist;
};

typedef struct fd_rpc_cluster_node fd_rpc_cluster_node_t;

#define DLIST_NAME  fd_rpc_cluster_node_dlist
#define DLIST_ELE_T fd_rpc_cluster_node_t
#define DLIST_PREV dlist.prev
#define DLIST_NEXT dlist.next
#include "../../util/tmpl/fd_dlist.c"

/* fd_rpc_gls_pair_t associates a leader-schedule rotation index with the
   identity pubkey that leads it, used to group getLeaderSchedule's
   result by identity (see the handler). */
struct fd_rpc_gls_pair {
  fd_pubkey_t id_key; /* leader identity */
  uint        rot;    /* rotation index into the epoch's leader schedule */
};
typedef struct fd_rpc_gls_pair fd_rpc_gls_pair_t;

struct fd_rpc_vote_set_ele {
  fd_pubkey_t vote_key;
  ulong       stake;
};
typedef struct fd_rpc_vote_set_ele fd_rpc_vote_set_ele_t;

struct fd_rpc_vote_set {
  ulong                 epoch;
  ulong                 cnt;
  fd_rpc_vote_set_ele_t ele[ MAX_STAKE_WEIGHTS ];
};
typedef struct fd_rpc_vote_set fd_rpc_vote_set_t;

#define FD_RPC_VOTE_SET_CNT (3UL)

#define SORT_NAME        fd_rpc_vote_set_sort
#define SORT_KEY_T       fd_rpc_vote_set_ele_t
#define SORT_BEFORE(a,b) (memcmp( (a).vote_key.uc, (b).vote_key.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

#define FD_RPC_VOTE_ACCOUNT_CREDITS_MAX     (5UL)
#define FD_RPC_DELINQUENT_SLOT_DISTANCE     (128UL)

struct fd_rpc_vote_info {
  fd_pubkey_t             vote_key;
  fd_pubkey_t             node_key;
  ulong                   stake;
  ushort                  commission_bps;
  int                     epoch_vote_account;
  ulong                   last_vote;
  ulong                   root_slot;
  ulong                   credits_cnt;
  fd_vote_epoch_credits_t credits[ FD_RPC_VOTE_ACCOUNT_CREDITS_MAX ];
};
typedef struct fd_rpc_vote_info fd_rpc_vote_info_t;

struct fd_rpc_block_production {
  fd_pubkey_t key;
  ulong       leader_slots;
  ulong       blocks_produced;
};
typedef struct fd_rpc_block_production fd_rpc_block_production_t;

static fd_pubkey_t const fd_rpc_null_pubkey = {0};

#define MAP_NAME              fd_rpc_block_production_map
#define MAP_T                 fd_rpc_block_production_t
#define MAP_KEY_T             fd_pubkey_t
#define MAP_MEMOIZE           0
#define MAP_LG_SLOT_CNT       16
#define MAP_KEY_NULL          fd_rpc_null_pubkey
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).uc, (k1).uc, 32UL ))
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL( (k), fd_rpc_null_pubkey )
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(k)       ((uint)fd_ulong_hash( fd_ulong_load_8( (k).uc ) ))
#include "../../util/tmpl/fd_map.c"

struct fd_rpc_block_production_table {
  fd_rpc_block_production_t map [ 1UL<<16 ];
  uint                      used[ 1UL<<16 ];
  ulong                     cnt;
};
typedef struct fd_rpc_block_production_table fd_rpc_block_production_table_t;

static void
fd_rpc_block_production_table_reset( fd_rpc_block_production_table_t * table ) {
  for( ulong i=0UL; i<table->cnt; i++ ) table->map[ table->used[ i ] ].key = fd_rpc_null_pubkey;
  table->cnt = 0UL;
}

static void
fd_rpc_block_production_table_add( fd_rpc_block_production_table_t * table,
                                   fd_pubkey_t const *               key,
                                   ulong                             leader_slots,
                                   ulong                             blocks_produced ) {
  fd_rpc_block_production_t * entry = fd_rpc_block_production_map_query( table->map, *key, NULL );
  if( FD_UNLIKELY( !entry ) ) {
    FD_TEST( table->cnt<fd_rpc_block_production_map_key_max() );
    entry = fd_rpc_block_production_map_insert( table->map, *key );
    entry->leader_slots    = 0UL;
    entry->blocks_produced = 0UL;
    table->used[ table->cnt++ ] = (uint)fd_rpc_block_production_map_slot_idx( table->map, entry );
  }
  entry->leader_slots    += leader_slots;
  entry->blocks_produced += blocks_produced;
}

#define FD_RPC_PERF_SAMPLE_MAX      (720UL)
#define FD_RPC_PERF_SAMPLE_INTERVAL (60L*1000000000L)

struct fd_rpc_perf_sample {
  ulong  slot;
  ulong  num_transactions;
  ulong  num_slots;
  ushort sample_period_secs;
};
typedef struct fd_rpc_perf_sample fd_rpc_perf_sample_t;

#define FD_RPC_BLOCK_TIME_MAX (1UL<<19)

struct fd_rpc_block_time {
  ulong slot;
  long  unix_timestamp;
};
typedef struct fd_rpc_block_time fd_rpc_block_time_t;

#define FD_RPC_MLEADERS_CNT       (5UL)
#define FD_RPC_MLEADERS_EPOCH_CNT (FD_RPC_MLEADERS_CNT*MULTI_EPOCH_LEADERS_EPOCH_CNT)

static inline void
fd_rpc_mleaders_init( fd_multi_epoch_leaders_t * mleaders ) {
  for( ulong i=0UL; i<FD_RPC_MLEADERS_CNT; i++ ) FD_TEST( fd_multi_epoch_leaders_new( &mleaders[ i ] ) );
}

static inline void
fd_rpc_mleaders_ingest( fd_multi_epoch_leaders_t *  mleaders,
                        fd_epoch_info_msg_t const * msg ) {
  ulong idx = (msg->epoch / MULTI_EPOCH_LEADERS_EPOCH_CNT) % FD_RPC_MLEADERS_CNT;
  fd_multi_epoch_leaders_epoch_msg_init( &mleaders[ idx ], msg );
  fd_multi_epoch_leaders_epoch_msg_fini( &mleaders[ idx ] );
}

FD_FN_PURE static inline fd_epoch_leaders_t const *
fd_rpc_mleaders_get_lsched_for_slot( fd_multi_epoch_leaders_t const * mleaders,
                                     ulong                            slot ) {
  for( ulong i=0UL; i<FD_RPC_MLEADERS_CNT; i++ ) {
    fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( &mleaders[ i ], slot );
    if( FD_LIKELY( lsched ) ) return lsched;
  }
  return NULL;
}

FD_FN_PURE static inline fd_pubkey_t const *
fd_rpc_mleaders_get_leader_for_slot( fd_multi_epoch_leaders_t const * mleaders,
                                     ulong                            slot ) {
  fd_epoch_leaders_t const * lsched = fd_rpc_mleaders_get_lsched_for_slot( mleaders, slot );
  if( FD_UNLIKELY( !lsched ) ) return NULL;
  return fd_epoch_leaders_get( lsched, slot );
}

/* Recent transaction window, fed by replay's per-transaction result
   message.  It is what getSignatureStatuses and getBlock answer from:
   a ring of the last FD_RPC_TXN_REC_CNT transactions that landed in a
   block, with a hash table from signature to ring position.  Nothing
   older than the ring, and nothing from before this node started, is
   known.  The link from replay is unreliable, so a transaction can be
   missing if the tile fell behind. */
#define FD_RPC_TXN_REC_CNT     (1UL<<17)
#define FD_RPC_TXN_TABLE_CNT   (1UL<<21)
#define FD_RPC_TXN_PROBE_MAX   (32UL)
#define FD_RPC_BLOCK_META_CNT  (1UL<<16)
#define FD_RPC_BLOCK_TXN_MAX   (16384UL)

struct fd_rpc_txn_rec {
  uchar  sig[ 64 ];
  ulong  slot;
  uint   index_in_slot;
  int    txn_err;      /* FD_RUNTIME_TXN_ERR_*, 0 on success */
  int    has_exec_err; /* the four fields below are known */
  int    exec_err;     /* failed instruction, if txn_err is INSTRUCTION_ERROR */
  int    exec_err_kind;
  uint   exec_err_idx;
  uint   custom_err;
  ulong  fee;          /* signature fee plus priority fee, lamports */
  uint   compute_units;
  ushort payload_sz;
  ushort acct_off;     /* static account addresses in payload */
  ushort acct_cnt;
  ushort bal_cnt;      /* 0 if replay did not report balances */
  ulong  pre_lamports [ MAX_TX_ACCOUNT_LOCKS ];
  ulong  post_lamports[ MAX_TX_ACCOUNT_LOCKS ];
  uchar  payload[ FD_TXN_MTU_V0 ];
};
typedef struct fd_rpc_txn_rec fd_rpc_txn_rec_t;

struct fd_rpc_block_meta {
  ulong slot;         /* ULONG_MAX if empty */
  ulong parent_slot;
  ulong block_height;
  ulong txn_cnt;      /* ULONG_MAX if replay did not report it */
  uchar block_hash[ 32 ];
  int   has_leader;   /* fee_reward is known */
  ulong fee_reward;   /* fees the block collected, 0 if none */
};
typedef struct fd_rpc_block_meta fd_rpc_block_meta_t;

struct fd_rpc_block_txn {
  uint  index_in_slot;
  uint  rec;
};
typedef struct fd_rpc_block_txn fd_rpc_block_txn_t;

#define SORT_NAME        fd_rpc_block_txn_sort
#define SORT_KEY_T       fd_rpc_block_txn_t
#define SORT_BEFORE(a,b) ((a).index_in_slot<(b).index_in_slot)
#include "../../util/tmpl/fd_sort.c"

/* sendTransaction: transactions are sent as UDP datagrams to the TPU
   port of the upcoming leaders, and kept here to be sent again each
   leader rotation until they are seen in a block or have expired. */
#define FD_RPC_SEND_PENDING_MAX      (256UL)
#define FD_RPC_SEND_EXPIRE_SLOTS     (150UL)
#define FD_RPC_SEND_LEADER_ROTATIONS (4UL)

struct fd_rpc_send_pending {
  int    used;
  ushort sz;
  ulong  submit_slot;
  uchar  sig[ 64 ];
  uchar  payload[ FD_TXN_MTU_V0 ];
};
typedef struct fd_rpc_send_pending fd_rpc_send_pending_t;

#define FD_RPC_SCAN_KEYS_MAX     (4096UL)
#define FD_RPC_SCAN_CHAIN_BUDGET (1UL<<20)
#define FD_RPC_PRIO_FEE_CNT      (150UL)

struct fd_rpc_tile {
  int delay_startup;
  int waker_rearm_pending;

  fd_http_server_t * http;

  ulong * ws_subscribers_vote;
  ulong   ws_subscribers_vote_cnt;
  ulong * ws_subscribers_slot;
  ulong   ws_subscribers_slot_cnt;

  /* Identical subscriptions share one subscription id while any
     subscriber remains, and new subscriptions draw ids from a single
     incrementing counter. */
  ulong   ws_sub_id_vote;
  ulong   ws_sub_id_slot;

  /* signatureSubscribe: one entry per pending subscription.  An entry
     is dropped once its notification has gone out, when it is
     unsubscribed, or when its connection closes.  If the table is
     full the oldest entry is replaced. */
# define FD_RPC_WS_SIG_SUB_MAX (256UL)
  struct {
    ulong sub_id;   /* subscription id plus one, 0 if unused */
    ulong ws_conn_id;
    int   level;    /* 0 processed, 1 confirmed, 2 finalized */
    uchar sig[ 64 ];
  } ws_sig_subs[ FD_RPC_WS_SIG_SUB_MAX ];
  ulong ws_sig_sub_cnt;

  /* accountSubscribe: the account is re-read whenever the subscribed
     commitment level moves and a notification goes out if it changed. */
# define FD_RPC_WS_ACCT_SUB_MAX (256UL)
  struct {
    ulong sub_id;   /* subscription id plus one, 0 if unused */
    ulong ws_conn_id;
    int   level;    /* 0 processed, 1 confirmed, 2 finalized */
    int   primed;   /* last_hash is valid */
    ulong last_hash;
    uchar pubkey[ 32 ];
    char  encoding[ 16 ];
  } ws_acct_subs[ FD_RPC_WS_ACCT_SUB_MAX ];
  ulong ws_acct_sub_cnt;
  ulong   ws_sub_id_next;

  fd_rpc_cluster_node_dlist_t * cluster_nodes_dlist;
  fd_rpc_cluster_node_t cluster_nodes[ FD_CONTACT_INFO_TABLE_SIZE ];

  bank_info_t * banks;
  ulong         max_live_slots;

  fd_accdb_t * accdb;

  ulong cluster_confirmed_slot;

  /* Highest slot relayed to turbine (Agave MaxSlots::retransmit),
     one fseq per shred tile, written by shred */
  ulong         shred_rtx_cnt;
  ulong const * shred_rtx[ FD_TOPO_MAX_TILES ];

  /* Address of the account holding the alpenglow genesis certificate,
     for getAgGenesisCert. */
  fd_pubkey_t fd_genesis_cert_addr[ 1 ];

  ulong processed_idx;
  ulong confirmed_idx;
  ulong finalized_idx;

  int has_genesis_hash;
  fd_hash_t genesis_hash[ 1 ];

  ulong genesis_tar_bz_sz;
  ulong genesis_max_message_size;
  ulong genesis_tar_max_sz;
  ulong genesis_tar_bz_max_sz;
  uchar * genesis_tar;
  uchar * genesis_tar_bz;

  fd_alloc_t * bz2_alloc;

  fd_clock_tile_t clock[1];
  ulong in_cnt;
  ulong idle_cnt;

  ulong   waker_client_idx;
  ulong * waker_fseq;

  fd_keyswitch_t * keyswitch;
  uchar identity_pubkey[ 32UL ];

  int in_kind[ 64UL ];
  fd_rpc_in_t in[ 64UL ];

  fd_rpc_out_t replay_out[1];

  fd_histf_t request_duration[ 1 ];

  fd_multi_epoch_leaders_t mleaders[ FD_RPC_MLEADERS_CNT ];
  fd_epoch_schedule_t      epoch_schedule;
  int                      has_epoch_schedule;

  fd_rpc_vote_set_t         vote_sets[ FD_RPC_VOTE_SET_CNT ];
  fd_rpc_vote_info_t        vote_infos[ 2UL*MAX_STAKE_WEIGHTS ];
  ulong                     vote_infos_cnt;
  int                       vote_infos_valid;
  int                       vote_infos_has_nxt;
  ulong                     vote_infos_slot;
  uchar                     vote_infos_block_hash[ 32 ];
  fd_vote_state_versioned_t vote_state[ 1 ];

  fd_rpc_block_production_table_t block_production[ 1 ];
  fd_rpc_block_production_table_t block_production_epoch[ 1 ];
  ulong                           block_production_epoch_first_slot;
  ulong                           block_production_epoch_next_slot;

  ulong                highest_replayed_slot;
  int                  perf_sample_has_snapshot;
  long                 perf_sample_last_ns;
  ulong                perf_sample_last_txn_cnt;
  ulong                perf_sample_last_slot;
  ulong                perf_sample_cnt;
  fd_rpc_perf_sample_t perf_samples[ FD_RPC_PERF_SAMPLE_MAX ];

  long                genesis_creation_time;
  ulong               block_time_first_slot;
  ulong               block_time_newest_slot;
  fd_rpc_block_time_t block_times[ FD_RPC_BLOCK_TIME_MAX ];

  ulong prio_fee_slots[ FD_RPC_PRIO_FEE_CNT ]; /* blocks with non-vote txns and no priority fees */
  ulong prio_fee_cnt;
  ulong prio_fee_next;
  ulong ns_per_slot;                           /* from the latest epoch message, 0 if none */
  uchar scan_keys[ FD_RPC_SCAN_KEYS_MAX*32UL ]; /* account scan batch */

  /* Snapshots on disk, from the snapshot writer's found/created/deleted
     messages.  base is ULONG_MAX for a full snapshot. */
# define FD_RPC_SNAP_MAX (64UL)
  struct { ulong slot; ulong base; } snaps[ FD_RPC_SNAP_MAX ];
  ulong                 snap_cnt;
  uchar const *         encode_key;                           /* address of the account being encoded, NULL if unknown (jsonParsed sysvars) */
  fd_rpc_sim_t *        sim;                                  /* simulateTransaction runtime, NULL if unavailable */
  fd_features_t         features;                             /* from the latest epoch message */
  int                   has_features;
  int                   udp_fd;                               /* sendTransaction socket, -1 if none */
  fd_sha512_t           sha[ 1 ];
  fd_rpc_send_pending_t send_pending[ FD_RPC_SEND_PENDING_MAX ];
  ulong                 send_datagram_cnt;                    /* datagrams handed to the kernel */

  /* Logs, inner instructions and return data of landed transactions,
     as the exec tiles report them.  A byte ring of variable size
     entries (fd_rpc_meta_ent_t followed by the inner trace, the log
     buffer and the return data; an entry never wraps) and a table from
     signature to the entry's absolute offset plus one.  An entry is
     gone once the ring has written RING_SZ bytes past its start. */
# define FD_RPC_META_RING_SZ   (1UL<<28)
# define FD_RPC_META_TABLE_CNT (1UL<<18)
  uchar *              meta_ring;      /* NULL if the memory could not be reserved */
  ulong                meta_head;      /* absolute offset of the next entry */
  ulong                meta_table[ FD_RPC_META_TABLE_CNT ];
  fd_execrp_txn_meta_t meta_msg[ 1 ];  /* copy of the frag being ingested */

  /* Epoch rewards, for getInflationReward.  See fd_rpc_reward_ingest. */
  fd_rpc_reward_epoch_t reward_epochs[ FD_RPC_REWARD_EPOCH_CNT ];
  ulong                 reward_seq_next;   /* next expected record index, ULONG_MAX before the first batch */
  ulong                 reward_dropped;    /* replay's drop count as of the last batch */
  ulong                 reward_boot_slot;  /* first slot this tile saw complete, ULONG_MAX if none */
  fd_replay_rewards_t   reward_msg[ 1 ];   /* copy of the batch being ingested */

  ulong               txn_rec_next;                           /* total transactions recorded; ring position is % CNT */
  fd_rpc_txn_rec_t    txn_recs[ FD_RPC_TXN_REC_CNT ];
  ulong               txn_table[ FD_RPC_TXN_TABLE_CNT ];      /* 1 + recording sequence number, 0 if never used */
  fd_rpc_block_meta_t block_metas[ FD_RPC_BLOCK_META_CNT ];
  fd_rpc_block_txn_t  block_txns[ FD_RPC_BLOCK_TXN_MAX ];     /* getBlock scratch */
  fd_frag_meta_t const * in_mcache[ 64UL ];
  ulong                  in_depth [ 64UL ];

  ZSTD_CCtx * zstd_cctx;
  uchar compress_buf[ ZSTD_COMPRESSBOUND( FD_RUNTIME_ACC_SZ_MAX ) ];

  /* Redirect to snapshot server */
  int    snapshot_server_enabled;
  char   snapshot_server_url[ FD_URL_MAX ];

  union {
    /* Scratch used by getLeaderSchedule to group the epoch's leader
       schedule by identity. */
    fd_rpc_gls_pair_t gls_pairs[ (MAX_SLOTS_PER_EPOCH + FD_EPOCH_SLOTS_PER_ROTATION - 1UL) / FD_EPOCH_SLOTS_PER_ROTATION ];

    /* Scratch buffer for fd_accdb_read_one_nocache: holds the account
       data bytes returned by the readonly accdb path.  Sized to the
       runtime account data maximum.  Must not be in accdb shmem. */
    uchar accdb_data_buf[ FD_RUNTIME_ACC_SZ_MAX ];
  } scratch;
};

typedef struct fd_rpc_tile fd_rpc_tile_t;

static void
fd_rpc_vote_sets_ingest( fd_rpc_tile_t *             ctx,
                         fd_epoch_info_msg_t const * msg ) {
  FD_TEST( msg->staked_vote_cnt<=MAX_STAKE_WEIGHTS );
  fd_rpc_vote_set_t *            set = &ctx->vote_sets[ msg->epoch % FD_RPC_VOTE_SET_CNT ];
  fd_vote_stake_weight_t const * w   = fd_epoch_info_msg_stake_weights( msg );
  set->epoch = msg->epoch;
  set->cnt   = msg->staked_vote_cnt;
  for( ulong i=0UL; i<set->cnt; i++ ) {
    set->ele[ i ].vote_key = w[ i ].vote_key;
    set->ele[ i ].stake    = w[ i ].stake;
  }
  fd_rpc_vote_set_sort_inplace( set->ele, set->cnt );
}

static void
fd_rpc_block_time_record( fd_rpc_tile_t *    ctx,
                          ulong              slot,
                          fd_accdb_fork_id_t accdb_fork_id ) {
  ulong lamports;
  int   executable;
  uchar owner[ 32UL ];
  ulong data_sz;
  fd_accdb_read_one_nocache( ctx->accdb, accdb_fork_id, fd_sysvar_clock_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_sz );
  if( FD_UNLIKELY( !lamports || data_sz<40UL ) ) return;

  fd_rpc_block_time_t * entry = &ctx->block_times[ slot % FD_RPC_BLOCK_TIME_MAX ];
  entry->slot           = slot;
  entry->unix_timestamp = FD_LOAD( long, ctx->scratch.accdb_data_buf+32UL );
  ctx->block_time_first_slot  = fd_ulong_min( ctx->block_time_first_slot,  slot );
  ctx->block_time_newest_slot = fd_ulong_max( ctx->block_time_newest_slot, slot );
}

static fd_rpc_block_time_t const *
fd_rpc_block_time_query( fd_rpc_tile_t const * ctx,
                         ulong                 slot ) {
  fd_rpc_block_time_t const * entry = &ctx->block_times[ slot % FD_RPC_BLOCK_TIME_MAX ];
  return entry->slot==slot ? entry : NULL;
}

static ulong
fd_rpc_block_time_first_available( fd_rpc_tile_t const * ctx ) {
  if( FD_UNLIKELY( ctx->block_time_first_slot==ULONG_MAX ) ) return 0UL;
  return fd_ulong_max( ctx->block_time_first_slot, fd_ulong_sat_sub( ctx->block_time_newest_slot, FD_RPC_BLOCK_TIME_MAX-1UL ) );
}

static void
fd_rpc_perf_sample_poll( fd_rpc_tile_t * ctx,
                         long            now ) {
  if( FD_UNLIKELY( ctx->finalized_idx==ULONG_MAX ) ) return;
  ulong txn_cnt = ctx->banks[ ctx->finalized_idx ].transaction_count;
  ulong slot    = ctx->highest_replayed_slot;

  if( FD_UNLIKELY( !ctx->perf_sample_has_snapshot ) ) {
    ctx->perf_sample_has_snapshot = 1;
    ctx->perf_sample_last_ns      = now;
    ctx->perf_sample_last_txn_cnt = txn_cnt;
    ctx->perf_sample_last_slot    = slot;
    return;
  }

  long elapsed = now - ctx->perf_sample_last_ns;
  if( FD_LIKELY( elapsed<FD_RPC_PERF_SAMPLE_INTERVAL ) ) return;

  fd_rpc_perf_sample_t * sample = &ctx->perf_samples[ ctx->perf_sample_cnt % FD_RPC_PERF_SAMPLE_MAX ];
  sample->slot               = slot;
  sample->num_transactions   = fd_ulong_sat_sub( txn_cnt, ctx->perf_sample_last_txn_cnt );
  sample->num_slots          = fd_ulong_sat_sub( slot,    ctx->perf_sample_last_slot    );
  sample->sample_period_secs = (ushort)( elapsed/1000000000L );
  ctx->perf_sample_cnt++;

  ctx->perf_sample_last_ns      = now;
  ctx->perf_sample_last_txn_cnt = txn_cnt;
  ctx->perf_sample_last_slot    = slot;
}

static fd_rpc_vote_set_t const *
fd_rpc_vote_set_query( fd_rpc_tile_t const * ctx,
                       ulong                 epoch ) {
  fd_rpc_vote_set_t const * set = &ctx->vote_sets[ epoch % FD_RPC_VOTE_SET_CNT ];
  return set->epoch==epoch ? set : NULL;
}

static void
fd_rpc_ws_subscriber_vote_add( fd_rpc_tile_t * ctx,
                               ulong           ws_conn_id ) {
  for( ulong i=0UL; i<ctx->ws_subscribers_vote_cnt; i++ )
    if( FD_UNLIKELY( ctx->ws_subscribers_vote[ i ]==ws_conn_id ) ) return;

  FD_TEST( ctx->ws_subscribers_vote_cnt<ctx->http->max_ws_conns );
  if( FD_UNLIKELY( !ctx->ws_subscribers_vote_cnt ) ) ctx->ws_sub_id_vote = ctx->ws_sub_id_next++;
  ctx->ws_subscribers_vote[ ctx->ws_subscribers_vote_cnt++ ] = ws_conn_id;
}

static int
fd_rpc_ws_subscriber_vote_remove( fd_rpc_tile_t * ctx,
                                  ulong           ws_conn_id ) {
  for( ulong idx=0UL; idx<ctx->ws_subscribers_vote_cnt; idx++ ) {
    if( FD_LIKELY( ctx->ws_subscribers_vote[ idx ]!=ws_conn_id ) ) continue;

    ctx->ws_subscribers_vote_cnt--;
    ctx->ws_subscribers_vote[ idx ] = ctx->ws_subscribers_vote[ ctx->ws_subscribers_vote_cnt ];
    return 1;
  }

  return 0;
}

static void
fd_rpc_ws_subscriber_slot_add( fd_rpc_tile_t * ctx,
                               ulong           ws_conn_id ) {
  for( ulong i=0UL; i<ctx->ws_subscribers_slot_cnt; i++ )
    if( FD_UNLIKELY( ctx->ws_subscribers_slot[ i ]==ws_conn_id ) ) return;

  FD_TEST( ctx->ws_subscribers_slot_cnt<ctx->http->max_ws_conns );
  if( FD_UNLIKELY( !ctx->ws_subscribers_slot_cnt ) ) ctx->ws_sub_id_slot = ctx->ws_sub_id_next++;
  ctx->ws_subscribers_slot[ ctx->ws_subscribers_slot_cnt++ ] = ws_conn_id;
}

static int
fd_rpc_ws_subscriber_slot_remove( fd_rpc_tile_t * ctx,
                                  ulong           ws_conn_id ) {
  for( ulong idx=0UL; idx<ctx->ws_subscribers_slot_cnt; idx++ ) {
    if( FD_LIKELY( ctx->ws_subscribers_slot[ idx ]!=ws_conn_id ) ) continue;

    ctx->ws_subscribers_slot_cnt--;
    ctx->ws_subscribers_slot[ idx ] = ctx->ws_subscribers_slot[ ctx->ws_subscribers_slot_cnt ];
    return 1;
  }

  return 0;
}

/* fd_rpc_ws_unsubscribe removes the subscription with id sub_id from
   connection ws_conn_id, whatever its type.  Returns 1 if a
   subscription was removed, 0 if the connection has no subscription
   with that id.

   Agave keeps all subscriptions of a connection in one map keyed by id
   and every *Unsubscribe method removes from that map without checking
   the subscription type.  This is a bug in Agave, we replicate it for
   conformance. */

static int
fd_rpc_ws_unsubscribe( fd_rpc_tile_t * ctx,
                       ulong           sub_id,
                       ulong           ws_conn_id ) {
  if( sub_id==ctx->ws_sub_id_slot && fd_rpc_ws_subscriber_slot_remove( ctx, ws_conn_id ) ) return 1;
  if( sub_id==ctx->ws_sub_id_vote && fd_rpc_ws_subscriber_vote_remove( ctx, ws_conn_id ) ) return 1;
  for( ulong i=0UL; i<FD_RPC_WS_SIG_SUB_MAX; i++ ) {
    if( ctx->ws_sig_subs[ i ].sub_id!=sub_id+1UL || ctx->ws_sig_subs[ i ].ws_conn_id!=ws_conn_id ) continue;
    ctx->ws_sig_subs[ i ].sub_id = 0UL;
    ctx->ws_sig_sub_cnt--;
    return 1;
  }
  for( ulong i=0UL; i<FD_RPC_WS_ACCT_SUB_MAX; i++ ) {
    if( ctx->ws_acct_subs[ i ].sub_id!=sub_id+1UL || ctx->ws_acct_subs[ i ].ws_conn_id!=ws_conn_id ) continue;
    ctx->ws_acct_subs[ i ].sub_id = 0UL;
    ctx->ws_acct_sub_cnt--;
    return 1;
  }
  return 0;
}

static void *
bz2_malloc( void * opaque,
            int    items,
            int    size ) {
  fd_alloc_t * alloc = (fd_alloc_t *)opaque;

  if( FD_UNLIKELY( items<=0 || size<=0 ) ) {
    FD_LOG_WARNING(( "bz2_malloc: invalid items=%d or size=%d", items, size ));
    return NULL;
  }
  void * result = fd_alloc_malloc( alloc, alignof(max_align_t), (ulong)items*(ulong)size );
  if( FD_UNLIKELY( !result ) ) return NULL;
  return result;
}

static void
bz2_free( void * opaque,
          void * addr ) {
  fd_alloc_t * alloc = (fd_alloc_t *)opaque;

  if( FD_UNLIKELY( !addr ) ) return;
  fd_alloc_free( alloc, addr );
}

static inline ulong
fd_rpc_file_as_tarball( fd_rpc_tile_t * ctx,
                        char const *    filename_cstr,
                        uchar const *   data,
                        ulong           data_sz,
                        uchar *         scratch,
                        ulong           scratch_sz,
                        uchar *         out,
                        ulong           out_sz ) {
  ulong padding_sz = 2UL*FD_TAR_BLOCK_SZ;
  if( FD_LIKELY( data_sz % FD_TAR_BLOCK_SZ ) ) padding_sz += FD_TAR_BLOCK_SZ - (data_sz % FD_TAR_BLOCK_SZ);

  if( FD_UNLIKELY( data_sz>ctx->genesis_max_message_size ) ) {
    FD_LOG_ERR(( "Genesis data exceeds maximum size (data_sz=%lu max=%lu)", data_sz, ctx->genesis_max_message_size ));
  }
  ulong tar_sz = sizeof(fd_tar_meta_t) + data_sz + padding_sz;
  if( FD_UNLIKELY( tar_sz>scratch_sz ) ) {
    FD_LOG_WARNING(( "tar_sz exceeds scratch_sz (tar_sz=%lu scratch_sz=%lu)", tar_sz, scratch_sz ));
    return ULONG_MAX;
  }

  fd_tar_meta_init_file_default( (fd_tar_meta_t *)scratch, filename_cstr, data_sz, fd_log_wallclock() );
  fd_memcpy( scratch+sizeof(fd_tar_meta_t), data, data_sz );
  memset( scratch+sizeof(fd_tar_meta_t)+data_sz, 0, padding_sz );

  /* NOTE: Agave's genesis.tar also contains a `rocksdb` folder */

  bz_stream bzstrm = {0};
  bzstrm.bzalloc = bz2_malloc;
  bzstrm.bzfree  = bz2_free;
  bzstrm.opaque  = ctx->bz2_alloc;
  int bzerr = BZ2_bzCompressInit( &bzstrm, 1, 0, 0 );
  if( FD_UNLIKELY( BZ_OK!=bzerr ) ) FD_LOG_ERR(( "BZ2_bzCompressInit() failed (%d)", bzerr ));

  ulong tar_bz_sz = out_sz;

  bzstrm.next_in   = (char *)scratch;
  bzstrm.avail_in  = (uint)tar_sz;
  bzstrm.next_out  = (char *)out;
  bzstrm.avail_out = (uint)tar_bz_sz;

  for(;;) {
    bzerr = BZ2_bzCompress( &bzstrm, BZ_FINISH );
    if( FD_LIKELY( bzerr==BZ_STREAM_END ) ) break;
    if( FD_UNLIKELY( bzerr>=0 ) ) continue;
    FD_LOG_ERR(( "BZ2_bzCompress(_, BZ_FINISH) failed (%d)", bzerr ));
  }

  tar_bz_sz -= (ulong)bzstrm.avail_out;

  bzerr = BZ2_bzCompressEnd( &bzstrm );
  if( FD_UNLIKELY( BZ_OK!=bzerr ) ) FD_LOG_ERR(( "BZ2_bzCompressEnd() failed (%d)", bzerr ));

  return tar_bz_sz;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof( fd_rpc_tile_t );
  a = fd_ulong_max( a, fd_http_server_align() );
  a = fd_ulong_max( a, fd_alloc_align() );
  a = fd_ulong_max( a, alignof(bank_info_t) );
  a = fd_ulong_max( a, fd_rpc_cluster_node_dlist_align() );
  a = fd_ulong_max( a, fd_accdb_align() );
  return a;
}

FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Leftover space for bzip2 allocations */
  return 1UL<<26; /* 64 MiB */
}

static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_http_server_params_t http_params = derive_http_params( tile );
  ulong http_fp = fd_http_server_footprint( http_params );
  if( FD_UNLIKELY( !http_fp ) ) FD_LOG_ERR(( "Invalid [tiles.rpc] config parameters" ));

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rpc_tile_t),            sizeof(fd_rpc_tile_t)                                              );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),            http_fp                                                            );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),                  fd_alloc_footprint()                                               );
  l = FD_LAYOUT_APPEND( l, alignof(bank_info_t),              tile->rpc.max_live_slots*sizeof(bank_info_t)                       );
  l = FD_LAYOUT_APPEND( l, fd_rpc_cluster_node_dlist_align(), fd_rpc_cluster_node_dlist_footprint()                              );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),                  fd_accdb_footprint( tile->rpc.max_live_slots, 0 )                     );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                    http_params.max_ws_connection_cnt*sizeof(ulong)                    );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                    http_params.max_ws_connection_cnt*sizeof(ulong)                    );
  l = FD_LAYOUT_APPEND( l, alignof(uchar),                    fd_rpc_genesis_tar_max_sz( tile->rpc.genesis_max_message_size )    );
  l = FD_LAYOUT_APPEND( l, alignof(uchar),                    fd_rpc_genesis_tar_bz_max_sz( tile->rpc.genesis_max_message_size ) );
  l = FD_LAYOUT_APPEND( l, 16UL, ZSTD_estimateCCtxSize( FD_RPC_ZSTD_LEVEL ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_rpc_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) {
    fd_clock_tile_recal( ctx->clock );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->identity_pubkey, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  fd_rpc_perf_sample_poll( ctx, fd_clock_tile_now( ctx->clock ) );
}

static inline void
metrics_write( fd_rpc_tile_t * ctx ) {
  FD_MHIST_COPY( RPC, REQUEST_DURATION_NANOS,             ctx->request_duration                );
  FD_MGAUGE_SET( RPC, CONN_OPEN,                          ctx->http->metrics.connection_cnt    );
  FD_MGAUGE_SET( RPC, WEBSOCKET_CONN_OPEN,                ctx->http->metrics.ws_connection_cnt );
  FD_MGAUGE_SET( RPC, WEBSOCKET_SUBSCRIBER_COUNT_VOTE,    ctx->ws_subscribers_vote_cnt         );
  FD_MGAUGE_SET( RPC, WEBSOCKET_SUBSCRIBER_COUNT_SLOT,    ctx->ws_subscribers_slot_cnt         );
  FD_ACCDB_METRICS_WRITE_RO( RPC, fd_accdb_metrics( ctx->accdb ) );
}

static void
before_credit( fd_rpc_tile_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt<2UL*ctx->in_cnt ) ) return;
  ctx->idle_cnt = 0UL;

  int replay_ready = ctx->confirmed_idx!=ULONG_MAX && ctx->processed_idx!=ULONG_MAX && ctx->finalized_idx!=ULONG_MAX;
  if( FD_UNLIKELY( ctx->delay_startup && !replay_ready ) ) {
    /* Consume readiness so an early connection does not veto every
       park, but do not rearm: the listen fd stays readable and would
       refire on every pass. */
    if( FD_UNLIKELY( fd_fseq_query( ctx->waker_fseq )==1UL ) ) {
      fd_fseq_update( ctx->waker_fseq, 0UL );
      ctx->waker_rearm_pending = 1;
    }
    return;
  }

  if( FD_UNLIKELY( ctx->waker_rearm_pending ) ) {
    ctx->waker_rearm_pending = 0;
    fd_waker_client_rearm( ctx->waker_client_idx );
  }

  if( FD_UNLIKELY( fd_fseq_query( ctx->waker_fseq )==1UL ) ) {
    fd_fseq_update( ctx->waker_fseq, 0UL );
    *charge_busy = fd_http_server_epoll_poll( ctx->http, 1UL );
    fd_waker_client_rearm( ctx->waker_client_idx );
  }
}

static int
before_frag( fd_rpc_tile_t *   ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig ) {
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP_OUT ) ) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO &&
           sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE;
  }

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) ) {
    return sig!=REPLAY_SIG_SLOT_COMPLETED && sig!=REPLAY_SIG_OC_ADVANCED &&
           sig!=REPLAY_SIG_ROOT_ADVANCED  && sig!=REPLAY_SIG_DROP_BANK_REF;
  }

  if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_TXN ) return sig!=REPLAY_SIG_TXN_EXECUTED && sig!=REPLAY_SIG_REWARDS;
  if( ctx->in_kind[ in_idx ]==IN_KIND_SNAPMK ) return sig!=FD_SNAPMK_MSG_FOUND && sig!=FD_SNAPMK_MSG_CREATED && sig!=FD_SNAPMK_MSG_DELETED;

  if( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) return sig!=FD_VOTOR_SIG_CERTED;

  return 0;
}

static void
fd_rpc_publish_slot_event( fd_rpc_tile_t *                    ctx,
                           fd_replay_slot_completed_t const * slot_completed ) {
  if( FD_UNLIKELY( !ctx->ws_subscribers_slot_cnt ) ) return;

  ulong sent_cnt = 0UL;
  for( ulong i=0UL; i<ctx->ws_subscribers_slot_cnt; ) {
    ulong ws_conn_id = ctx->ws_subscribers_slot[ i ];
    fd_http_server_printf( ctx->http,
                           "{\"jsonrpc\":\"2.0\",\"method\":\"slotNotification\",\"params\":{\"subscription\":%lu,\"result\":{\"parent\":%lu,\"root\":%lu,\"slot\":%lu}}}\n",
                           ctx->ws_sub_id_slot,
                           slot_completed->parent_slot,
                           slot_completed->root_slot,
                           slot_completed->slot );

    if( FD_UNLIKELY( fd_http_server_ws_send( ctx->http, ws_conn_id ) ) ) {
      fd_rpc_ws_subscriber_slot_remove( ctx, ws_conn_id );
      fd_http_server_ws_close( ctx->http, ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_TOO_SLOW );
      continue;
    }
    if( FD_UNLIKELY( i>=ctx->ws_subscribers_slot_cnt || ctx->ws_subscribers_slot[ i ]!=ws_conn_id ) ) continue;
    sent_cnt++;
    i++;
  }

  FD_MCNT_INC( RPC, WEBSOCKET_NOTIFICATION_PUBLISHED_SLOT, !!sent_cnt );
  FD_MCNT_INC( RPC, WEBSOCKET_NOTIFICATION_TX_SLOT,          sent_cnt );
}

static inline void
fd_rpc_cluster_finalized( fd_rpc_tile_t * ctx,
                          ulong           slot ) {
  ctx->cluster_confirmed_slot = ctx->cluster_confirmed_slot==ULONG_MAX ? slot : fd_ulong_max( ctx->cluster_confirmed_slot, slot );
}

/* Signature -> ring position.  A table entry holds 1 + the recording
   sequence number of a transaction; it is stale once the ring has
   wrapped past that number. */
static inline int
fd_rpc_txn_seq_live( fd_rpc_tile_t const * ctx,
                     ulong                 entry ) {
  return entry && (entry-1UL)+FD_RPC_TXN_REC_CNT>=ctx->txn_rec_next;
}

/* fd_rpc_txn_commit publishes the record the caller just filled in at
   ring position txn_rec_next. */
static void
fd_rpc_meta_ingest( fd_rpc_tile_t *              ctx,
                    fd_execrp_txn_meta_t const * msg,
                    ulong                        msg_sz ) {
  if( FD_UNLIKELY( !ctx->meta_ring ) ) return;
  ulong log_sz = msg->log_sz, inner_sz = msg->inner_sz, return_sz = msg->has_return ? msg->return_sz : 0UL;
  if( FD_UNLIKELY( inner_sz>FD_EXECRP_TXN_META_INNER_MAX || return_sz>FD_EXECRP_TXN_META_RETURN_MAX ||
                   log_sz>FD_EXECRP_TXN_META_LOG_MAX || offsetof( fd_execrp_txn_meta_t, log )+log_sz>msg_sz ) ) return;
  ulong ent_sz = fd_ulong_align_up( sizeof(fd_rpc_meta_ent_t)+inner_sz+log_sz+return_sz, 8UL );
  ulong pos    = ctx->meta_head & (FD_RPC_META_RING_SZ-1UL);
  if( FD_UNLIKELY( pos+ent_sz>FD_RPC_META_RING_SZ ) ) { ctx->meta_head += FD_RPC_META_RING_SZ-pos; pos = 0UL; }
  fd_rpc_meta_ent_t * ent = (fd_rpc_meta_ent_t *)( ctx->meta_ring+pos );
  memcpy( ent->sig, msg->sig, 64UL );
  ent->slot            = msg->slot;
  ent->log_sz          = (uint)log_sz;
  ent->inner_sz        = (uint)inner_sz;
  ent->return_sz       = (uint)return_sz;
  ent->has_return      = msg->has_return;
  ent->inner_truncated = msg->inner_truncated;
  ent->has_token       = msg->has_token;
  ent->has_cu          = msg->has_cu;
  ent->cu_consumed     = msg->cu_consumed;
  memcpy( ent->return_program, msg->return_program, 32UL );
  uchar * body = (uchar *)( ent+1 );
  memcpy( body,                 msg->inner,       inner_sz  );
  memcpy( body+inner_sz,        msg->log,         log_sz    );
  memcpy( body+inner_sz+log_sz, msg->return_data, return_sz );

  /* Index it: the signature's own slot if there is one, else a free or
     expired slot nearby, else the home slot. */
  ulong home = fd_ulong_hash( fd_ulong_load_8( msg->sig ) ^ fd_ulong_load_8( msg->sig+8UL ) ) & (FD_RPC_META_TABLE_CNT-1UL);
  ulong pick = home; int found = 0;
  for( ulong k=0UL; k<8UL && !found; k++ ) {
    ulong idx = (home+k) & (FD_RPC_META_TABLE_CNT-1UL);
    ulong off = ctx->meta_table[ idx ];
    if( !off || off-1UL+FD_RPC_META_RING_SZ<ctx->meta_head ) { pick = idx; found = 1; }
    else if( !memcmp( ctx->meta_ring+((off-1UL)&(FD_RPC_META_RING_SZ-1UL)), msg->sig, 64UL ) ) { pick = idx; found = 1; }
  }
  ctx->meta_table[ pick ] = ctx->meta_head+1UL;
  ctx->meta_head += ent_sz;
}

/* fd_rpc_meta_query returns what the exec tiles reported for the
   transaction with this signature, or NULL if nothing is kept. */
static fd_rpc_meta_ent_t const *
fd_rpc_meta_query( fd_rpc_tile_t const * ctx,
                   uchar const *         sig ) {
  if( FD_UNLIKELY( !ctx->meta_ring ) ) return NULL;
  ulong home = fd_ulong_hash( fd_ulong_load_8( sig ) ^ fd_ulong_load_8( sig+8UL ) ) & (FD_RPC_META_TABLE_CNT-1UL);
  for( ulong k=0UL; k<8UL; k++ ) {
    ulong off = ctx->meta_table[ (home+k) & (FD_RPC_META_TABLE_CNT-1UL) ];
    if( !off || off-1UL+FD_RPC_META_RING_SZ<ctx->meta_head+sizeof(fd_execrp_txn_meta_t) ) continue; /* never used, or (about to be) overwritten */
    fd_rpc_meta_ent_t const * ent = (fd_rpc_meta_ent_t const *)( ctx->meta_ring+((off-1UL)&(FD_RPC_META_RING_SZ-1UL)) );
    if( !memcmp( ent->sig, sig, 64UL ) ) return ent;
  }
  return NULL;
}

/* fd_rpc_reward_table returns the table holding the rewards earned in
   epoch, or NULL.  With create set, the table of the oldest epoch is
   recycled if there is none yet. */
static fd_rpc_reward_epoch_t *
fd_rpc_reward_table( fd_rpc_tile_t * ctx,
                     ulong           epoch,
                     int             create ) {
  fd_rpc_reward_epoch_t * oldest = NULL;
  for( ulong i=0UL; i<FD_RPC_REWARD_EPOCH_CNT; i++ ) {
    fd_rpc_reward_epoch_t * t = &ctx->reward_epochs[ i ];
    if( t->epoch==epoch ) return t;
    if( !oldest || t->epoch==ULONG_MAX || ( oldest->epoch!=ULONG_MAX && t->epoch<oldest->epoch ) ) oldest = t;
  }
  if( !create || !oldest->ents ) return NULL;
  if( oldest->epoch!=ULONG_MAX && oldest->epoch>epoch ) return NULL; /* older than everything kept */
  if( oldest->cnt ) memset( oldest->ents, 0, FD_RPC_REWARD_ENT_CNT*sizeof(fd_rpc_reward_ent_t) );
  oldest->epoch   = epoch;
  oldest->cnt     = 0UL;
  oldest->slot_lo = ULONG_MAX;
  oldest->slot_hi = 0UL;
  /* Rewards earned in epoch are paid from the first slot of the next
     one.  If this tile was not up before that, some were missed. */
  ulong pay_slot0 = fd_epoch_slot0( &ctx->epoch_schedule, epoch+1UL );
  oldest->incomplete = !( ctx->reward_boot_slot<pay_slot0 );
  return oldest;
}

/* fd_rpc_reward_gap is called when reward records were lost.  Which
   epoch they belonged to is not known, so every table is marked. */
static void
fd_rpc_reward_gap( fd_rpc_tile_t * ctx ) {
  for( ulong i=0UL; i<FD_RPC_REWARD_EPOCH_CNT; i++ ) ctx->reward_epochs[ i ].incomplete = 1;
  ctx->reward_seq_next = ULONG_MAX;
}

static void
fd_rpc_reward_ingest( fd_rpc_tile_t *             ctx,
                      fd_replay_rewards_t const * msg ) {
  if( FD_UNLIKELY( !ctx->has_epoch_schedule || msg->cnt>FD_REPLAY_REWARDS_BATCH_MAX ) ) { fd_rpc_reward_gap( ctx ); return; }
  if( FD_UNLIKELY( ( ctx->reward_seq_next!=ULONG_MAX && msg->seq!=ctx->reward_seq_next ) || msg->dropped!=ctx->reward_dropped ) ) fd_rpc_reward_gap( ctx );
  ctx->reward_seq_next = msg->seq+msg->cnt;
  ctx->reward_dropped  = msg->dropped;

  for( ulong i=0UL; i<msg->cnt; i++ ) {
    ulong slot = msg->recs[ i ].slot;
    if( FD_UNLIKELY( !slot ) ) continue;
    /* Agave records no reward for a stake account that was paid nothing */
    if( msg->recs[ i ].kind==1U && msg->recs[ i ].lamports_post==msg->recs[ i ].lamports_pre ) continue;
    ulong pay_epoch = fd_slot_to_epoch( &ctx->epoch_schedule, slot, NULL );
    if( FD_UNLIKELY( !pay_epoch ) ) continue;
    fd_rpc_reward_epoch_t * t = fd_rpc_reward_table( ctx, pay_epoch-1UL, 1 );
    if( FD_UNLIKELY( !t ) ) continue;
    t->slot_lo = fd_ulong_min( t->slot_lo, slot );
    t->slot_hi = fd_ulong_max( t->slot_hi, slot );
    if( FD_UNLIKELY( t->cnt>=FD_RPC_REWARD_ENT_MAX ) ) { t->incomplete = 1; continue; }
    ulong idx = fd_ulong_hash( FD_LOAD( ulong, msg->recs[ i ].pubkey ) ^ FD_LOAD( ulong, msg->recs[ i ].pubkey+8UL ) ) & (FD_RPC_REWARD_ENT_CNT-1UL);
    int   dup = 0;
    while( t->ents[ idx ].slot ) {
      if( FD_UNLIKELY( t->ents[ idx ].slot==slot && !memcmp( t->ents[ idx ].pubkey, msg->recs[ i ].pubkey, 32UL ) ) ) { dup = 1; break; }
      idx = (idx+1UL) & (FD_RPC_REWARD_ENT_CNT-1UL);
    }
    if( FD_UNLIKELY( dup ) ) continue;
    memcpy( t->ents[ idx ].pubkey, msg->recs[ i ].pubkey, 32UL );
    t->ents[ idx ].slot         = slot;
    t->ents[ idx ].amount       = msg->recs[ i ].lamports_post-msg->recs[ i ].lamports_pre;
    t->ents[ idx ].post_balance = msg->recs[ i ].lamports_post;
    t->cnt++;
  }
}

static void
fd_rpc_txn_commit( fd_rpc_tile_t * ctx ) {
  ulong seq = ctx->txn_rec_next++;
  uchar const * sig = ctx->txn_recs[ seq % FD_RPC_TXN_REC_CNT ].sig;
  ulong home = fd_ulong_hash( fd_ulong_load_8( sig ) ^ fd_ulong_load_8( sig+8UL ) ) % FD_RPC_TXN_TABLE_CNT;
  ulong pos  = home;
  for( ulong i=0UL; i<FD_RPC_TXN_PROBE_MAX; i++ ) {
    ulong p = (home+i) % FD_RPC_TXN_TABLE_CNT;
    if( !fd_rpc_txn_seq_live( ctx, ctx->txn_table[ p ] ) ) { pos = p; break; }
  }
  ctx->txn_table[ pos ] = seq+1UL;
}

/* Finds the newest recorded transaction with this signature whose slot
   passes on_fork (the same transaction can be executed on more than one
   fork).  Returns NULL if none. */
static fd_rpc_txn_rec_t const *
fd_rpc_txn_query( fd_rpc_tile_t *     ctx,
                  uchar const *       sig,
                  bank_info_t const * tip,
                  ulong               next_slot ); /* defined with the handlers */

/* fd_rpc_ws_sig_check sends the notification of every signature
   subscription whose transaction has reached its commitment level. */
static void
fd_rpc_ws_sig_check( fd_rpc_tile_t * ctx );

/* fd_rpc_ws_acct_check notifies every account subscription whose
   account changed at its commitment level. */
static void
fd_rpc_ws_acct_check( fd_rpc_tile_t * ctx );

/* fd_rpc_send_to_leaders sends a transaction to the TPU UDP port of
   the leaders of the next few rotations starting at from_slot, as
   advertised in gossip.  Returns the number of datagrams sent.  A
   leader that advertises no TPU UDP port (Agave accepts QUIC only) is
   skipped, as is this node itself, which is not in its own gossip
   table. */
static ulong
fd_rpc_send_to_leaders( fd_rpc_tile_t * ctx,
                        uchar const *   payload,
                        ulong           payload_sz,
                        ulong           from_slot ) {
  if( FD_UNLIKELY( ctx->udp_fd<0 ) ) return 0UL;
  ulong               sent = 0UL;
  fd_pubkey_t const * done[ FD_RPC_SEND_LEADER_ROTATIONS ];
  ulong               done_cnt = 0UL;
  for( ulong r=0UL; r<FD_RPC_SEND_LEADER_ROTATIONS; r++ ) {
    fd_pubkey_t const * leader = fd_rpc_mleaders_get_leader_for_slot( ctx->mleaders, from_slot+r*FD_EPOCH_SLOTS_PER_ROTATION );
    if( FD_UNLIKELY( !leader ) ) continue;
    int dup = 0;
    for( ulong k=0UL; k<done_cnt; k++ ) if( !memcmp( done[ k ]->uc, leader->uc, 32UL ) ) dup = 1;
    if( dup ) continue;
    done[ done_cnt++ ] = leader;

    for( fd_rpc_cluster_node_dlist_iter_t iter = fd_rpc_cluster_node_dlist_iter_rev_init( ctx->cluster_nodes_dlist, ctx->cluster_nodes );
         !fd_rpc_cluster_node_dlist_iter_done( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes );
         iter = fd_rpc_cluster_node_dlist_iter_rev_next( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes ) ) {
      fd_rpc_cluster_node_t const * ele = fd_rpc_cluster_node_dlist_iter_ele( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes );
      if( memcmp( ele->identity.uc, leader->uc, 32UL ) ) continue;
      fd_gossip_socket_t const * sock = &ele->ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TPU ];
      if( sock->is_ipv6 || !sock->ip4 || !sock->port ) break;
      struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = sock->port, .sin_addr = { .s_addr = sock->ip4 } };
      if( FD_LIKELY( sendto( ctx->udp_fd, payload, payload_sz, MSG_DONTWAIT|MSG_NOSIGNAL, fd_type_pun_const( &dst ), sizeof(dst) )==(long)payload_sz ) ) {
        sent++;
        ctx->send_datagram_cnt++;
      }
      break;
    }
  }
  return sent;
}

/* Returns 1 if a transaction with this signature is in the recent
   transaction window, on any fork. */
static int
fd_rpc_txn_seen( fd_rpc_tile_t const * ctx,
                 uchar const *         sig ) {
  ulong home = fd_ulong_hash( fd_ulong_load_8( sig ) ^ fd_ulong_load_8( sig+8UL ) ) % FD_RPC_TXN_TABLE_CNT;
  for( ulong i=0UL; i<FD_RPC_TXN_PROBE_MAX; i++ ) {
    ulong entry = ctx->txn_table[ (home+i) % FD_RPC_TXN_TABLE_CNT ];
    if( !entry ) return 0;
    if( !fd_rpc_txn_seq_live( ctx, entry ) ) continue;
    if( !memcmp( ctx->txn_recs[ (entry-1UL) % FD_RPC_TXN_REC_CNT ].sig, sig, 64UL ) ) return 1;
  }
  return 0;
}

/* Called once per leader rotation: sends every pending transaction
   again unless it has landed or expired. */
static void
fd_rpc_send_retry( fd_rpc_tile_t * ctx,
                   ulong           slot ) {
  for( ulong i=0UL; i<FD_RPC_SEND_PENDING_MAX; i++ ) {
    fd_rpc_send_pending_t * p = &ctx->send_pending[ i ];
    if( !p->used ) continue;
    if( slot>p->submit_slot+FD_RPC_SEND_EXPIRE_SLOTS || fd_rpc_txn_seen( ctx, p->sig ) ) { p->used = 0; continue; }
    fd_rpc_send_to_leaders( ctx, p->payload, p->sz, slot+1UL );
  }
}

static void
fd_rpc_block_meta_record( fd_rpc_tile_t *                    ctx,
                          fd_replay_slot_completed_t const * msg ) {
  fd_rpc_block_meta_t * m = &ctx->block_metas[ msg->slot % FD_RPC_BLOCK_META_CNT ];
  m->slot         = msg->slot;
  m->parent_slot  = msg->parent_slot;
  m->block_height = msg->block_height;
  m->txn_cnt      = ( msg->vote_success==ULONG_MAX || msg->vote_failed==ULONG_MAX || msg->nonvote_success==ULONG_MAX || msg->nonvote_failed==ULONG_MAX ) ? ULONG_MAX
                  : msg->vote_success+msg->vote_failed+msg->nonvote_success+msg->nonvote_failed;
  memcpy( m->block_hash, msg->block_hash.uc, 32UL );

  /* Whether any fees were paid: a block without fees has no fee
     reward, which is all that is said about block rewards. */
  m->has_leader = msg->transaction_fee!=ULONG_MAX && msg->priority_fee!=ULONG_MAX;
  m->fee_reward = m->has_leader ? msg->transaction_fee+msg->priority_fee+msg->tips : 0UL;
}

static void
fd_rpc_prio_fee_record( fd_rpc_tile_t *                    ctx,
                        fd_replay_slot_completed_t const * msg ) {
  ulong nonvote = ( msg->nonvote_success!=ULONG_MAX ? msg->nonvote_success : 0UL ) + ( msg->nonvote_failed!=ULONG_MAX ? msg->nonvote_failed : 0UL );
  if( !nonvote || msg->priority_fee ) return;
  ctx->prio_fee_slots[ ctx->prio_fee_next ] = msg->slot;
  ctx->prio_fee_next = (ctx->prio_fee_next+1UL) % FD_RPC_PRIO_FEE_CNT;
  ctx->prio_fee_cnt  = fd_ulong_min( ctx->prio_fee_cnt+1UL, FD_RPC_PRIO_FEE_CNT );
}

static inline int
returnable_frag( fd_rpc_tile_t *     ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz FD_PARAM_UNUSED,
                 ulong               ctl FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {

  ctx->idle_cnt = 0UL;

  if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) {
    switch( sig ) {
      case REPLAY_SIG_SLOT_COMPLETED: {
        fd_replay_slot_completed_t const * slot_completed = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

        FD_TEST( slot_completed->bank_idx<ctx->max_live_slots );
        bank_info_t * bank = &ctx->banks[ slot_completed->bank_idx ];
        if( FD_UNLIKELY( ctx->reward_boot_slot==ULONG_MAX ) ) ctx->reward_boot_slot = slot_completed->slot;
        bank->slot = slot_completed->slot;
        bank->accdb_fork_id = slot_completed->accdb_fork_id;
        bank->epoch = slot_completed->epoch;
        bank->slot_in_epoch = slot_completed->slot_in_epoch;
        bank->slots_per_epoch = slot_completed->slots_per_epoch;
        bank->transaction_count = slot_completed->transaction_count;
        ctx->highest_replayed_slot = fd_ulong_max( ctx->highest_replayed_slot, slot_completed->slot );
        fd_rpc_block_time_record( ctx, slot_completed->slot, slot_completed->accdb_fork_id );
        fd_rpc_prio_fee_record( ctx, slot_completed );
        fd_rpc_block_meta_record( ctx, slot_completed );
        if( FD_UNLIKELY( !(slot_completed->slot % FD_EPOCH_SLOTS_PER_ROTATION) ) ) fd_rpc_send_retry( ctx, slot_completed->slot );
        bank->block_height = slot_completed->block_height;
        fd_memcpy( bank->block_hash, slot_completed->block_hash.uc, 32 );

        bank->inflation.initial         = slot_completed->inflation.initial;
        bank->inflation.terminal        = slot_completed->inflation.terminal;
        bank->inflation.taper           = slot_completed->inflation.taper;
        bank->inflation.foundation      = slot_completed->inflation.foundation;
        bank->inflation.foundation_term = slot_completed->inflation.foundation_term;

        bank->rent.lamports_per_uint8_year = slot_completed->rent.lamports_per_uint8_year;
        bank->rent.exemption_threshold     = slot_completed->rent.exemption_threshold;
        bank->rent.burn_percent            = slot_completed->rent.burn_percent;

        fd_rpc_publish_slot_event( ctx, slot_completed );

        /* In Agave, "processed" confirmation is the bank we've just
           voted for (handle_votable_bank), which is also guaranteed to
           have been replayed.

           Right now tower is not really built out to replicate this
           exactly, so we use the latest replayed slot, which is
           slightly more eager than Agave but shouldn't really affect
           end-users, since any use-cases that assume "processed" means
           "voted-for" would fail in Agave in cases where a cast vote
           does not land.

           Due to bank eviction semantics, it is possible that the RPC
           can return data about a slot that is not the most recently
           replayed slot (since slots can be re-replayed).

           tldr: This isn't strictly conformant with Agave, but doesn't
           need to be since Agave doesn't provide any guarantees
           anyways. */
        if( FD_LIKELY( ctx->processed_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->processed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->processed_idx = slot_completed->bank_idx;
        if( FD_UNLIKELY( ctx->ws_sig_sub_cnt ) ) fd_rpc_ws_sig_check( ctx );
        if( FD_UNLIKELY( ctx->ws_acct_sub_cnt ) ) fd_rpc_ws_acct_check( ctx );
        break;
      }
      case REPLAY_SIG_OC_ADVANCED: {
        fd_replay_oc_advanced_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        if( FD_LIKELY( ctx->confirmed_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->confirmed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        FD_TEST( msg->bank_idx<ctx->max_live_slots );
        ctx->confirmed_idx = msg->bank_idx;
        if( FD_UNLIKELY( ctx->ws_sig_sub_cnt ) ) fd_rpc_ws_sig_check( ctx );
        if( FD_UNLIKELY( ctx->ws_acct_sub_cnt ) ) fd_rpc_ws_acct_check( ctx );
        break;
      }
      case REPLAY_SIG_ROOT_ADVANCED: {
        fd_replay_root_advanced_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        if( FD_LIKELY( ctx->finalized_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->finalized_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        FD_TEST( msg->bank_idx<ctx->max_live_slots );
        ctx->finalized_idx = msg->bank_idx;

        if( FD_LIKELY( ctx->confirmed_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, ctx->confirmed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        ctx->confirmed_idx = msg->bank_idx;

        if( FD_LIKELY( ctx->cluster_confirmed_slot!=ULONG_MAX ) ) fd_rpc_cluster_finalized( ctx, msg->slot );
        if( FD_UNLIKELY( ctx->ws_sig_sub_cnt ) ) fd_rpc_ws_sig_check( ctx );
        if( FD_UNLIKELY( ctx->ws_acct_sub_cnt ) ) fd_rpc_ws_acct_check( ctx );
        break;
      }
      case REPLAY_SIG_DROP_BANK_REF: {
        fd_replay_drop_bank_ref_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        if( FD_UNLIKELY( ctx->processed_idx==msg->bank_idx ) ) {
          fd_stem_publish( stem, ctx->replay_out->idx, ctx->processed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->processed_idx = ULONG_MAX;
        }
        if( FD_UNLIKELY( ctx->confirmed_idx==msg->bank_idx ) ) {
          fd_stem_publish( stem, ctx->replay_out->idx, ctx->confirmed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->confirmed_idx = ULONG_MAX;
        }
        if( FD_UNLIKELY( ctx->finalized_idx==msg->bank_idx ) ) {
          fd_stem_publish( stem, ctx->replay_out->idx, ctx->finalized_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
          ctx->finalized_idx = ULONG_MAX;
        }
        break;
      }
      default: {
        break;
      }
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_GOSSIP_OUT ) {
    fd_gossip_update_message_t const * update = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    switch( update->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
        if( FD_UNLIKELY( update->contact_info->idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected contact_info_idx %lu >= %lu", update->contact_info->idx, FD_CONTACT_INFO_TABLE_SIZE ));
        fd_rpc_cluster_node_t * node = &ctx->cluster_nodes[ update->contact_info->idx ];
        if( FD_LIKELY( node->valid ) ) fd_rpc_cluster_node_dlist_idx_remove( ctx->cluster_nodes_dlist, update->contact_info->idx, ctx->cluster_nodes );

        node->valid = 1;
        node->identity = *(fd_pubkey_t *)update->origin;
        fd_memcpy( node->ci, update->contact_info->value, sizeof(fd_gossip_contact_info_t) );

        fd_rpc_cluster_node_dlist_idx_push_tail( ctx->cluster_nodes_dlist, update->contact_info->idx, ctx->cluster_nodes );
        break;
      }
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
        if( FD_UNLIKELY( update->contact_info_remove->idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected remove_contact_info_idx %lu >= %lu", update->contact_info_remove->idx, FD_CONTACT_INFO_TABLE_SIZE ));
        fd_rpc_cluster_node_t * node = &ctx->cluster_nodes[ update->contact_info_remove->idx ];
        FD_TEST( node->valid );
        node->valid = 0;
        fd_rpc_cluster_node_dlist_idx_remove( ctx->cluster_nodes_dlist, update->contact_info_remove->idx, ctx->cluster_nodes );
        break;
      }
      default: break;
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_EPOCH ) {
    fd_epoch_info_msg_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    FD_TEST( msg->staked_vote_cnt<=MAX_STAKE_WEIGHTS );
    ctx->epoch_schedule     = msg->epoch_schedule;
    ctx->has_epoch_schedule = 1;

    fd_rpc_mleaders_ingest( ctx->mleaders, msg );
    fd_rpc_vote_sets_ingest( ctx, msg );
    ctx->ns_per_slot = msg->ns_per_slot;
    ctx->features     = msg->features;
    ctx->has_features = 1;
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_EXECRP_META ) {
    /* Unreliable link: copy, then check the frag was not overwritten. */
    if( FD_LIKELY( sz>=offsetof( fd_execrp_txn_meta_t, log ) && sz<=sizeof(fd_execrp_txn_meta_t) ) ) {
      memcpy( ctx->meta_msg, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sz );
      FD_COMPILER_MFENCE();
      ulong seq_now = fd_frag_meta_seq_query( ctx->in_mcache[ in_idx ]+fd_mcache_line_idx( seq, ctx->in_depth[ in_idx ] ) );
      if( FD_LIKELY( seq_now==seq ) ) fd_rpc_meta_ingest( ctx, ctx->meta_msg, sz );
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_TXN && sig==REPLAY_SIG_REWARDS ) {
    /* Unreliable link: copy, then check the frag was not overwritten. */
    memcpy( ctx->reward_msg, fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk ), sizeof(fd_replay_rewards_t) );
    FD_COMPILER_MFENCE();
    ulong seq_now = fd_frag_meta_seq_query( ctx->in_mcache[ in_idx ]+fd_mcache_line_idx( seq, ctx->in_depth[ in_idx ] ) );
    if( FD_LIKELY( seq_now==seq ) ) fd_rpc_reward_ingest( ctx, ctx->reward_msg );
    else                            fd_rpc_reward_gap( ctx );
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY_TXN ) {
    /* This link is unreliable: copy what is needed, then check the frag
       was not overwritten underneath us before using the copy. */
    fd_replay_txn_executed_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_rpc_txn_rec_t * rec = &ctx->txn_recs[ ctx->txn_rec_next % FD_RPC_TXN_REC_CNT ];
    fd_txn_t const *   txn = TXN( msg->txn );
    ulong payload_sz = (ulong)msg->txn->payload_sz;
    ulong sig_off    = (ulong)txn->signature_off;
    ulong acct_off   = (ulong)txn->acct_addr_off;
    ulong acct_cnt   = (ulong)txn->acct_addr_cnt;
    int   landed     = ( msg->is_committable || msg->is_fees_only ) && !msg->is_noop;
    int   sane       = payload_sz<=FD_TXN_MTU_V0 && sig_off+64UL<=payload_sz && acct_off+32UL*acct_cnt<=payload_sz;
    if( FD_LIKELY( sane ) ) {
      memcpy( rec->payload, msg->txn->payload, payload_sz );
      memcpy( rec->sig, rec->payload+sig_off, 64UL );
      rec->slot          = msg->slot;
      rec->index_in_slot = (uint)msg->index_in_slot;
      rec->txn_err       = msg->txn_err;
      rec->has_exec_err  = msg->has_exec_err;
      rec->exec_err      = msg->exec_err;
      rec->exec_err_kind = msg->exec_err_kind;
      rec->exec_err_idx  = msg->exec_err_idx;
      rec->custom_err    = msg->custom_err;
      rec->fee           = msg->transaction_fee+msg->priority_fee;
      rec->compute_units = msg->compute_units_consumed;
      rec->payload_sz    = (ushort)payload_sz;
      rec->acct_off      = (ushort)acct_off;
      rec->acct_cnt      = (ushort)acct_cnt;
      ulong bal_cnt = fd_ulong_min( msg->bal_cnt, MAX_TX_ACCOUNT_LOCKS );
      rec->bal_cnt       = (ushort)bal_cnt;
      memcpy( rec->pre_lamports,  msg->pre_lamports,  bal_cnt*sizeof(ulong) );
      memcpy( rec->post_lamports, msg->post_lamports, bal_cnt*sizeof(ulong) );
    }
    FD_COMPILER_MFENCE();
    ulong seq_now = fd_frag_meta_seq_query( ctx->in_mcache[ in_idx ]+fd_mcache_line_idx( seq, ctx->in_depth[ in_idx ] ) );
    /* Only a record that was copied whole is published; otherwise the
       ring position is simply reused by the next transaction. */
    if( FD_LIKELY( seq_now==seq && landed && sane ) ) fd_rpc_txn_commit( ctx );
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_SNAPMK ) {
    /* unreliable link: copy, then check the frag was not overwritten */
    fd_snapmk_msg_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    ulong slot = msg->found.slot;      /* slot and base_slot lead all three messages */
    ulong base = msg->found.base_slot;
    FD_COMPILER_MFENCE();
    ulong seq_now = fd_frag_meta_seq_query( ctx->in_mcache[ in_idx ]+fd_mcache_line_idx( seq, ctx->in_depth[ in_idx ] ) );
    if( FD_LIKELY( seq_now==seq ) ) {
      ulong i;
      for( i=0UL; i<ctx->snap_cnt; i++ ) if( ctx->snaps[ i ].slot==slot && ctx->snaps[ i ].base==base ) break;
      if( sig==FD_SNAPMK_MSG_DELETED ) {
        if( i<ctx->snap_cnt ) ctx->snaps[ i ] = ctx->snaps[ --ctx->snap_cnt ];
      } else if( i==ctx->snap_cnt && ctx->snap_cnt<FD_RPC_SNAP_MAX ) {
        ctx->snaps[ ctx->snap_cnt ].slot = slot;
        ctx->snaps[ ctx->snap_cnt ].base = base;
        ctx->snap_cnt++;
      }
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) {
    fd_votor_msg_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    if( FD_LIKELY( msg->certed.kind==FD_CERT_KIND_FINAL || msg->certed.kind==FD_CERT_KIND_FAST_FINAL ) ) {
      fd_rpc_cluster_finalized( ctx, msg->certed.slot );
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_GENESI ) {
    ctx->has_genesis_hash = 1;
    fd_genesis_meta_t const * genesis_meta = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    *ctx->genesis_hash = genesis_meta->genesis_hash;
    ctx->genesis_creation_time = (long)genesis_meta->creation_time_seconds;

    uchar const * blob    = (uchar const *)( genesis_meta+1 );
    ulong const   blob_sz = genesis_meta->blob_sz;
    FD_TEST( blob_sz<=ctx->genesis_max_message_size );

    ctx->genesis_tar_bz_sz = fd_rpc_file_as_tarball(
      ctx,
      "genesis.bin",
      blob, blob_sz,
      ctx->genesis_tar, ctx->genesis_tar_max_sz,
      ctx->genesis_tar_bz, ctx->genesis_tar_bz_max_sz );
    if( FD_UNLIKELY( ctx->genesis_tar_bz_sz==ULONG_MAX ) ) {
      FD_LOG_ERR(( "failed to create genesis tarball (blob_sz=%lu)", blob_sz ));
    }
  }

  return 0;
}

#define STAGE_JSON(__ctx) (__extension__({ \
  fd_http_server_response_t __res = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 }; \
  if( FD_UNLIKELY( fd_http_server_stage_body( __ctx->http, &__res ) ) ) { \
    __res.status = 500; \
    FD_LOG_WARNING(( "Failed to populate RPC response buffer" )); \
    FD_LOG_HEXDUMP_WARNING(( "start of message:\n%.*s", __ctx->http->oring+(__ctx->http->stage_off%__ctx->http->oring_sz), fd_ulong_min( 500UL, __ctx->http->oring_sz-(__ctx->http->stage_off%__ctx->http->oring_sz)-1UL ) )); \
    FD_LOG_HEXDUMP_WARNING(( "start of buffer:\n%.*s",  __ctx->http->oring,                                                fd_ulong_min( 500UL, __ctx->http->oring_sz ) )); \
  } \
  __res; }))

#define PRINTF_JSON(__ctx, ...) (__extension__({ \
  fd_http_server_printf( __ctx->http, __VA_ARGS__ ); \
  fd_http_server_response_t __res = STAGE_JSON( __ctx ); \
  __res; }))


static inline char const *
fd_rpc_val_kind_cstr( fd_rpc_val_t const * v ) {
  switch( v->kind ) {
  case FD_RPC_VAL_STR:   return "string";
  case FD_RPC_VAL_MAP:   return "map";
  case FD_RPC_VAL_SEQ:   return "sequence";
  case FD_RPC_VAL_BOOL:  return "boolean";
  case FD_RPC_VAL_FLOAT: return "floating point";
  case FD_RPC_VAL_INT:   return "integer";
  case FD_RPC_VAL_NULL:  return "null";
  default: FD_LOG_ERR(( "unreachable" ));
  }
}

/* fd_rpc_str_ws_sz returns the size of the whitespace unit at the
   start of the JSON string body [p,end), or 0 if it does not start
   with one.  A unit is a literal space or an escape that decodes to an
   ASCII control character. */

static ulong
fd_rpc_str_ws_sz( char const * p,
                  char const * end ) {
  if( p[0]==' ' ) return 1UL;
  if( p[0]!='\\' || p+1>=end ) return 0UL;
  switch( p[1] ) {
  case 'b': case 'f': case 'n': case 'r': case 't':
    return 2UL;
  case 'u':
    if( p+6<=end && p[2]=='0' && p[3]=='0' && (p[4]=='0' || p[4]=='1') ) return 6UL;
    return 0UL;
  default:
    return 0UL;
  }
}

/* fd_rpc_print_str appends the contents of a request string to the
   response.  The bytes between the quotes of a well formed JSON string
   are themselves a well formed JSON string body, so they are copied
   as-is, escapes included.  Runs of whitespace (literal spaces and the
   escapes for control characters) are collapsed into a single space to
   keep the error message on one line. */

static void
fd_rpc_print_str( fd_rpc_tile_t *       ctx,
                  fd_jtok_str_t const * s ) {
  char const * p    = s->ptr;
  char const * end  = s->ptr + s->sz;
  char const * span = p;
  while( p<end ) {
    ulong ws_sz = fd_rpc_str_ws_sz( p, end );
    if( !ws_sz ) {
      p += ( p[0]=='\\' && p+1<end ) ? 2 : 1; /* skip escapes whole */
      continue;
    }
    if( span<p ) fd_http_server_memcpy( ctx->http, (uchar const *)span, (ulong)(p-span) );
    fd_http_server_memcpy( ctx->http, (uchar const *)" ", 1UL );
    do p += ws_sz; while( p<end && (ws_sz = fd_rpc_str_ws_sz( p, end )) );
    span = p;
  }
  if( span<p ) fd_http_server_memcpy( ctx->http, (uchar const *)span, (ulong)(p-span) );
}

/* fd_rpc_print_float formats a double to match serde_json / zmij. */

static inline void
fd_rpc_print_float( fd_rpc_tile_t * ctx,
                    double          d ) {
  char buf[ 64 ];
  double test;
  int ok = 0;
  if( FD_LIKELY( sprintf( buf, "%1.15g", d )>0 && sscanf( buf, "%lg", &test )==1 && test==d ) ) ok = 1;
  else if( FD_LIKELY( sprintf( buf, "%1.16g", d )>0 && sscanf( buf, "%lg", &test )==1 && test==d ) ) ok = 1;
  else if( FD_LIKELY( sprintf( buf, "%1.17g", d )>0 ) ) ok = 1;
  if( FD_UNLIKELY( !ok ) ) {
    fd_http_server_printf( ctx->http, " `0.0`" );
    return;
  }
  if( !strchr( buf, '.' ) && !strchr( buf, 'e' ) ) {
    fd_http_server_printf( ctx->http, " `%s.0`", buf );
  } else {
    fd_http_server_printf( ctx->http, " `%s`", buf );
  }
}

/* fd_rpc_err_invalid emits an "invalid type" / "invalid value" error
   for v in the style of serde.  what is "type" or "value", expected is
   the name of the expected type. */

static fd_http_server_response_t
fd_rpc_err_invalid( fd_rpc_tile_t *      ctx,
                    char const *         id_cstr,
                    char const *         what,
                    fd_rpc_val_t const * v,
                    char const *         expected ) {
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid %s: %s", what, fd_rpc_val_kind_cstr( v ) );
  switch( v->kind ) {
  case FD_RPC_VAL_STR:
    fd_http_server_printf( ctx->http, " \\\"" );
    fd_rpc_print_str( ctx, &v->str );
    fd_http_server_printf( ctx->http, "\\\"" );
    break;
  case FD_RPC_VAL_BOOL:
  case FD_RPC_VAL_INT:
    fd_http_server_printf( ctx->http, " `%.*s`", (int)v->raw_sz, v->raw );
    break;
  case FD_RPC_VAL_FLOAT: {
    fd_jtok_t j[1];
    double d;
    fd_jtok_double( fd_jtok_init( j, v->raw, v->raw_sz ), &d );
    if( FD_LIKELY( !fd_jtok_fini( j ) ) ) fd_rpc_print_float( ctx, d );
    else                                  fd_http_server_printf( ctx->http, " `%.*s`", (int)v->raw_sz, v->raw );
    break;
  }
  default:
    break;
  }
  fd_http_server_printf( ctx->http, ", expected %s.\"},\"id\":%s}\n", expected, id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
fd_rpc_err_unknown_encoding( fd_rpc_tile_t *       ctx,
                             char const *          id_cstr,
                             fd_jtok_str_t const * variant ) {
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: unknown variant `" );
  fd_rpc_print_str( ctx, variant );
  fd_http_server_printf( ctx->http, "`, expected one of `binary`, `base58`, `base64`, `jsonParsed`, `base64+zstd`.\"},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static inline int
fd_rpc_validate_params( fd_rpc_tile_t *             ctx,
                        char const *                id_cstr,
                        fd_rpc_params_t const *     params,
                        ulong                       min_cnt,
                        ulong                       max_cnt,
                        fd_http_server_response_t * res ) {
  FD_TEST( min_cnt <= max_cnt );
  /* Agave also includes a "data" field in some responses with the
     faulty params payload. Instead of printing raw JSON, they print the
     representation which we won't replicate.

     e.g. "data" might contain something like
      Array([String(\"\"), Object {}])

    instead, we just include the field with an empty string
  */

  ulong param_cnt = 0UL;
  switch( params->kind ) {
  case FD_RPC_VAL_NONE:
  case FD_RPC_VAL_NULL:
    break;
  case FD_RPC_VAL_SEQ:
    param_cnt = params->cnt;
    break;
  case FD_RPC_VAL_MAP:
    if( max_cnt==0UL ) *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters: No parameters were expected\",\"data\":\"\"},\"id\":%s}\n", id_cstr );
    else                *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"`params` should be an array\"},\"id\":%s}\n", id_cstr );
    return 0;
  default:
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
    return 0;
  }

  if( FD_UNLIKELY( param_cnt>0UL && max_cnt==0UL ) ) {
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters: No parameters were expected\",\"data\":\"\"},\"id\":%s}\n", id_cstr );
    return 0;
  }
  if( FD_UNLIKELY( param_cnt<min_cnt ) ) {
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"`params` should have at least %lu argument(s)\"},\"id\":%s}\n", min_cnt, id_cstr );
    return 0;
  }
  if( param_cnt>max_cnt ) {
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid parameters: Expected from %lu to %lu parameters.\",\"data\":\"\\\"Got: %lu\\\"\"},\"id\":%s}\n", min_cnt, max_cnt, param_cnt, id_cstr );
    return 0;
  }

  return 1;
}

/* TODO: use optimized version of this from fd_base58_tmpl.c */
static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static inline int
fd_rpc_cstr_contains_non_base58(const char *str) {
    for (; *str; str++) {
        if (!strchr(base58_chars, *str)) return 1;
    }
    return 0;
}

/* adapted from https://salsa.debian.org/debian/libbase58/-/blob/debian/master/base58.c */
static inline int
fd_rpc_base58_encode_128( char * b58, ulong * b58sz, const void *data, ulong binsz ) {
  FD_TEST( binsz <= 128UL );

  const uchar * bin = data;
  ulong carry;
  ulong i, j, high, zcount = 0;
  ulong size;

  while( zcount<binsz && !bin[ zcount ] ) zcount++;

  size = (binsz-zcount)*138/100+1; /* strict overestimate */
  size = fd_ulong_min( size, FD_RPC_BASE58_ENCODED_128_LEN ); /* theoretical max */
  uchar buf[ FD_RPC_BASE58_ENCODED_128_LEN ] = { 0 };

  for( i=zcount, high=size-1UL; i<binsz; i++, high=j ) {
    for( carry=bin[ i ], j=size-1UL; (j>high) || carry; j-- ) {
      carry += 256UL * buf[ j ];
      buf[ j ] = (uchar)(carry%58UL);
      carry /= 58UL;
      if( FD_UNLIKELY( !j ) ) break;
    }
  }

  for( j=0; j<size && !buf[ j ]; j++);

  if( *b58sz<zcount+size-j ) {
    *b58sz = zcount+size-j;
    return 0;
  }

  if (zcount) memset(b58, '1', zcount);
  for( i=zcount; j<size; i++, j++) b58[ i ] = base58_chars[ buf[ j ] ];
  *b58sz = i;

  return 1;
}

/* getInflationGovernor and getMinimumBalanceForRentExemption take a
   bare Option<CommitmentConfig> in Agave, so unlike the flattened
   configs serde rejects a missing or malformed commitment member. */

static int
fd_rpc_validate_commitment_strict( fd_rpc_tile_t *             ctx,
                                   char const *                id_cstr,
                                   fd_rpc_val_t const *        config,
                                   fd_http_server_response_t * res ) {
  if( config->kind!=FD_RPC_VAL_MAP ) return 1; /* type errors are fd_rpc_validate_config's */
  fd_rpc_config_t cfg[1];
  fd_rpc_config_read( config, cfg );
  fd_rpc_val_t const * commitment = &cfg->commitment;
  if( FD_UNLIKELY( commitment->kind==FD_RPC_VAL_NONE ) ) {
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `commitment`.\"},\"id\":%s}\n", id_cstr );
    return 0;
  }
  if( FD_UNLIKELY( commitment->kind!=FD_RPC_VAL_STR ) ) {
    *res = fd_rpc_err_invalid( ctx, id_cstr, "type", commitment, "enum CommitmentLevel" );
    return 0;
  }
  if( FD_UNLIKELY( !fd_jtok_str_eq( &commitment->str, "processed" ) && !fd_jtok_str_eq( &commitment->str, "confirmed" ) && !fd_jtok_str_eq( &commitment->str, "finalized" ) ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: unknown variant `" );
    fd_rpc_print_str( ctx, &commitment->str );
    fd_http_server_printf( ctx->http, "`, expected one of `processed`, `confirmed`, `finalized`.\"},\"id\":%s}\n", id_cstr );
    *res = STAGE_JSON( ctx );
    return 0;
  }
  return 1;
}

static inline int
fd_rpc_validate_config( fd_rpc_tile_t *             ctx,
                        char const *                id_cstr,
                        fd_rpc_val_t const *        config,
                        char const *                config_rust_type,
                        int                         has_commitment,
                        int                         has_encoding,
                        int                         has_data_slice,
                        int                         has_min_context_slot,
                        ulong *                     bank_idx,
                        char const **               opt_encoding_cstr,
                        ulong *                     opt_slice_length,
                        ulong *                     opt_slice_offset,
                        fd_rpc_val_t *              opt_identity,
                        fd_http_server_response_t * res ) {

  switch( config->kind ) {
  case FD_RPC_VAL_INT:
  case FD_RPC_VAL_FLOAT:
  case FD_RPC_VAL_BOOL:
  case FD_RPC_VAL_STR:
    *res = fd_rpc_err_invalid( ctx, id_cstr, "type", config, config_rust_type );
    return 0;
  case FD_RPC_VAL_SEQ:
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: Positional config params not supported\"},\"id\":%s}\n", id_cstr );
    return 0;
  default:
    break;
  }

  fd_rpc_config_t cfg[1];
  fd_rpc_config_read( config, cfg );
  if( opt_identity ) *opt_identity = cfg->identity;

  ulong _bank_idx = ULONG_MAX;
  if( FD_LIKELY( has_commitment ) ) {
    fd_rpc_val_t const * commitment = &cfg->commitment;
    char commitment_cstr[ 16 ];
    if( FD_UNLIKELY( !fd_rpc_val_cstr( commitment, commitment_cstr, sizeof(commitment_cstr) ) ) ) _bank_idx = ctx->finalized_idx;
    else if( FD_LIKELY( !strcmp( commitment_cstr, "processed" ) ) ) _bank_idx = ctx->processed_idx;
    else if( FD_LIKELY( !strcmp( commitment_cstr, "confirmed" ) ) ) _bank_idx = ctx->confirmed_idx;
    else if( FD_LIKELY( !strcmp( commitment_cstr, "finalized" ) ) ) _bank_idx = ctx->finalized_idx;
    else _bank_idx = ctx->finalized_idx;
  } else {
    _bank_idx = ctx->finalized_idx;
  }
  if( FD_UNLIKELY( _bank_idx==ULONG_MAX ) ) {
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: banks uninitialized\"},\"id\":%s}\n", id_cstr );
    return 0;
  }
  *bank_idx = _bank_idx;

  if( FD_LIKELY( has_encoding ) ) {
    fd_rpc_val_t const * encoding = &cfg->encoding;

    if( FD_UNLIKELY( encoding->kind==FD_RPC_VAL_INT || encoding->kind==FD_RPC_VAL_FLOAT || encoding->kind==FD_RPC_VAL_BOOL ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", encoding, "string or map" );
      return 0;
    }

    /* An encoding given as a map must be a single key naming the
       variant with a null (unit) value, e.g. {"base64":null}. */
    fd_jtok_str_t variant_key = {0};
    fd_rpc_val_t  variant_val[1] = {{ .kind = FD_RPC_VAL_NONE }};
    if( FD_UNLIKELY( encoding->kind==FD_RPC_VAL_MAP ) ) {
      fd_jtok_t j[1];
      fd_jtok_str_t key;
      ulong member_cnt = 0UL;
      fd_jtok_obj_enter( fd_jtok_init( j, encoding->raw, encoding->raw_sz ) );
      while( fd_jtok_obj_next( j, &key ) ) {
        if( !member_cnt ) { variant_key = key; fd_rpc_val_read( j, variant_val ); }
        member_cnt++;
      }
      if( FD_UNLIKELY( member_cnt!=1UL ) ) {
        *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid value: map, expected map with a single key.\"},\"id\":%s}\n", id_cstr );
        return 0;
      }
    }
    if( FD_UNLIKELY( encoding->kind==FD_RPC_VAL_SEQ ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", encoding, "string or map" );
      return 0;
    }

    char const * encoding_cstr;
    if( FD_UNLIKELY( encoding->kind==FD_RPC_VAL_MAP ) ) {
      if(      fd_jtok_str_eq( &variant_key, "binary"      ) ) encoding_cstr = "binary";
      else if( fd_jtok_str_eq( &variant_key, "base58"      ) ) encoding_cstr = "base58";
      else if( fd_jtok_str_eq( &variant_key, "base64"      ) ) encoding_cstr = "base64";
      else if( fd_jtok_str_eq( &variant_key, "base64+zstd" ) ) encoding_cstr = "base64+zstd";
      else if( fd_jtok_str_eq( &variant_key, "jsonParsed"  ) ) encoding_cstr = "jsonParsed";
      else {
        *res = fd_rpc_err_unknown_encoding( ctx, id_cstr, &variant_key );
        return 0;
      }
      if( FD_UNLIKELY( variant_val->kind!=FD_RPC_VAL_NULL ) ) {
        *res = fd_rpc_err_invalid( ctx, id_cstr, "type", variant_val, "unit" );
        return 0;
      }
    } else {
      char buf[ 16 ];
      if(      encoding->kind!=FD_RPC_VAL_STR    ) encoding_cstr = "binary";
      else if( !fd_rpc_val_cstr( encoding, buf, sizeof(buf) ) ) encoding_cstr = "";
      else if( !strcmp( buf, "binary"      ) ) encoding_cstr = "binary";
      else if( !strcmp( buf, "base58"      ) ) encoding_cstr = "base58";
      else if( !strcmp( buf, "base64"      ) ) encoding_cstr = "base64";
      else if( !strcmp( buf, "base64+zstd" ) ) encoding_cstr = "base64+zstd";
      else if( !strcmp( buf, "jsonParsed"  ) ) encoding_cstr = "jsonParsed";
      else encoding_cstr = "";
    }

    if( FD_UNLIKELY( !encoding_cstr[0] ) ) {
      *res = fd_rpc_err_unknown_encoding( ctx, id_cstr, &encoding->str );
      return 0;
    }

    if( FD_LIKELY( opt_encoding_cstr ) ) *opt_encoding_cstr = encoding_cstr;
  }

  if( FD_LIKELY( has_data_slice ) ) {
    fd_rpc_val_t const * dataSlice = &cfg->data_slice;

    if( FD_UNLIKELY( dataSlice->kind==FD_RPC_VAL_INT || dataSlice->kind==FD_RPC_VAL_FLOAT || dataSlice->kind==FD_RPC_VAL_BOOL || dataSlice->kind==FD_RPC_VAL_STR ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", dataSlice, "struct UiDataSliceConfig" );
      return 0;
    }

    /* A data slice is either {"offset":..,"length":..} or a two
       element [offset,length] array. */
    fd_rpc_val_t _offset[1] = {{ .kind = FD_RPC_VAL_NONE }};
    fd_rpc_val_t _length[1] = {{ .kind = FD_RPC_VAL_NONE }};
    ulong        slice_cnt  = 0UL;
    if( dataSlice->kind==FD_RPC_VAL_MAP ) {
      fd_jtok_t j[1];
      fd_jtok_str_t key;
      fd_jtok_obj_enter( fd_jtok_init( j, dataSlice->raw, dataSlice->raw_sz ) );
      while( fd_jtok_obj_next( j, &key ) ) {
        if(      fd_jtok_str_eq( &key, "offset" ) ) { if( _offset->kind==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, _offset ); }
        else if( fd_jtok_str_eq( &key, "length" ) ) { if( _length->kind==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, _length ); }
      }
    } else if( FD_UNLIKELY( dataSlice->kind==FD_RPC_VAL_SEQ ) ) {
      fd_jtok_t j[1];
      fd_jtok_arr_enter( fd_jtok_init( j, dataSlice->raw, dataSlice->raw_sz ) );
      while( fd_jtok_arr_next( j ) ) {
        if(      slice_cnt==0UL ) fd_rpc_val_read( j, _offset );
        else if( slice_cnt==1UL ) fd_rpc_val_read( j, _length );
        slice_cnt++;
      }
    }

    if( FD_UNLIKELY( _offset->kind==FD_RPC_VAL_BOOL || _offset->kind==FD_RPC_VAL_FLOAT ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _offset, "usize" );
      return 0;
    }
    if( FD_UNLIKELY( _length->kind==FD_RPC_VAL_BOOL || _length->kind==FD_RPC_VAL_FLOAT ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _length, "usize" );
      return 0;
    }

    if( FD_UNLIKELY( _offset->kind==FD_RPC_VAL_INT && _offset->neg ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "value", _offset, "usize" );
      return 0;
    }
    if( FD_UNLIKELY( _length->kind==FD_RPC_VAL_INT && _length->neg ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "value", _length, "usize" );
      return 0;
    }

    if( FD_UNLIKELY( _offset->kind==FD_RPC_VAL_STR ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _offset, "usize" );
      return 0;
    }
    if( FD_UNLIKELY( _length->kind==FD_RPC_VAL_STR ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _length, "usize" );
      return 0;
    }

    if( FD_UNLIKELY( _offset->kind!=FD_RPC_VAL_NONE && _offset->kind!=FD_RPC_VAL_INT ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _offset, "usize" );
      return 0;
    }
    if( FD_UNLIKELY( _length->kind!=FD_RPC_VAL_NONE && _length->kind!=FD_RPC_VAL_INT ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _length, "usize" );
      return 0;
    }

    if( FD_UNLIKELY( dataSlice->kind==FD_RPC_VAL_MAP && _offset->kind==FD_RPC_VAL_NONE ) ) {
      *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `offset`.\"},\"id\":%s}\n", id_cstr );
      return 0;
    }
    if( FD_UNLIKELY( dataSlice->kind==FD_RPC_VAL_MAP && _length->kind==FD_RPC_VAL_NONE ) ) {
      *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `length`.\"},\"id\":%s}\n", id_cstr );
      return 0;
    }

    if( FD_UNLIKELY( dataSlice->kind==FD_RPC_VAL_SEQ && slice_cnt!=2UL ) ) {
      *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid length %lu, expected struct UiDataSliceConfig with 2 elements.\"},\"id\":%s}\n", slice_cnt, id_cstr );
      return 0;
    }

    if( dataSlice->kind==FD_RPC_VAL_MAP || dataSlice->kind==FD_RPC_VAL_SEQ ) {
      if( FD_LIKELY( opt_slice_offset ) ) *opt_slice_offset = _offset->u;
      if( FD_LIKELY( opt_slice_length ) ) *opt_slice_length = _length->u;
    } else {
      if( FD_LIKELY( opt_slice_offset ) ) *opt_slice_offset = 0UL;
      if( FD_LIKELY( opt_slice_length ) ) *opt_slice_length = ULONG_MAX;
    }
  }

  if( FD_LIKELY( has_min_context_slot ) ) {
    fd_rpc_val_t const * _minContextSlot = &cfg->min_context_slot;
    if( FD_UNLIKELY( _minContextSlot->kind==FD_RPC_VAL_BOOL || _minContextSlot->kind==FD_RPC_VAL_FLOAT ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _minContextSlot, "u64" );
      return 0;
    }

    if( FD_UNLIKELY( _minContextSlot->kind==FD_RPC_VAL_INT && _minContextSlot->neg ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "value", _minContextSlot, "u64" );
      return 0;
    }

    if( FD_UNLIKELY( _minContextSlot->kind==FD_RPC_VAL_STR ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _minContextSlot, "u64" );
      return 0;
    }

    if( FD_UNLIKELY( _minContextSlot->kind==FD_RPC_VAL_MAP || _minContextSlot->kind==FD_RPC_VAL_SEQ ) ) {
      *res = fd_rpc_err_invalid( ctx, id_cstr, "type", _minContextSlot, "u64" );
      return 0;
    }

    ulong minContextSlot = _minContextSlot->kind==FD_RPC_VAL_INT ? _minContextSlot->u : 0UL;

    if( _bank_idx!=ULONG_MAX && ctx->banks[ _bank_idx ].slot<minContextSlot ) {
      *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%s}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, ctx->banks[ _bank_idx ].slot, id_cstr );
      return 0;
    }
  }

  return 1;
}

static int
fd_rpc_validate_address( fd_rpc_tile_t *             ctx,
                         char const *                id_cstr,
                         fd_rpc_val_t const *        address_in,
                         fd_pubkey_t *               address_out,
                         fd_http_server_response_t * response ) {
  if( FD_UNLIKELY( address_in->kind!=FD_RPC_VAL_STR ) ) {
    *response = fd_rpc_err_invalid( ctx, id_cstr, "type", address_in, "a string" );
    return 0;
  }
  char address_cstr[ FD_BASE58_ENCODED_32_SZ ];
  fd_jtok_t s[1];
  fd_jtok_cstr( fd_jtok_init( s, address_in->raw, address_in->raw_sz ), address_cstr, sizeof(address_cstr) );
  int fits = !fd_jtok_err( s );
  int invalid_char;
  if( FD_LIKELY( fits ) ) invalid_char = fd_rpc_cstr_contains_non_base58( address_cstr );
  else {
    /* Too long to be a pubkey.  A string of only base58 characters is
       still WrongSize rather than Invalid. */
    invalid_char = 0;
    for( ulong i=0UL; i<address_in->str.sz; i++ ) {
      if( !strchr( base58_chars, address_in->str.ptr[ i ] ) ) { invalid_char = 1; break; }
    }
  }
  if( FD_UNLIKELY( invalid_char ) ) {
    *response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: Invalid\"},\"id\":%s}\n", id_cstr );
    return 0;
  }
  int valid = fits && !!fd_base58_decode_32( address_cstr, address_out->uc );
  if( FD_UNLIKELY( !valid ) ) {
    *response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: WrongSize\"},\"id\":%s}\n", id_cstr );
    return 0;
  }

  return 1;
}

static inline int
fd_rpc_validate_uint_param( fd_rpc_tile_t *             ctx,
                            char const *                id_cstr,
                            fd_rpc_val_t const *        val,
                            char const *                type_cstr,
                            ulong *                     out,
                            fd_http_server_response_t * res ) {
  if( FD_UNLIKELY( val->kind==FD_RPC_VAL_BOOL || val->kind==FD_RPC_VAL_FLOAT ) ) {
    *res = fd_rpc_err_invalid( ctx, id_cstr, "type", val, type_cstr );
    return 0;
  }
  if( FD_UNLIKELY( val->kind==FD_RPC_VAL_INT && val->neg ) ) {
    *res = fd_rpc_err_invalid( ctx, id_cstr, "value", val, type_cstr );
    return 0;
  }
  if( FD_UNLIKELY( val->kind!=FD_RPC_VAL_INT ) ) {
    *res = fd_rpc_err_invalid( ctx, id_cstr, "type", val, type_cstr );
    return 0;
  }

  *out = val->u;
  return 1;
}

#define UNIMPLEMENTED(X)                               \
static fd_http_server_response_t                       \
X( fd_rpc_tile_t *         ctx,                        \
   char const *            id_cstr,                    \
   fd_rpc_params_t const * params ) {                     \
  (void)ctx; (void)id_cstr; (void)params;                 \
  FD_MCNT_INC( RPC, REQUEST_HANDLED_UNIMPLEMENTED, 1UL ); \
  return (fd_http_server_response_t){ .status = 501 };    \
}

/* ---- Agave RPC compatibility additions --------------------------------
   Helpers shared by the handlers below. */

#define FD_RPC_SLOT_HISTORY_MAX_ENTRIES (1024UL*1024UL)
#define FD_RPC_TOKEN_ACCOUNT_MIN_SZ     (165UL)
#define FD_RPC_TOKEN_MINT_MIN_SZ        (82UL)

/* fd_rpc_cfg_member looks up one member of a config map.  Returns 1 and
   fills out if present, 0 otherwise. */
static int
fd_rpc_cfg_member( fd_rpc_val_t const * config,
                   char const *         name,
                   fd_rpc_val_t *       out ) {
  out->kind = FD_RPC_VAL_NONE;
  if( config->kind!=FD_RPC_VAL_MAP ) return 0;
  fd_jtok_t j[1];
  fd_jtok_str_t key;
  fd_jtok_obj_enter( fd_jtok_init( j, config->raw, config->raw_sz ) );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( fd_jtok_str_eq( &key, name ) && out->kind==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, out );
  }
  return out->kind!=FD_RPC_VAL_NONE;
}

/* fd_rpc_cfg_bank resolves the commitment in a config map to a bank. */
static int
fd_rpc_cfg_bank( fd_rpc_tile_t *             ctx,
                 char const *                id_cstr,
                 fd_rpc_val_t const *        config,
                 ulong *                     bank_idx,
                 fd_http_server_response_t * res ) {
  return fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig", 1, 0, 0, 1,
                                 bank_idx, NULL, NULL, NULL, NULL, res );
}

/* fd_rpc_slot_history_load reads the SlotHistory sysvar of a bank into
   the scratch buffer.  The sysvar is a bit vector of the last 1M slots
   on this fork: a set bit means a block was produced in that slot.
   Returns 1 on success and sets *next_slot. */
static int
fd_rpc_slot_history_load( fd_rpc_tile_t *     ctx,
                          bank_info_t const * info,
                          ulong *             next_slot ) {
  ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, fd_sysvar_slot_history_id.uc,
                             &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
  if( FD_UNLIKELY( !lamports ) ) return 0;
  ulong const words = FD_RPC_SLOT_HISTORY_MAX_ENTRIES/64UL;
  if( FD_UNLIKELY( data_len<1UL+8UL+8UL*words+8UL+8UL ) ) return 0;
  uchar const * d = ctx->scratch.accdb_data_buf;
  if( FD_UNLIKELY( d[ 0 ]!=1 || FD_LOAD( ulong, d+1UL )!=words ) ) return 0;
  *next_slot = FD_LOAD( ulong, d+1UL+8UL+8UL*words+8UL );
  return 1;
}

/* Returns 1 if a block was produced in slot, 0 if it was skipped or is
   outside the window the loaded SlotHistory covers. */
static inline int
fd_rpc_slot_history_has( fd_rpc_tile_t const * ctx,
                         ulong                 next_slot,
                         ulong                 slot ) {
  if( FD_UNLIKELY( slot>=next_slot ) ) return 0;
  if( FD_UNLIKELY( next_slot-slot>FD_RPC_SLOT_HISTORY_MAX_ENTRIES ) ) return 0;
  ulong bit  = slot % FD_RPC_SLOT_HISTORY_MAX_ENTRIES;
  ulong word = FD_LOAD( ulong, ctx->scratch.accdb_data_buf+9UL+8UL*(bit/64UL) );
  return (int)((word>>(bit%64UL))&1UL);
}

static inline ulong
fd_rpc_slot_history_oldest( ulong next_slot ) {
  return next_slot>FD_RPC_SLOT_HISTORY_MAX_ENTRIES ? next_slot-FD_RPC_SLOT_HISTORY_MAX_ENTRIES : 0UL;
}

static fd_http_server_response_t
fd_rpc_err_msg( fd_rpc_tile_t * ctx,
                char const *    id_cstr,
                int             code,
                char const *    msg ) {
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"%s\"},\"id\":%s}\n", code, msg, id_cstr );
}

/* fd_rpc_print_ui_amount_fields prints the members of the SPL token
   amount object; fd_rpc_print_ui_amount wraps them in braces. */
static void
fd_rpc_print_ui_amount_fields( fd_rpc_tile_t * ctx,
                               ulong           amount,
                               uchar           decimals ) {
  char s[ 64 ];
  ulong len;
  if( decimals==0 ) {
    len = (ulong)snprintf( s, sizeof(s), "%lu", amount );
  } else {
    ulong div = 1UL; uint d = fd_uint_min( (uint)decimals, 19U );
    for( uint i=0U; i<d; i++ ) div *= 10UL;
    len = (ulong)snprintf( s, sizeof(s), "%lu.%0*lu", amount/div, (int)d, amount%div );
    while( len && s[ len-1UL ]=='0' ) len--;
    if( len && s[ len-1UL ]=='.' ) len--;
    s[ len ] = '\0';
  }
  double ui = (double)amount / pow( 10.0, (double)decimals ); /* one division, as Agave does */
  /* shortest text that reads back as the same double, with ".0" on a
     whole number, as Agave prints floats */
  char ui_cstr[ 40 ];
  for( int prec=1; prec<=17; prec++ ) {
    snprintf( ui_cstr, sizeof(ui_cstr), "%.*g", prec, ui );
    if( strtod( ui_cstr, NULL )==ui ) break;
  }
  if( !strpbrk( ui_cstr, ".eEn" ) ) strcat( ui_cstr, ".0" );
  fd_http_server_printf( ctx->http, "\"amount\":\"%lu\",\"decimals\":%u,\"uiAmount\":%s,\"uiAmountString\":\"%s\"",
                         amount, (uint)decimals, ui_cstr, s );
}

static void
fd_rpc_print_ui_amount( fd_rpc_tile_t * ctx,
                        ulong           amount,
                        uchar           decimals ) {
  fd_http_server_printf( ctx->http, "{" );
  fd_rpc_print_ui_amount_fields( ctx, amount, decimals );
  fd_http_server_printf( ctx->http, "}" );
}

static int
fd_rpc_owner_is_token_program( uchar const * owner ) {
  if( !memcmp( owner, fd_solana_spl_token_id.uc, 32UL ) ) return 1;
  FD_BASE58_ENCODE_32_BYTES( owner, owner_b58 );
  return !strcmp( owner_b58, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" );
}

static fd_http_server_response_t
getBlockCommitment( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 1, &response ) ) ) return response;
  ulong slot;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, &params->v[ 0 ], "u64", &slot, &response ) ) ) return response;

  /* Alpenglow has no lockout tower, so there is no per-block commitment
     to report.  Agave under Alpenglow answers exactly this. */
  (void)slot;
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"commitment\":null,\"totalStake\":0},\"id\":%s}\n", id_cstr );
}


static inline int
fd_rpc_owner_is_token_program_early( char const * owner_b58 ) {
  return !strcmp( owner_b58, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" ) || !strcmp( owner_b58, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" );
}

/* fd_rpc_encode_account_parsed prints an account in Agave's jsonParsed
   form.  Vote accounts (v4 vote state), stake accounts and plain SPL
   token mints and accounts are parsed.  Returns 1 if
   the account object was printed, 0 if this is an account Agave does
   not parse either (the caller falls back to base64, as Agave does),
   -1 if Agave would parse it and this tile cannot. */
static int
fd_rpc_encode_account_parsed( fd_rpc_tile_t * ctx,
                              uchar const *   d,
                              ulong           sz,
                              uchar const *   owner,
                              ulong           lamports,
                              int             executable ) {
  FD_BASE58_ENCODE_32_BYTES( owner, owner_b58 );

  if( !memcmp( owner, fd_solana_stake_program_id.uc, 32UL ) ) {
    /* StakeStateV2: u32 state, then Meta { rent_exempt_reserve,
       authorized { staker, withdrawer }, lockup { unix_timestamp,
       epoch, custodian } } at 4, then Stake { delegation { voter,
       stake, activation_epoch, deactivation_epoch, (unused f64) },
       credits_observed } at 124. */
    if( FD_UNLIKELY( sz<4UL ) ) return -1;
    uint state = FD_LOAD( uint, d );
    if( FD_UNLIKELY( state>3U || ( (state==1U || state==2U) && sz<196UL ) ) ) return -1;
    fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{" );
    if( state==1U || state==2U ) {
      FD_BASE58_ENCODE_32_BYTES( d+12UL, staker_b58     );
      FD_BASE58_ENCODE_32_BYTES( d+44UL, withdrawer_b58 );
      FD_BASE58_ENCODE_32_BYTES( d+92UL, custodian_b58  );
      fd_http_server_printf( ctx->http, "\"info\":{\"meta\":{\"authorized\":{\"staker\":\"%s\",\"withdrawer\":\"%s\"},\"lockup\":{\"custodian\":\"%s\",\"epoch\":%lu,\"unixTimestamp\":%ld},\"rentExemptReserve\":\"%lu\"},",
                             staker_b58, withdrawer_b58, custodian_b58, FD_LOAD( ulong, d+84UL ), FD_LOAD( long, d+76UL ), FD_LOAD( ulong, d+4UL ) );
      if( state==2U ) {
        FD_BASE58_ENCODE_32_BYTES( d+124UL, voter_b58 );
        fd_http_server_printf( ctx->http, "\"stake\":{\"creditsObserved\":%lu,\"delegation\":{\"activationEpoch\":\"%lu\",\"deactivationEpoch\":\"%lu\",\"stake\":\"%lu\",\"voter\":\"%s\"}}},",
                               FD_LOAD( ulong, d+188UL ), FD_LOAD( ulong, d+164UL ), FD_LOAD( ulong, d+172UL ), FD_LOAD( ulong, d+156UL ), voter_b58 );
      } else {
        fd_http_server_printf( ctx->http, "\"stake\":null}," );
      }
    }
    char const * type = state==0U ? "uninitialized" : state==1U ? "initialized" : state==2U ? "delegated" : "rewardsPool";
    fd_http_server_printf( ctx->http, "\"type\":\"%s\"},\"program\":\"stake\",\"space\":%lu},\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu}",
                           type, sz, executable ? "true" : "false", lamports, owner_b58, sz );
    return 1;
  }

  if( fd_rpc_owner_is_token_program_early( owner_b58 ) ) {
    /* Plain SPL token mints (82 bytes) and accounts (165 bytes), of
       either token program.  Token-2022 accounts with extensions and
       multisigs are not parsed. */
    char const * program = !strcmp( owner_b58, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" ) ? "spl-token" : "spl-token-2022";
    if( sz==82UL ) {
      fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{\"decimals\":%u,", (uint)d[ 44 ] );
      if( FD_LOAD( uint, d+46UL ) ) { FD_BASE58_ENCODE_32_BYTES( d+50UL, k ); fd_http_server_printf( ctx->http, "\"freezeAuthority\":\"%s\",", k ); }
      else                            fd_http_server_printf( ctx->http, "\"freezeAuthority\":null," );
      fd_http_server_printf( ctx->http, "\"isInitialized\":%s,", d[ 45 ] ? "true" : "false" );
      if( FD_LOAD( uint, d ) ) { FD_BASE58_ENCODE_32_BYTES( d+4UL, k ); fd_http_server_printf( ctx->http, "\"mintAuthority\":\"%s\",", k ); }
      else                       fd_http_server_printf( ctx->http, "\"mintAuthority\":null," );
      fd_http_server_printf( ctx->http, "\"supply\":\"%lu\"},\"type\":\"mint\"},\"program\":\"%s\",\"space\":%lu},\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu}",
                             FD_LOAD( ulong, d+36UL ), program, sz, executable ? "true" : "false", lamports, owner_b58, sz );
      return 1;
    }
    if( FD_UNLIKELY( sz!=165UL ) ) return -1;

    /* Copy what is needed out of the account first: reading the mint
       for its decimals reuses the buffer d may point into. */
    uchar mint[ 32 ], tok_owner[ 32 ], delegate[ 32 ], close_auth[ 32 ];
    memcpy( mint, d, 32UL ); memcpy( tok_owner, d+32UL, 32UL ); memcpy( delegate, d+76UL, 32UL ); memcpy( close_auth, d+133UL, 32UL );
    ulong amount        = FD_LOAD( ulong, d+64UL  );
    uint  has_delegate  = FD_LOAD( uint,  d+72UL  );
    uchar state         = d[ 108 ];
    uint  is_native     = FD_LOAD( uint,  d+109UL );
    ulong native_rent   = FD_LOAD( ulong, d+113UL );
    ulong delegated_amt = FD_LOAD( ulong, d+121UL );
    uint  has_close     = FD_LOAD( uint,  d+129UL );

    ulong bank_idx = ctx->processed_idx!=ULONG_MAX ? ctx->processed_idx : ctx->finalized_idx;
    if( FD_UNLIKELY( bank_idx==ULONG_MAX ) ) return -1;
    ulong m_lamports; int m_exec; uchar m_owner[ 32UL ]; ulong m_len;
    fd_accdb_read_one_nocache( ctx->accdb, ctx->banks[ bank_idx ].accdb_fork_id, mint, &m_lamports, &m_exec, m_owner, ctx->scratch.accdb_data_buf, &m_len );
    if( FD_UNLIKELY( !m_lamports || m_len<82UL || memcmp( m_owner, owner, 32UL ) ) ) return -1;
    uchar decimals = ctx->scratch.accdb_data_buf[ 44 ];

    FD_BASE58_ENCODE_32_BYTES( mint,      mint_b58      );
    FD_BASE58_ENCODE_32_BYTES( tok_owner, tok_owner_b58 );
    fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{" );
    if( has_close ) { FD_BASE58_ENCODE_32_BYTES( close_auth, k ); fd_http_server_printf( ctx->http, "\"closeAuthority\":\"%s\",", k ); }
    if( has_delegate ) {
      FD_BASE58_ENCODE_32_BYTES( delegate, k );
      fd_http_server_printf( ctx->http, "\"delegate\":\"%s\",\"delegatedAmount\":", k );
      fd_rpc_print_ui_amount( ctx, delegated_amt, decimals );
      fd_http_server_printf( ctx->http, "," );
    }
    fd_http_server_printf( ctx->http, "\"isNative\":%s,\"mint\":\"%s\",\"owner\":\"%s\",", is_native ? "true" : "false", mint_b58, tok_owner_b58 );
    if( is_native ) {
      fd_http_server_printf( ctx->http, "\"rentExemptReserve\":" );
      fd_rpc_print_ui_amount( ctx, native_rent, decimals );
      fd_http_server_printf( ctx->http, "," );
    }
    fd_http_server_printf( ctx->http, "\"state\":\"%s\",\"tokenAmount\":", state==1 ? "initialized" : state==2 ? "frozen" : "uninitialized" );
    fd_rpc_print_ui_amount( ctx, amount, decimals );
    fd_http_server_printf( ctx->http, "},\"type\":\"account\"},\"program\":\"%s\",\"space\":%lu},\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu}",
                           program, sz, executable ? "true" : "false", lamports, owner_b58, sz );
    return 1;
  }

  if( !memcmp( owner, fd_sysvar_owner_id.uc, 32UL ) ) {
    /* Sysvars are told apart by address.  Each is printed as Agave's
       parse_sysvar does. */
    uchar const * key = ctx->encode_key;
    if( FD_UNLIKELY( !key ) ) return -1;
    fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":" );
    char const * type;
    if( !memcmp( key, fd_sysvar_clock_id.uc, 32UL ) && sz>=40UL ) {
      type = "clock";
      fd_http_server_printf( ctx->http, "{\"epoch\":%lu,\"epochStartTimestamp\":%ld,\"leaderScheduleEpoch\":%lu,\"slot\":%lu,\"unixTimestamp\":%ld}",
                             FD_LOAD( ulong, d+16UL ), FD_LOAD( long, d+8UL ), FD_LOAD( ulong, d+24UL ), FD_LOAD( ulong, d ), FD_LOAD( long, d+32UL ) );
    } else if( !memcmp( key, fd_sysvar_epoch_schedule_id.uc, 32UL ) && sz>=33UL ) {
      type = "epochSchedule";
      fd_http_server_printf( ctx->http, "{\"firstNormalEpoch\":%lu,\"firstNormalSlot\":%lu,\"leaderScheduleSlotOffset\":%lu,\"slotsPerEpoch\":%lu,\"warmup\":%s}",
                             FD_LOAD( ulong, d+17UL ), FD_LOAD( ulong, d+25UL ), FD_LOAD( ulong, d+8UL ), FD_LOAD( ulong, d ), d[ 16 ] ? "true" : "false" );
    } else if( !memcmp( key, fd_sysvar_rent_id.uc, 32UL ) && sz>=8UL ) {
      type = "rent";
      fd_http_server_printf( ctx->http, "{\"lamportsPerByte\":\"%lu\"}", FD_LOAD( ulong, d ) );
    } else if( !memcmp( key, fd_sysvar_last_restart_slot_id.uc, 32UL ) && sz>=8UL ) {
      type = "lastRestartSlot";
      fd_http_server_printf( ctx->http, "{\"lastRestartSlot\":%lu}", FD_LOAD( ulong, d ) );
    } else if( !memcmp( key, fd_sysvar_epoch_rewards_id.uc, 32UL ) && sz>=81UL ) {
      /* distribution_starting_block_height, num_partitions, parent_blockhash,
         total_points (u128), total_rewards, distributed_rewards, active */
      type = "epochRewards";
      FD_BASE58_ENCODE_32_BYTES( d+16UL, parent_b58 );
      uint128 points = FD_LOAD( uint128, d+48UL );
      char points_cstr[ 48 ]; ulong pl = sizeof(points_cstr)-1UL; points_cstr[ pl ] = '\0';
      do { points_cstr[ --pl ] = (char)( '0'+(int)( points%10 ) ); points /= 10; } while( points );
      fd_http_server_printf( ctx->http, "{\"active\":%s,\"distributedRewards\":\"%lu\",\"distributionStartingBlockHeight\":%lu,\"numPartitions\":%lu,\"parentBlockhash\":\"%s\",\"totalPoints\":\"%s\",\"totalRewards\":\"%lu\"}",
                             d[ 80 ] ? "true" : "false", FD_LOAD( ulong, d+72UL ), FD_LOAD( ulong, d ), FD_LOAD( ulong, d+8UL ), parent_b58, points_cstr+pl, FD_LOAD( ulong, d+64UL ) );
    } else if( !memcmp( key, fd_sysvar_recent_block_hashes_id.uc, 32UL ) && sz>=8UL ) {
      type = "recentBlockhashes";
      ulong cnt = fd_ulong_min( FD_LOAD( ulong, d ), (sz-8UL)/40UL );
      fd_http_server_printf( ctx->http, "[" );
      for( ulong i=0UL; i<cnt; i++ ) {
        FD_BASE58_ENCODE_32_BYTES( d+8UL+40UL*i, h_b58 );
        fd_http_server_printf( ctx->http, "%s{\"blockhash\":\"%s\",\"feeCalculator\":{\"lamportsPerSignature\":\"%lu\"}}", i ? "," : "", h_b58, FD_LOAD( ulong, d+8UL+40UL*i+32UL ) );
      }
      fd_http_server_printf( ctx->http, "]" );
    } else if( !memcmp( key, fd_sysvar_slot_hashes_id.uc, 32UL ) && sz>=8UL ) {
      type = "slotHashes";
      ulong cnt = fd_ulong_min( FD_LOAD( ulong, d ), (sz-8UL)/40UL );
      fd_http_server_printf( ctx->http, "[" );
      for( ulong i=0UL; i<cnt; i++ ) {
        FD_BASE58_ENCODE_32_BYTES( d+8UL+40UL*i+8UL, h_b58 );
        fd_http_server_printf( ctx->http, "%s{\"hash\":\"%s\",\"slot\":%lu}", i ? "," : "", h_b58, FD_LOAD( ulong, d+8UL+40UL*i ) );
      }
      fd_http_server_printf( ctx->http, "]" );
    } else if( !memcmp( key, fd_sysvar_stake_history_id.uc, 32UL ) && sz>=8UL ) {
      /* entries: epoch, effective, activating, deactivating */
      type = "stakeHistory";
      ulong cnt = fd_ulong_min( FD_LOAD( ulong, d ), (sz-8UL)/32UL );
      fd_http_server_printf( ctx->http, "[" );
      for( ulong i=0UL; i<cnt; i++ ) {
        uchar const * e = d+8UL+32UL*i;
        fd_http_server_printf( ctx->http, "%s{\"epoch\":%lu,\"stakeHistory\":{\"activating\":%lu,\"deactivating\":%lu,\"effective\":%lu}}", i ? "," : "",
                               FD_LOAD( ulong, e ), FD_LOAD( ulong, e+16UL ), FD_LOAD( ulong, e+24UL ), FD_LOAD( ulong, e+8UL ) );
      }
      fd_http_server_printf( ctx->http, "]" );
    } else if( !memcmp( key, fd_sysvar_slot_history_id.uc, 32UL ) && sz>=9UL ) {
      /* bit vector: option tag, word count, words, bit count; then next_slot */
      type = "slotHistory";
      ulong words = FD_LOAD( ulong, d+1UL );
      if( FD_UNLIKELY( d[ 0 ]!=1 || words>(sz-9UL)/8UL || sz<9UL+8UL*words+16UL ) ) { fd_http_server_unstage( ctx->http ); return -1; }
      ulong bits = fd_ulong_min( FD_LOAD( ulong, d+9UL+8UL*words ), 64UL*words );
      fd_http_server_printf( ctx->http, "{\"bits\":\"" );
      char chunk[ 65 ]; chunk[ 64 ] = '\0';
      for( ulong w=0UL; w*64UL<bits; w++ ) {
        ulong word = FD_LOAD( ulong, d+9UL+8UL*w );
        ulong n    = fd_ulong_min( 64UL, bits-w*64UL );
        for( ulong b=0UL; b<n; b++ ) chunk[ b ] = (char)( '0'+(int)( (word>>b)&1UL ) );
        fd_http_server_printf( ctx->http, "%.*s", (int)n, chunk );
      }
      fd_http_server_printf( ctx->http, "\",\"nextSlot\":%lu}", FD_LOAD( ulong, d+9UL+8UL*words+8UL ) );
    } else {
      fd_http_server_unstage( ctx->http );
      return -1;
    }
    fd_http_server_printf( ctx->http, ",\"type\":\"%s\"},\"program\":\"sysvar\",\"space\":%lu},\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu}",
                           type, sz, executable ? "true" : "false", lamports, owner_b58, sz );
    return 1;
  }

# define FD_RPC_PARSED_TAIL( type, program ) \
    fd_http_server_printf( ctx->http, ",\"type\":\"%s\"},\"program\":\"%s\",\"space\":%lu},\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu}", \
                           (type), (program), sz, executable ? "true" : "false", lamports, owner_b58, sz )

  if( !memcmp( owner, fd_solana_system_program_id.uc, 32UL ) && sz==80UL ) {
    /* nonce account: version, state, authority, durable nonce, fee */
    if( FD_UNLIKELY( FD_LOAD( uint, d+4UL )!=1U ) ) return -1;
    FD_BASE58_ENCODE_32_BYTES( d+8UL,  authority_b58 );
    FD_BASE58_ENCODE_32_BYTES( d+40UL, nonce_b58     );
    fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{\"authority\":\"%s\",\"blockhash\":\"%s\",\"feeCalculator\":{\"lamportsPerSignature\":\"%lu\"}}", authority_b58, nonce_b58, FD_LOAD( ulong, d+72UL ) );
    FD_RPC_PARSED_TAIL( "initialized", "nonce" );
    return 1;
  }

  if( !memcmp( owner, fd_solana_address_lookup_table_program_id.uc, 32UL ) ) {
    /* type, deactivation slot, last extended slot, start index,
       optional authority, padding; addresses from byte 56 */
    if( FD_UNLIKELY( sz<56UL || FD_LOAD( uint, d )!=1U ) ) return -1;
    fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{\"addresses\":[" );
    for( ulong i=0UL; 56UL+32UL*(i+1UL)<=sz; i++ ) {
      FD_BASE58_ENCODE_32_BYTES( d+56UL+32UL*i, a_b58 );
      fd_http_server_printf( ctx->http, "%s\"%s\"", i ? "," : "", a_b58 );
    }
    fd_http_server_printf( ctx->http, "]," );
    if( d[ 21 ] ) { FD_BASE58_ENCODE_32_BYTES( d+22UL, auth_b58 ); fd_http_server_printf( ctx->http, "\"authority\":\"%s\",", auth_b58 ); }
    fd_http_server_printf( ctx->http, "\"deactivationSlot\":\"%lu\",\"lastExtendedSlot\":\"%lu\",\"lastExtendedSlotStartIndex\":%u}", FD_LOAD( ulong, d+4UL ), FD_LOAD( ulong, d+12UL ), (uint)d[ 20 ] );
    FD_RPC_PARSED_TAIL( "lookupTable", "address-lookup-table" );
    return 1;
  }

  if( !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.uc, 32UL ) ) {
    uint state = sz>=4UL ? FD_LOAD( uint, d ) : 0U;
    if( state==2U && sz>=36UL ) {
      FD_BASE58_ENCODE_32_BYTES( d+4UL, pd_b58 );
      fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{\"programData\":\"%s\"}", pd_b58 );
      FD_RPC_PARSED_TAIL( "program", "bpf-upgradeable-loader" );
      return 1;
    }
    if( state==3U && sz>=45UL ) {
      /* slot, optional upgrade authority, then the program bytes */
      fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{" );
      if( d[ 12 ] ) { FD_BASE58_ENCODE_32_BYTES( d+13UL, auth_b58 ); fd_http_server_printf( ctx->http, "\"authority\":\"%s\",", auth_b58 ); }
      else            fd_http_server_printf( ctx->http, "\"authority\":null," );
      fd_http_server_printf( ctx->http, "\"data\":[\"" );
      ulong   enc_sz = FD_BASE64_ENC_SZ( sz-45UL );
      uchar * enc    = fd_http_server_append_start( ctx->http, enc_sz );
      if( FD_UNLIKELY( !enc ) ) { fd_http_server_unstage( ctx->http ); return -1; }
      fd_http_server_append_end( ctx->http, fd_base64_encode( (char *)enc, d+45UL, sz-45UL ) );
      fd_http_server_printf( ctx->http, "\",\"base64\"],\"slot\":%lu}", FD_LOAD( ulong, d+4UL ) );
      FD_RPC_PARSED_TAIL( "programData", "bpf-upgradeable-loader" );
      return 1;
    }
    return -1; /* buffer or uninitialized */
  }

  if( !memcmp( owner, fd_solana_config_program_id.uc, 32UL ) ) {
    /* [short vec of (key, signer)][u64 length][JSON text].  Agave parses
       validator info records and leaves other config accounts as
       base64; so does this. */
    static uchar const validator_info_id[ 32 ] = { 0x07,0x51,0x97,0x01,0x74,0x48,0xf2,0xac,0x5d,0xc2,0x3c,0x9e,0xbc,0x7a,0xc7,0x8c,
                                                   0x0a,0x27,0x25,0x7a,0xc6,0x14,0x45,0x8d,0xe0,0xa4,0xf1,0x6f,0x80,0x00,0x00,0x00 };
    if( sz<1UL || (d[ 0 ] & 0x80) ) return 0;
    ulong key_cnt = d[ 0 ];
    ulong off     = 1UL+33UL*key_cnt;
    if( !key_cnt || off+8UL>sz || memcmp( d+1UL, validator_info_id, 32UL ) ) return 0;
    ulong json_len = FD_LOAD( ulong, d+off ); off += 8UL;
    if( json_len>sz-off ) return 0;
    /* embed the record only if it is one well formed JSON object */
    fd_jtok_t j[1]; char const * raw; ulong raw_sz;
    fd_jtok_init( j, (char const *)d+off, json_len );
    if( fd_jtok_peek( j )!=FD_JTOK_OBJ ) return 0;
    fd_jtok_raw( j, &raw, &raw_sz );
    if( fd_jtok_err( j ) ) return 0;
    fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{\"configData\":%.*s,\"keys\":[", (int)raw_sz, raw );
    for( ulong i=0UL; i<key_cnt; i++ ) {
      FD_BASE58_ENCODE_32_BYTES( d+1UL+33UL*i, k_b58 );
      fd_http_server_printf( ctx->http, "%s{\"pubkey\":\"%s\",\"signer\":%s}", i ? "," : "", k_b58, d[ 1UL+33UL*i+32UL ] ? "true" : "false" );
    }
    fd_http_server_printf( ctx->http, "]}" );
    FD_RPC_PARSED_TAIL( "validatorInfo", "config" );
    return 1;
  }
# undef FD_RPC_PARSED_TAIL

  if( memcmp( owner, fd_solana_vote_program_id.uc, 32UL ) ) return 0;

  /* bincode v4 vote state, see fd_rpc_vote_v4_last_vote for the layout */
  if( FD_UNLIKELY( sz<4UL || FD_LOAD( uint, d )!=fd_vote_state_versioned_enum_v4 ) ) return -1;
  ulong off = 4UL;
# define NEED(n) do { if( FD_UNLIKELY( off+(n)>sz ) ) return -1; } while(0)
  NEED( 4UL*32UL+2UL+2UL+8UL+1UL );
  uchar const * node      = d+off; off += 32UL;
  uchar const * withdraw  = d+off; off += 32UL;
  uchar const * infl_coll = d+off; off += 32UL;
  uchar const * blk_coll  = d+off; off += 32UL;
  ushort infl_bps = FD_LOAD( ushort, d+off ); off += 2UL;
  ushort blk_bps  = FD_LOAD( ushort, d+off ); off += 2UL;
  ulong  pending  = FD_LOAD( ulong,  d+off ); off += 8UL;
  uchar  has_bls  = d[ off ];                 off += 1UL;
  uchar const * bls = NULL;
  if( has_bls ) { NEED( 48UL ); bls = d+off; off += 48UL; }
  NEED( 8UL );
  ulong votes_cnt = FD_LOAD( ulong, d+off ); off += 8UL;
  if( FD_UNLIKELY( votes_cnt>sz/13UL ) ) return -1;
  NEED( votes_cnt*13UL+1UL );
  uchar const * votes = d+off; off += votes_cnt*13UL;
  uchar has_root = d[ off ]; off += 1UL;
  ulong root = 0UL;
  if( has_root ) { NEED( 8UL ); root = FD_LOAD( ulong, d+off ); off += 8UL; }
  NEED( 8UL );
  ulong av_cnt = FD_LOAD( ulong, d+off ); off += 8UL;
  if( FD_UNLIKELY( av_cnt>sz/40UL ) ) return -1;
  NEED( av_cnt*40UL+8UL );
  uchar const * av = d+off; off += av_cnt*40UL;
  ulong ec_cnt = FD_LOAD( ulong, d+off ); off += 8UL;
  if( FD_UNLIKELY( ec_cnt>sz/24UL ) ) return -1;
  NEED( ec_cnt*24UL+16UL );
  uchar const * ec = d+off; off += ec_cnt*24UL;
  ulong ts_slot = FD_LOAD( ulong, d+off );
  long  ts      = FD_LOAD( long,  d+off+8UL );
# undef NEED

  fd_http_server_printf( ctx->http, "{\"data\":{\"parsed\":{\"info\":{\"authorizedVoters\":[" );
  for( ulong i=0UL; i<av_cnt; i++ ) {
    FD_BASE58_ENCODE_32_BYTES( av+i*40UL+8UL, voter_b58 );
    fd_http_server_printf( ctx->http, "%s{\"authorizedVoter\":\"%s\",\"epoch\":%lu}", i ? "," : "", voter_b58, FD_LOAD( ulong, av+i*40UL ) );
  }
  FD_BASE58_ENCODE_32_BYTES( withdraw,  withdraw_b58  );
  FD_BASE58_ENCODE_32_BYTES( blk_coll,  blk_coll_b58  );
  FD_BASE58_ENCODE_32_BYTES( infl_coll, infl_coll_b58 );
  FD_BASE58_ENCODE_32_BYTES( node,      node_b58      );
  fd_http_server_printf( ctx->http, "],\"authorizedWithdrawer\":\"%s\",\"blockRevenueCollector\":\"%s\",\"blockRevenueCommissionBps\":%u,", withdraw_b58, blk_coll_b58, (uint)blk_bps );
  if( bls ) {
    char  bls_b58[ FD_RPC_BASE58_ENCODED_128_LEN+1UL ];
    ulong bls_b58_sz = sizeof(bls_b58); /* in: capacity, out: length */
    if( FD_UNLIKELY( !fd_rpc_base58_encode_128( bls_b58, &bls_b58_sz, bls, 48UL ) ) ) bls_b58_sz = 0UL;
    fd_http_server_printf( ctx->http, "\"blsPubkeyCompressed\":\"%.*s\",", (int)bls_b58_sz, bls_b58 );
  } else {
    fd_http_server_printf( ctx->http, "\"blsPubkeyCompressed\":null," );
  }
  fd_http_server_printf( ctx->http, "\"commission\":%lu,\"epochCredits\":[", fd_ulong_min( (ulong)infl_bps/100UL, 255UL ) );
  for( ulong i=0UL; i<ec_cnt; i++ ) {
    fd_http_server_printf( ctx->http, "%s{\"credits\":\"%lu\",\"epoch\":%lu,\"previousCredits\":\"%lu\"}", i ? "," : "",
                           FD_LOAD( ulong, ec+i*24UL+8UL ), FD_LOAD( ulong, ec+i*24UL ), FD_LOAD( ulong, ec+i*24UL+16UL ) );
  }
  fd_http_server_printf( ctx->http, "],\"inflationRewardsCollector\":\"%s\",\"inflationRewardsCommissionBps\":%u,\"lastTimestamp\":{\"slot\":%lu,\"timestamp\":%ld},\"nodePubkey\":\"%s\",\"pendingDelegatorRewards\":\"%lu\",\"priorVoters\":[],",
                         infl_coll_b58, (uint)infl_bps, ts_slot, ts, node_b58, pending );
  if( has_root ) fd_http_server_printf( ctx->http, "\"rootSlot\":%lu,\"votes\":[", root );
  else           fd_http_server_printf( ctx->http, "\"rootSlot\":null,\"votes\":[" );
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    fd_http_server_printf( ctx->http, "%s{\"confirmationCount\":%u,\"latency\":%u,\"slot\":%lu}", i ? "," : "",
                           FD_LOAD( uint, votes+i*13UL+9UL ), (uint)votes[ i*13UL ], FD_LOAD( ulong, votes+i*13UL+1UL ) );
  }
  fd_http_server_printf( ctx->http, "]},\"type\":\"vote\"},\"program\":\"vote\",\"space\":%lu},\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu}",
                         sz, executable ? "true" : "false", lamports, owner_b58, sz );
  return 1;
}

/* fd_rpc_encode_account_data encodes account data fields
   (executable, lamports, owner, rentEpoch, space, data) into the http
   staging buffer.  Returns 1 on success.  On failure, calls
   fd_http_server_unstage and writes an error response into
   err_response. */
static int
fd_rpc_encode_account_data( fd_rpc_tile_t *             ctx,
                            uchar const *               acct_data,
                            ulong                       acct_data_len,
                            uchar const *               acct_owner,
                            ulong                       acct_lamports,
                            int                         acct_executable,
                            char const *                encoding_cstr,
                            ulong                       slice_offset,
                            ulong                       slice_length,
                            char const *                id_cstr,
                            fd_http_server_response_t * err_response ) {

  if( !strcmp( encoding_cstr, "jsonParsed" ) ) {
    int parsed = fd_rpc_encode_account_parsed( ctx, acct_data, acct_data_len, acct_owner, acct_lamports, acct_executable );
    if( parsed==1 ) return 1;
    if( FD_UNLIKELY( parsed<0 ) ) {
      FD_BASE58_ENCODE_32_BYTES( acct_owner, owner_b58 );
      fd_http_server_unstage( ctx->http );
      *err_response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: jsonParsed could not parse this account of program %s (unsupported state or layout)\"},\"id\":%s}\n", owner_b58, id_cstr );
      return 0;
    }
    encoding_cstr = "base64"; /* a program Agave does not parse either */
  }

  int is_binary = !strcmp( encoding_cstr, "binary" );
  int is_base58 = !strcmp( encoding_cstr, "base58" );
  int is_zstd   = !strcmp( encoding_cstr, "base64+zstd" );

  ulong data_sz        = acct_data_len;
  uchar const * out    = acct_data + fd_ulong_if( slice_offset<data_sz, slice_offset, 0UL );
  ulong         snip_sz = fd_ulong_min( fd_ulong_if( slice_offset<data_sz, data_sz-slice_offset, 0UL ), slice_length );
  ulong         out_sz  = snip_sz;

  if( FD_UNLIKELY( (is_binary || is_base58) && snip_sz>128UL ) ) {
    fd_http_server_unstage( ctx->http );
    *err_response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Encoded binary (base 58) data should be less than 128 bytes, please use Base64 encoding.\"},\"id\":%s}\n", id_cstr );
    return 0;
  }

  if( is_zstd ) {
    ulong zstd_res = ZSTD_compressCCtx( ctx->zstd_cctx, ctx->compress_buf, sizeof(ctx->compress_buf), out, snip_sz, FD_RPC_ZSTD_LEVEL );
    if( ZSTD_isError( zstd_res ) ) {
      fd_http_server_unstage( ctx->http );
      *err_response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: zstandard compression failed (%s)\"},\"id\":%s}\n", ZSTD_getErrorName( zstd_res ), id_cstr );
      return 0;
    }
    out    = ctx->compress_buf;
    out_sz = (ulong)zstd_res;
  }

  FD_BASE58_ENCODE_32_BYTES( acct_owner, owner_b58 );
  fd_http_server_printf( ctx->http,
      "{\"executable\":%s,\"lamports\":%lu,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":%lu,\"data\":",
      acct_executable ? "true" : "false",
      acct_lamports,
      owner_b58,
      data_sz );

  ulong encoded_sz = fd_ulong_if( is_base58 || is_binary, FD_RPC_BASE58_ENCODED_128_LEN, FD_BASE64_ENC_SZ( out_sz ) );
  if( FD_UNLIKELY( is_binary ) ) {
    fd_http_server_printf( ctx->http, "\"" );
  } else {
    fd_http_server_printf( ctx->http, "[\"" );
  }

  uchar * encoded = fd_http_server_append_start( ctx->http, encoded_sz );
  if( FD_UNLIKELY( !encoded ) ) {
    fd_http_server_unstage( ctx->http );
    *err_response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: response encoding buffer overflow (account data too large for response buffer)\"},\"id\":%s}\n", id_cstr );
    return 0;
  }

  if( FD_UNLIKELY( is_base58 || is_binary ) ) {
    if( FD_UNLIKELY( !fd_rpc_base58_encode_128( (char *)encoded, &encoded_sz, out, out_sz ) ) ) {
      fd_http_server_unstage( ctx->http );
      FD_LOG_WARNING(( "base58 encode failed out_sz=%lu", out_sz ));
      *err_response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: base58 encode failed\"},\"id\":%s}\n", id_cstr );
      return 0;
    }
  } else {
    encoded_sz = fd_base64_encode( (char *)encoded, out, out_sz );
  }

  fd_http_server_append_end( ctx->http, encoded_sz );

  if( FD_UNLIKELY( is_binary ) ) fd_http_server_printf( ctx->http, "\"}" );
  else                           fd_http_server_printf( ctx->http, "\",\"%s\"]}", encoding_cstr );

  return 1;
}

static fd_http_server_response_t
getAccountInfo( fd_rpc_tile_t *         ctx,
                char const *            id_cstr,
                fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_ACCOUNT_INFO, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;

  fd_pubkey_t address;
  fd_rpc_val_t const * acct_pubkey = &params->v[ 0 ];
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, acct_pubkey, &address, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  char const * encoding_cstr = NULL;
  ulong slice_length = ULONG_MAX;
  ulong slice_offset = 0;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcAccountInfoConfig",
                                             1, /* has_commitment */
                                             1, /* has_encoding */
                                             1, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             &encoding_cstr,
                                             &slice_length,
                                             &slice_offset,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  bank_info_t * info = &ctx->banks[ bank_idx ];
  ulong acct_lamports;
  int   acct_executable;
  uchar acct_owner[ 32UL ];
  ulong acct_data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, address.uc,
                             &acct_lamports, &acct_executable, acct_owner,
                             ctx->scratch.accdb_data_buf, &acct_data_len );
  if( FD_UNLIKELY( !acct_lamports ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":null},\"id\":%s}\n", FD_RPC_AGAVE_API_VERSION, info->slot, id_cstr );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":", id_cstr, FD_RPC_AGAVE_API_VERSION, info->slot );

  fd_http_server_response_t err_response;
  ctx->encode_key = address.uc;
  int encoded = fd_rpc_encode_account_data( ctx, ctx->scratch.accdb_data_buf, acct_data_len, acct_owner, acct_lamports, acct_executable, encoding_cstr, slice_offset, slice_length, id_cstr, &err_response );
  ctx->encode_key = NULL;
  if( FD_UNLIKELY( !encoded ) ) {
    return err_response;
  }

  fd_http_server_printf( ctx->http, "}}\n" );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getBalance( fd_rpc_tile_t *         ctx,
            char const *            id_cstr,
            fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_BALANCE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;

  fd_pubkey_t address;
  fd_rpc_val_t const * acct_pubkey = &params->v[ 0 ];
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, acct_pubkey, &address, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  ulong balance = fd_accdb_lamports( ctx->accdb, ctx->banks[ bank_idx ].accdb_fork_id, address.uc );

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":%lu},\"id\":%s}\n", FD_RPC_AGAVE_API_VERSION, ctx->banks[ bank_idx ].slot, balance, id_cstr );
}

static fd_http_server_response_t
getBlockHeight( fd_rpc_tile_t *         ctx,
                char const *            id_cstr,
                fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_BLOCK_HEIGHT, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", ctx->banks[ bank_idx ].block_height, id_cstr );
}

static int
fd_rpc_validate_block_production_range( fd_rpc_tile_t *             ctx,
                                        char const *                id_cstr,
                                        fd_rpc_val_t const *        range,
                                        int *                       has_first,
                                        ulong *                     first_slot,
                                        int *                       has_last,
                                        ulong *                     last_slot,
                                        fd_http_server_response_t * res ) {
  *has_first = 0;
  *has_last  = 0;
  if( range->kind==FD_RPC_VAL_NONE || range->kind==FD_RPC_VAL_NULL ) return 1;

  fd_rpc_val_t first[ 1 ] = {{ .kind = FD_RPC_VAL_NONE }};
  fd_rpc_val_t last [ 1 ] = {{ .kind = FD_RPC_VAL_NONE }};
  if( range->kind==FD_RPC_VAL_MAP ) {
    fd_jtok_t     j[ 1 ];
    fd_jtok_str_t key;
    fd_jtok_obj_enter( fd_jtok_init( j, range->raw, range->raw_sz ) );
    while( fd_jtok_obj_next( j, &key ) ) {
      if(      fd_jtok_str_eq( &key, "firstSlot" ) ) { if( first->kind==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, first ); }
      else if( fd_jtok_str_eq( &key, "lastSlot"  ) ) { if( last->kind ==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, last  ); }
    }
  } else if( range->kind==FD_RPC_VAL_SEQ ) {
    fd_jtok_t j[ 1 ];
    ulong     cnt = 0UL;
    fd_jtok_arr_enter( fd_jtok_init( j, range->raw, range->raw_sz ) );
    while( fd_jtok_arr_next( j ) ) {
      if(      cnt==0UL ) fd_rpc_val_read( j, first );
      else if( cnt==1UL ) fd_rpc_val_read( j, last  );
      cnt++;
    }
  } else {
    *res = fd_rpc_err_invalid( ctx, id_cstr, "type", range, "struct RpcBlockProductionConfigRange" );
    return 0;
  }

  if( FD_UNLIKELY( first->kind==FD_RPC_VAL_NONE ) ) {
    *res = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `firstSlot`.\"},\"id\":%s}\n", id_cstr );
    return 0;
  }
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, first, "u64", first_slot, res ) ) ) return 0;
  *has_first = 1;

  if( last->kind!=FD_RPC_VAL_NONE && last->kind!=FD_RPC_VAL_NULL ) {
    if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, last, "u64", last_slot, res ) ) ) return 0;
    *has_last = 1;
  }
  return 1;
}

static void
fd_rpc_block_production_epoch_update( fd_rpc_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->finalized_idx==ULONG_MAX ) ) return;
  bank_info_t const * root  = &ctx->banks[ ctx->finalized_idx ];
  ulong               first = root->slot-root->slot_in_epoch;
  if( FD_UNLIKELY( ctx->block_production_epoch_first_slot!=first ) ) {
    fd_rpc_block_production_table_reset( ctx->block_production_epoch );
    ctx->block_production_epoch_first_slot = first;
    ctx->block_production_epoch_next_slot  = first;
  }
  if( ctx->block_production_epoch_next_slot>root->slot ) return;

  ulong lamports;
  int   executable;
  uchar owner[ 32UL ];
  ulong data_sz;
  fd_accdb_read_one_nocache( ctx->accdb, root->accdb_fork_id, fd_sysvar_slot_history_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_sz );
  fd_slot_history_view_t view[ 1 ];
  if( FD_UNLIKELY( !lamports || !fd_sysvar_slot_history_view( view, ctx->scratch.accdb_data_buf, data_sz ) ) ) return;

  for( ulong slot=ctx->block_production_epoch_next_slot; slot<=root->slot; slot++ ) {
    fd_pubkey_t const * leader = fd_rpc_mleaders_get_leader_for_slot( ctx->mleaders, slot );
    if( FD_UNLIKELY( !leader ) ) return;
    fd_rpc_block_production_table_add( ctx->block_production_epoch, leader, 1UL, fd_sysvar_slot_history_find_slot( view, slot )==FD_SLOT_HISTORY_SLOT_FOUND );
    ctx->block_production_epoch_next_slot = slot+1UL;
  }
}

static fd_http_server_response_t
getBlockProduction( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_BLOCK_PRODUCTION, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  fd_rpc_val_t const * config   = &params->v[ 0 ];
  ulong                bank_idx = ULONG_MAX;
  fd_rpc_val_t         identity[ 1 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcBlockProductionConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             0, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             identity,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  int has_filter = identity->kind!=FD_RPC_VAL_NONE && identity->kind!=FD_RPC_VAL_NULL;
  if( FD_UNLIKELY( has_filter && identity->kind!=FD_RPC_VAL_STR ) ) {
    return fd_rpc_err_invalid( ctx, id_cstr, "type", identity, "a string" );
  }

  fd_rpc_config_t cfg[ 1 ];
  fd_rpc_config_read( config, cfg );
  int   has_first;
  int   has_last;
  ulong first_slot = 0UL;
  ulong last_slot  = 0UL;
  if( FD_UNLIKELY( !fd_rpc_validate_block_production_range( ctx, id_cstr, &cfg->range, &has_first, &first_slot, &has_last, &last_slot, &response ) ) ) return response;

  fd_pubkey_t filter[ 1 ];
  if( has_filter && FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, identity, filter, &response ) ) ) return response;

  bank_info_t const * bank          = &ctx->banks[ bank_idx ];
  int                 default_range = !has_first && !has_last;
  if( !has_first ) first_slot = bank->slot-bank->slot_in_epoch;
  if( !has_last  ) last_slot  = bank->slot;
  if( FD_UNLIKELY( last_slot<first_slot ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"lastSlot, %lu, cannot be less than firstSlot, %lu\"},\"id\":%s}\n", last_slot, first_slot, id_cstr );
  }

  if( default_range ) fd_rpc_block_production_epoch_update( ctx );

  ulong lamports;
  int   executable;
  uchar owner[ 32UL ];
  ulong data_sz;
  fd_accdb_read_one_nocache( ctx->accdb, bank->accdb_fork_id, fd_sysvar_slot_history_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_sz );
  fd_slot_history_view_t view[ 1 ];
  if( FD_UNLIKELY( !lamports || !fd_sysvar_slot_history_view( view, ctx->scratch.accdb_data_buf, data_sz ) ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"No slot history\"},\"id\":%s}\n", FD_RPC_ERROR_NO_SLOT_HISTORY, id_cstr );
  }

  ulong oldest = fd_ulong_sat_sub( view->next_slot, FD_SLOT_HISTORY_MAX_ENTRIES );
  ulong newest = fd_ulong_sat_sub( view->next_slot, 1UL );
  if( FD_UNLIKELY( first_slot<oldest ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"firstSlot, %lu, is too small; min %lu\"},\"id\":%s}\n", first_slot, oldest, id_cstr );
  }
  if( FD_UNLIKELY( last_slot>newest ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"lastSlot, %lu, is too large; max %lu\"},\"id\":%s}\n", last_slot, newest, id_cstr );
  }

  fd_rpc_block_production_table_t * table = ctx->block_production;
  fd_rpc_block_production_table_reset( table );

  ulong walk_slot = first_slot;
  if( default_range && ctx->block_production_epoch_first_slot==first_slot && ctx->block_production_epoch_next_slot<=(last_slot+1UL) ) {
    fd_rpc_block_production_table_t const * epoch = ctx->block_production_epoch;
    for( ulong i=0UL; i<epoch->cnt; i++ ) {
      fd_rpc_block_production_t const * entry = &epoch->map[ epoch->used[ i ] ];
      if( has_filter && !fd_pubkey_eq( &entry->key, filter ) ) continue;
      fd_rpc_block_production_table_add( table, &entry->key, entry->leader_slots, entry->blocks_produced );
    }
    walk_slot = ctx->block_production_epoch_next_slot;
  }

  for( ulong slot=walk_slot; slot<=last_slot; slot++ ) {
    fd_pubkey_t const * leader = fd_rpc_mleaders_get_leader_for_slot( ctx->mleaders, slot );
    if( FD_UNLIKELY( !leader ) ) {
      ulong epoch = ctx->has_epoch_schedule ? fd_slot_to_epoch( &ctx->epoch_schedule, slot, NULL ) : 0UL;
      return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid slot range: leader schedule for epoch %lu is unavailable\"},\"id\":%s}\n", epoch, id_cstr );
    }
    if( has_filter && !fd_pubkey_eq( leader, filter ) ) continue;

    fd_rpc_block_production_table_add( table, leader, 1UL, fd_sysvar_slot_history_find_slot( view, slot )==FD_SLOT_HISTORY_SLOT_FOUND );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":{\"byIdentity\":{", FD_RPC_AGAVE_API_VERSION, bank->slot );
  int first = 1;
  for( ulong i=0UL; i<table->cnt; i++ ) {
    fd_rpc_block_production_t const * entry = &table->map[ table->used[ i ] ];
    FD_BASE58_ENCODE_32_BYTES( entry->key.uc, identity_b58 );
    fd_http_server_printf( ctx->http, "%s\"%s\":[%lu,%lu]", first ? "" : ",", identity_b58, entry->leader_slots, entry->blocks_produced );
    first = 0;
  }
  fd_http_server_printf( ctx->http, "},\"range\":{\"firstSlot\":%lu,\"lastSlot\":%lu}}},\"id\":%s}\n", first_slot, last_slot, id_cstr );
  return STAGE_JSON( ctx );
}
#define FD_RPC_GET_BLOCKS_MAX (500000UL)

/* Shared by getBlocks and getBlocksWithLimit: lists the slots in
   [start_slot,end_slot] that have a block, at most limit of them. */
static fd_http_server_response_t
fd_rpc_blocks_list( fd_rpc_tile_t * ctx,
                    char const *    id_cstr,
                    ulong           bank_idx,
                    ulong           start_slot,
                    ulong           end_slot,
                    ulong           limit ) {
  bank_info_t const * info = &ctx->banks[ bank_idx ];
  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, info, &next_slot ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: slot history unavailable" );

  end_slot   = fd_ulong_min( end_slot, info->slot );
  start_slot = fd_ulong_max( start_slot, fd_rpc_slot_history_oldest( next_slot ) );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  ulong printed = 0UL;
  for( ulong slot=start_slot; slot<=end_slot && printed<limit; slot++ ) {
    if( slot!=info->slot && !fd_rpc_slot_history_has( ctx, next_slot, slot ) ) continue;
    fd_http_server_printf( ctx->http, "%s%lu", printed ? "," : "", slot );
    printed++;
    if( FD_UNLIKELY( slot==ULONG_MAX ) ) break;
  }
  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getBlocks( fd_rpc_tile_t *         ctx,
           char const *            id_cstr,
           fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( params->kind!=FD_RPC_VAL_SEQ || params->cnt<1UL || params->cnt>3UL ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: expected [start_slot, end_slot?, config?]." );
  }
  ulong start_slot;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, &params->v[ 0 ], "u64", &start_slot, &response ) ) ) return response;

  fd_rpc_val_t const * p1 = &params->v[ 1 ];
  fd_rpc_val_t none[1] = {{ .kind = FD_RPC_VAL_NONE }};
  ulong end_slot = ULONG_MAX;
  int   has_end  = 0;
  if( p1->kind==FD_RPC_VAL_INT ) {
    if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, p1, "u64", &end_slot, &response ) ) ) return response;
    has_end = 1;
  }
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, p1->kind==FD_RPC_VAL_MAP ? p1 : none, &bank_idx, &response ) ) ) return response;

  if( !has_end ) end_slot = start_slot<=ULONG_MAX-FD_RPC_GET_BLOCKS_MAX ? start_slot+FD_RPC_GET_BLOCKS_MAX : ULONG_MAX;
  if( FD_UNLIKELY( end_slot<start_slot ) ) return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":[],\"id\":%s}\n", id_cstr );
  if( FD_UNLIKELY( end_slot-start_slot>FD_RPC_GET_BLOCKS_MAX ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Slot range too large; max 500000" );
  }
  return fd_rpc_blocks_list( ctx, id_cstr, bank_idx, start_slot, end_slot, ULONG_MAX );
}

static fd_http_server_response_t
getBlocksWithLimit( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( params->kind!=FD_RPC_VAL_SEQ || params->cnt<2UL || params->cnt>3UL ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: expected [start_slot, limit, config?]." );
  }
  ulong start_slot;
  ulong limit;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, &params->v[ 0 ], "u64",   &start_slot, &response ) ) ) return response;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, &params->v[ 1 ], "usize", &limit,      &response ) ) ) return response;
  if( FD_UNLIKELY( limit>FD_RPC_GET_BLOCKS_MAX ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Limit too large; max 500000" );

  fd_rpc_val_t none[1] = {{ .kind = FD_RPC_VAL_NONE }};
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, none, &bank_idx, &response ) ) ) return response;
  if( FD_UNLIKELY( !limit ) ) return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":[],\"id\":%s}\n", id_cstr );
  return fd_rpc_blocks_list( ctx, id_cstr, bank_idx, start_slot, ULONG_MAX, limit );
}

static fd_http_server_response_t
getBlockTime( fd_rpc_tile_t *         ctx,
              char const *            id_cstr,
              fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_BLOCK_TIME, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 1, &response ) ) ) return response;

  ulong slot;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, &params->v[ 0 ], "u64", &slot, &response ) ) ) return response;

  if( FD_UNLIKELY( !slot && ctx->has_genesis_hash ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%ld,\"id\":%s}\n", ctx->genesis_creation_time, id_cstr );
  }

  if( FD_UNLIKELY( ctx->finalized_idx==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: banks uninitialized\"},\"id\":%s}\n", id_cstr );
  }
  bank_info_t const *         root  = &ctx->banks[ ctx->finalized_idx ];
  fd_rpc_block_time_t const * entry = fd_rpc_block_time_query( ctx, slot );

  if( slot>root->slot ) {
    if( FD_LIKELY( entry ) ) return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%ld,\"id\":%s}\n", entry->unix_timestamp, id_cstr );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Block not available for slot %lu\"},\"id\":%s}\n", FD_RPC_ERROR_BLOCK_NOT_AVAILABLE, slot, id_cstr );
  }

  int   rooted = -1;
  ulong lamports;
  int   executable;
  uchar owner[ 32UL ];
  ulong data_sz;
  fd_accdb_read_one_nocache( ctx->accdb, root->accdb_fork_id, fd_sysvar_slot_history_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_sz );
  fd_slot_history_view_t view[ 1 ];
  if( FD_LIKELY( lamports && fd_sysvar_slot_history_view( view, ctx->scratch.accdb_data_buf, data_sz ) ) ) {
    int found = fd_sysvar_slot_history_find_slot( view, slot );
    if(      found==FD_SLOT_HISTORY_SLOT_FOUND     ) rooted = 1;
    else if( found==FD_SLOT_HISTORY_SLOT_NOT_FOUND ) rooted = 0;
  }

  if( FD_LIKELY( entry && rooted!=0 ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%ld,\"id\":%s}\n", entry->unix_timestamp, id_cstr );
  }
  if( FD_UNLIKELY( slot>=root->slot ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Block not available for slot %lu\"},\"id\":%s}\n", FD_RPC_ERROR_BLOCK_NOT_AVAILABLE, slot, id_cstr );
  }
  if( FD_UNLIKELY( !rooted ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Slot %lu was skipped, or missing due to ledger jump to recent snapshot\"},\"id\":%s}\n", FD_RPC_ERROR_SLOT_SKIPPED, slot, id_cstr );
  }
  ulong first_available = fd_rpc_block_time_first_available( ctx );
  if( FD_UNLIKELY( slot<first_available ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Block %lu cleaned up, does not exist on node. First available block: %lu\"},\"id\":%s}\n", FD_RPC_ERROR_BLOCK_CLEANED_UP, slot, first_available, id_cstr );
  }
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}\n", id_cstr );
}

static fd_http_server_response_t
getClusterNodes( fd_rpc_tile_t *         ctx,
                 char const *            id_cstr,
                 fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_CLUSTER_NODES, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );

  for( fd_rpc_cluster_node_dlist_iter_t iter = fd_rpc_cluster_node_dlist_iter_rev_init( ctx->cluster_nodes_dlist, ctx->cluster_nodes );
       !fd_rpc_cluster_node_dlist_iter_done( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes );
       iter = fd_rpc_cluster_node_dlist_iter_rev_next( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes ) ) {
    fd_rpc_cluster_node_t * ele = fd_rpc_cluster_node_dlist_iter_ele( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes );
    FD_BASE58_ENCODE_32_BYTES( ele->identity.uc, identity_cstr );
    int is_last = fd_rpc_cluster_node_dlist_iter_done( fd_rpc_cluster_node_dlist_iter_rev_next( iter, ctx->cluster_nodes_dlist, ctx->cluster_nodes ), ctx->cluster_nodes_dlist, ctx->cluster_nodes );

    fd_http_server_printf( ctx->http, "{\"featureSet\":%u,", ele->ci->version.feature_set );

    for( ulong i=0UL; i<FD_GOSSIP_CONTACT_INFO_SOCKET_CNT; i++ ) {
      char const * name;
      switch( i ) {
        case FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP:            name = "gossip"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC: name = NULL; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_RPC:               name = "rpc"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_RPC_PUBSUB:        name = "pubsub"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR:      name = "serveRepair"; break;
        /* Even though Agave does not support "tpu" and "tpuForwards"
           (hardcoded null), Firedancer still supports
           UDP-TPU. */
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU:               name = "tpu"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS:      name = "tpuForwards"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC: name = "tpuForwardsQuic"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_QUIC:          name = "tpuQuic"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE:          name = "tpuVote"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TVU:               name = "tvu"; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TVU_QUIC:          name = NULL; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC:     name = NULL; break;
        case FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW:         name = NULL; break;
        default: FD_LOG_ERR(( "unreachable "));
      }
      if( FD_UNLIKELY( !name ) ) continue;

      uint ip4 = ele->ci->sockets[ i ].is_ipv6 ? 0U : ele->ci->sockets[ i ].ip4;
      if( FD_LIKELY( !!ip4 || !!ele->ci->sockets[ i ].port ) ) fd_http_server_printf( ctx->http, "\"%s\":\"" FD_IP4_ADDR_FMT ":%hu\",", name, FD_IP4_ADDR_FMT_ARGS( ip4 ), fd_ushort_bswap( ele->ci->sockets[ i ].port ) );
      else                                                     fd_http_server_printf( ctx->http, "\"%s\":null,", name );
    }
    fd_http_server_printf( ctx->http, "\"pubkey\":\"%s\",", identity_cstr );
    fd_http_server_printf( ctx->http, "\"shredVersion\":%u,", ele->ci->shred_version );

    char version[ 64UL ];
    FD_TEST( fd_gossip_version_cstr( ele->ci->version.major, ele->ci->version.minor, ele->ci->version.patch, version, sizeof( version ) ) );
    fd_http_server_printf( ctx->http, "\"version\":\"%s\",", version );

    char const * client_id;
    switch( ele->ci->version.client ) {
      case FD_GOSSIP_CONTACT_INFO_CLIENT_SOLANA_LABS:            client_id = "SolanaLabs";              break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_JITO_LABS:              client_id = "JitoLabs";                break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_FRANKENDANCER:          client_id = "Frankendancer";           break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_AGAVE:                  client_id = "Agave";                   break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_AGAVE_PALADIN:          client_id = "AgavePaladin";            break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER:             client_id = "Firedancer";              break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_AGAVE_BAM:              client_id = "AgaveBam";                break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_SIG:                    client_id = "Sig";                     break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_RAKURAI:                client_id = "Rakurai";                 break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_HARMONIC_FIREDANCER:    client_id = "HarmonicFiredancer";      break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_HARMONIC_AGAVE:         client_id = "HarmonicAgave";           break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_HARMONIC_FRANKENDANCER: client_id = "HarmonicFrankendancer";  break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_FIRE_BAM:               client_id = "FireBAM";                 break;
      case FD_GOSSIP_CONTACT_INFO_CLIENT_RAIKU:                  client_id = "Raiku";                   break;
      default:                                                   client_id = NULL;                      break;
    }
    if( FD_LIKELY( client_id ) ) fd_http_server_printf( ctx->http, "\"clientId\":\"%s\"", client_id );
    else                         fd_http_server_printf( ctx->http, "\"clientId\":\"Unknown(%hu)\"", ele->ci->version.client );

    if( FD_UNLIKELY( is_last ) ) fd_http_server_printf( ctx->http, "}" );
    else                         fd_http_server_printf( ctx->http, "}," );
  }

  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getEpochInfo( fd_rpc_tile_t *         ctx,
              char const *            id_cstr,
              fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_EPOCH_INFO, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                              1, /* has_commitment */
                                              0, /* has_encoding */
                                              0, /* has_data_slice */
                                              1, /* has_min_context_slot */
                                              &bank_idx,
                                              NULL,
                                              NULL,
                                              NULL,
                                              NULL,
                                              &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"absoluteSlot\":%lu,\"blockHeight\":%lu,\"epoch\":%lu,\"slotIndex\":%lu,\"slotsInEpoch\":%lu,\"transactionCount\":%lu},\"id\":%s}\n", ctx->banks[ bank_idx ].slot, ctx->banks[ bank_idx ].block_height, ctx->banks[ bank_idx ].epoch, ctx->banks[ bank_idx ].slot_in_epoch, ctx->banks[ bank_idx ].slots_per_epoch, ctx->banks[ bank_idx ].transaction_count, id_cstr );
}

static fd_http_server_response_t
getEpochSchedule( fd_rpc_tile_t *         ctx,
                  char const *            id_cstr,
                  fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_EPOCH_SCHEDULE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  if( FD_UNLIKELY( !ctx->has_epoch_schedule ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Firedancer Error: No epoch schedule\"},\"id\":%s}\n", FD_RPC_ERROR_NO_SNAPSHOT, id_cstr );
  }

  fd_epoch_schedule_t const * schedule = &ctx->epoch_schedule;
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"slotsPerEpoch\":%lu,\"leaderScheduleSlotOffset\":%lu,\"warmup\":%s,\"firstNormalEpoch\":%lu,\"firstNormalSlot\":%lu},\"id\":%s}\n",
                      schedule->slots_per_epoch, schedule->leader_schedule_slot_offset, schedule->warmup ? "true" : "false", schedule->first_normal_epoch, schedule->first_normal_slot, id_cstr );
}
static fd_http_server_response_t
getFeeForMessage( fd_rpc_tile_t *         ctx,
                  char const *            id_cstr,
                  fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 1 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  fd_rpc_val_t const * m = &params->v[ 0 ];
  if( FD_UNLIKELY( m->kind!=FD_RPC_VAL_STR ) ) return fd_rpc_err_invalid( ctx, id_cstr, "type", m, "a string" );
  if( FD_UNLIKELY( m->str.sz>4UL*FD_TXN_MTU_V0 ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: message too large." );
  uchar msg[ 3UL*FD_TXN_MTU_V0+3UL ];
  long  msg_sz = fd_base64_decode( msg, m->str.ptr, m->str.sz );
  if( FD_UNLIKELY( msg_sz<4L ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: message is not valid base64." );

  /* Wrap the message in a transaction with blank signatures so the
     transaction parser can validate it and find its instructions. */
  /* Legacy and v0 transactions are [signature count][signatures][message].
     A v1 transaction (first byte 0x81) is [message][signatures]. */
  int   is_v1   = msg[ 0 ]==(uchar)0x81;
  uchar sig_cnt = (msg[ 0 ] & 0x80) ? msg[ 1 ] : msg[ 0 ];
  if( FD_UNLIKELY( !sig_cnt || sig_cnt>12 ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: failed to deserialize message." );
  uchar payload[ 1UL+12UL*64UL+3UL*FD_TXN_MTU_V0+3UL ];
  ulong payload_sz;
  if( is_v1 ) {
    payload_sz = (ulong)msg_sz+(ulong)sig_cnt*64UL;
    memcpy( payload, msg, (ulong)msg_sz );
    memset( payload+msg_sz, 0, (ulong)sig_cnt*64UL );
  } else {
    payload_sz = 1UL+(ulong)sig_cnt*64UL+(ulong)msg_sz;
    payload[ 0 ] = sig_cnt;
    memset( payload+1UL, 0, (ulong)sig_cnt*64UL );
    memcpy( payload+1UL+(ulong)sig_cnt*64UL, msg, (ulong)msg_sz );
  }
  uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  if( FD_UNLIKELY( payload_sz>FD_TXN_MTU || !fd_txn_parse( payload, payload_sz, txn_buf, NULL ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: failed to deserialize message." );
  }
  fd_txn_t const * txn = (fd_txn_t const *)txn_buf;

  /* Signature fee: as fd_executor_calculate_fee.  Priority fee: the
     compute unit price times the compute unit limit, in micro-lamports
     rounded up. */
  ulong num_signatures = txn->signature_cnt;
  ulong cu_price = 0UL; int has_price = 0;
  ulong cu_limit = 0UL; int has_limit = 0;
  fd_pubkey_t const * accts = fd_type_pun_const( fd_txn_get_acct_addrs( txn, payload ) );
  for( ushort i=0; i<txn->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn->instr[ i ];
    fd_pubkey_t const *    prog  = &accts[ instr->program_id ];
    uchar const *          data  = payload+instr->data_off;
    if( !memcmp( prog->uc, fd_solana_keccak_secp_256k_program_id.uc,  32UL ) ||
        !memcmp( prog->uc, fd_solana_ed25519_sig_verify_program_id.uc, 32UL ) ||
        !memcmp( prog->uc, fd_solana_secp256r1_program_id.uc,          32UL ) ) {
      if( instr->data_sz ) num_signatures = fd_ulong_sat_add( num_signatures, (ulong)data[ 0 ] );
    } else if( !memcmp( prog->uc, fd_solana_compute_budget_program_id.uc, 32UL ) ) {
      if(      instr->data_sz==5UL && data[ 0 ]==2 ) { cu_limit = (ulong)FD_LOAD( uint,  data+1 ); has_limit = 1; }
      else if( instr->data_sz==9UL && data[ 0 ]==3 ) { cu_price =        FD_LOAD( ulong, data+1 ); has_price = 1; }
    }
  }
  ulong priority_fee = 0UL;
  if( txn->transaction_version==FD_TXN_V1 ) {
    /* v1 states its priority fee in lamports in the message header */
    ulong v1_cu_limit, v1_loaded, v1_heap;
    fd_txn_parse_v1_config( fd_uint_load_4( payload+4UL ), payload+txn->v1_txn_config_values_off, &priority_fee, &v1_cu_limit, &v1_loaded, &v1_heap );
  } else if( has_price && cu_price ) {
    /* Without an explicit limit the default depends on which of the
       transaction's programs are builtins on this bank, which this
       tile does not know.  Refuse rather than guess. */
    if( FD_UNLIKELY( !has_limit ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: cannot price a message that sets a compute unit price without a compute unit limit" );
    cu_limit = fd_ulong_min( cu_limit, 1400000UL );
    uint128 micro = (uint128)cu_price * (uint128)cu_limit;
    uint128 fee   = ( micro + (uint128)999999UL ) / (uint128)1000000UL;
    priority_fee  = fee>(uint128)ULONG_MAX ? ULONG_MAX : (ulong)fee;
  }
  ulong fee = fd_ulong_sat_add( fd_ulong_sat_mul( 5000UL, num_signatures ), priority_fee );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":%lu},\"id\":%s}\n", FD_RPC_AGAVE_API_VERSION, info->slot, fee, id_cstr );
}
/* Firedancer keeps no block store.  The oldest slot it has first-hand
   data for is the oldest one in its block time table, so report that. */
static fd_http_server_response_t
fd_rpc_first_slot( fd_rpc_tile_t *         ctx,
                   char const *            id_cstr,
                   fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;
  if( FD_UNLIKELY( ctx->block_time_first_slot==ULONG_MAX ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: banks uninitialized" );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", fd_rpc_block_time_first_available( ctx ), id_cstr );
}

static fd_http_server_response_t
getFirstAvailableBlock( fd_rpc_tile_t *         ctx,
                        char const *            id_cstr,
                        fd_rpc_params_t const * params ) {
  return fd_rpc_first_slot( ctx, id_cstr, params );
}

/* Get the genesis hash of the cluster.  Firedancer deviates slightly
   from Agave here, as the genesis hash is not always known when RPC
   is first booted, it may need to be determined asynchronously in the
   background, fetched from a peer node.  If the genesis hash is not yet
   known, we return an error indicating no snapshot is available. */

static fd_http_server_response_t
getGenesisHash( fd_rpc_tile_t *         ctx,
                char const *            id_cstr,
                fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_GENESIS_HASH, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  if( FD_UNLIKELY( !ctx->has_genesis_hash ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Firedancer Error: No genesis hash\"},\"id\":%s}\n", FD_RPC_ERROR_NO_SNAPSHOT, id_cstr );
  }

  FD_BASE58_ENCODE_32_BYTES( ctx->genesis_hash->uc, genesis_hash_b58 );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":%s}\n", genesis_hash_b58, id_cstr );
}

/* getAgGenesisCert returns the alpenglow genesis certificate, or null
   if Tower consensus is active still.

   The account holds a wincode encoded WireBlockCertMessage,

     u64   block.slot
     [u8;32]  block.block_id
     [u8;192] signature.signature   (uncompressed BLS signature)
     u64   signature.bitmap_len
     [u8]  signature.bitmap

   and the result is that struct as JSON, with the fixed size byte
   arrays and the bitmap encoded as arrays of numbers, or null if the
   account is empty or does not exist. */

#define FD_RPC_AG_GENESIS_CERT_HDR_SZ (8UL+32UL+FD_BLS_SIG_SZ+8UL)

static fd_http_server_response_t
getAgGenesisCert( fd_rpc_tile_t *         ctx,
                  char const *            id_cstr,
                  fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_AG_GENESIS_CERT, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  if( FD_UNLIKELY( ctx->finalized_idx==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: banks uninitialized\"},\"id\":%s}\n", id_cstr );
  }

  bank_info_t * info = &ctx->banks[ ctx->finalized_idx ];
  ulong acct_lamports;
  int   acct_executable;
  uchar acct_owner[ 32UL ];
  ulong acct_data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, ctx->fd_genesis_cert_addr->uc,
                             &acct_lamports, &acct_executable, acct_owner,
                             ctx->scratch.accdb_data_buf, &acct_data_len );
  if( FD_UNLIKELY( !acct_lamports || !acct_data_len ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}\n", id_cstr );
  }

  uchar const * data       = ctx->scratch.accdb_data_buf;
  ulong         bitmap_sz  = 0UL;
  int           malformed  = acct_data_len<FD_RPC_AG_GENESIS_CERT_HDR_SZ;
  if( FD_LIKELY( !malformed ) ) {
    bitmap_sz = FD_LOAD( ulong, data+FD_RPC_AG_GENESIS_CERT_HDR_SZ-8UL );
    malformed = bitmap_sz>acct_data_len-FD_RPC_AG_GENESIS_CERT_HDR_SZ;
  }
  if( FD_UNLIKELY( malformed ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Firedancer Error: malformed genesis certificate\"},\"id\":%s}\n", id_cstr );
  }

  uchar const * block_id  = data+8UL;
  uchar const * signature = block_id+32UL;
  uchar const * bitmap    = data+FD_RPC_AG_GENESIS_CERT_HDR_SZ;

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"block\":{\"slot\":%lu,\"blockId\":[", FD_LOAD( ulong, data ) );
  for( ulong i=0UL; i<32UL;         i++ ) fd_http_server_printf( ctx->http, i ? ",%u" : "%u", (uint)block_id [ i ] );
  fd_http_server_printf( ctx->http, "]},\"signature\":{\"signature\":[" );
  for( ulong i=0UL; i<FD_BLS_SIG_SZ; i++ ) fd_http_server_printf( ctx->http, i ? ",%u" : "%u", (uint)signature[ i ] );
  fd_http_server_printf( ctx->http, "],\"bitmap\":[" );
  for( ulong i=0UL; i<bitmap_sz;    i++ ) fd_http_server_printf( ctx->http, i ? ",%u" : "%u", (uint)bitmap   [ i ] );
  fd_http_server_printf( ctx->http, "]}},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

/* Determines if the node is healthy.  Agave defines this as follows,

    - On boot, nodes must go through the entire snapshot slot database
      and hash everything, and once it's done verify the hash matches.
      While this is ongoing, the node is unhealthy with a "slotsBehind"
      value of null.

    - On boot, if the cluster is restarting and we are currently waiting
      for a supermajority of stake to join gossip to proceed with
      booting, the node is forcibly marked as healthy, to, per Agave,

       > prevent load balancers from removing the node from their list
       > of candidates during a manual restart

    - In addition, once booted, there is a period where we do not yet
      know the cluster confirmed slot, because we have not yet observed
      any (or enough) votes arrive from peers in the cluster.  During
      this period the node is unhealthy with a "slotsBehind" value of
      null.

    - Finally, once the cluster confirmed slot is known, which is the
      highest optimistically confirmed slot observed from both gossip,
      and votes processed in blocks, it is compared to our own
      optimistically confirmed slot, which is just the highest slot down
      the cluster confirmed fork that we have finished replaying
      locally.  The difference between these two slots is compared, and
      if it is less than or equal to 128, the node is healthy, otherwise
      it is unhealthy with a "slotsBehind" value equal to the
      difference.

   Under alpenglow there are no optimistic confirmations.  The cluster
   slot is instead the highest slot for which votor has observed a
   finalization certificate (slow or fast), and the node stays Unknown
   until it has seen one.

   Firedancer currently only implements the final two checks, and does
   not forcibly mark the node as healthy while waiting for a
   supermajority, nor does it mark a node as unhealthy while hashing the
   snapshot database on boot.  Firedancer hashes snapshots so quickly
   that the node will die on boot if the hash is not valid. */

static inline int
_getHealth( fd_rpc_tile_t * ctx ) {
  /* Requests are not served until RPC has initialized banks */
  if( FD_UNLIKELY( ctx->confirmed_idx==ULONG_MAX ) ) return FD_RPC_HEALTH_STATUS_UNKNOWN;
  if( FD_UNLIKELY( ctx->cluster_confirmed_slot==ULONG_MAX ) ) return FD_RPC_HEALTH_STATUS_UNKNOWN;

  ulong slots_behind = fd_ulong_sat_sub( ctx->cluster_confirmed_slot, ctx->banks[ ctx->confirmed_idx ].slot );
  if( FD_LIKELY( slots_behind<=FD_RPC_HEALTH_CHECK_SLOT_DISTANCE ) ) return FD_RPC_HEALTH_STATUS_OK;
  else                                                               return FD_RPC_HEALTH_STATUS_BEHIND;
}

static fd_http_server_response_t
getHealth( fd_rpc_tile_t *         ctx,
           char const *            id_cstr,
           fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_HEALTH, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  // TODO: We should probably implement the same waiting_for_supermajority
  // logic to conform with Agave here.

  int health_status = _getHealth( ctx );

  switch( health_status ) {
    case FD_RPC_HEALTH_STATUS_UNKNOWN: return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Node is unhealthy\",\"data\":{\"slotsBehind\":null}},\"id\":%s}\n", FD_RPC_ERROR_NODE_UNHEALTHY, id_cstr );
    case FD_RPC_HEALTH_STATUS_BEHIND:  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Node is unhealthy\",\"data\":{\"slotsBehind\":%lu}},\"id\":%s}\n", FD_RPC_ERROR_NODE_UNHEALTHY, fd_ulong_sat_sub( ctx->cluster_confirmed_slot, ctx->banks[ ctx->confirmed_idx ].slot ), id_cstr );
    case FD_RPC_HEALTH_STATUS_OK:      return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":%s}\n", id_cstr );
    default: FD_LOG_ERR(( "unknown health status" ));
  }
}

/* The newest full snapshot this node has on disk and the newest
   incremental built on it, as reported by the snapshot writer.  A node
   that does not write snapshots has nothing to report. */
static fd_http_server_response_t
getHighestSnapshotSlot( fd_rpc_tile_t *         ctx,
                        char const *            id_cstr,
                        fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;
  ulong full = ULONG_MAX, incr = ULONG_MAX;
  for( ulong i=0UL; i<ctx->snap_cnt; i++ ) if( ctx->snaps[ i ].base==ULONG_MAX && ( full==ULONG_MAX || ctx->snaps[ i ].slot>full ) ) full = ctx->snaps[ i ].slot;
  if( FD_UNLIKELY( full==ULONG_MAX ) ) return fd_rpc_err_msg( ctx, id_cstr, -32008, "No snapshot" );
  for( ulong i=0UL; i<ctx->snap_cnt; i++ ) if( ctx->snaps[ i ].base==full && ( incr==ULONG_MAX || ctx->snaps[ i ].slot>incr ) ) incr = ctx->snaps[ i ].slot;
  if( incr!=ULONG_MAX ) return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"full\":%lu,\"incremental\":%lu},\"id\":%s}\n", full, incr, id_cstr );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"full\":%lu,\"incremental\":null},\"id\":%s}\n", full, id_cstr );
}

static fd_http_server_response_t
getIdentity( fd_rpc_tile_t *         ctx,
             char const *            id_cstr,
             fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_IDENTITY, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  FD_BASE58_ENCODE_32_BYTES( ctx->identity_pubkey, identity_pubkey_b58 );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"identity\":\"%s\"},\"id\":%s}\n", identity_pubkey_b58, id_cstr );
}

static fd_http_server_response_t
getInflationGovernor( fd_rpc_tile_t *         ctx,
                      char const *            id_cstr,
                      fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_INFLATION_GOVERNOR, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  if( FD_UNLIKELY( !fd_rpc_validate_commitment_strict( ctx, id_cstr, config, &response ) ) ) return response;
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct CommitmentConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             0, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  bank_info_t const * bank = &ctx->banks[ bank_idx ];
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"foundation\":%g%s,\"foundationTerm\":%g%s,\"initial\":%g%s,\"taper\":%g%s,\"terminal\":%g%s},\"id\":%s}\n",
                           bank->inflation.foundation, bank->inflation.foundation==0 ? ".0" : "",
                           bank->inflation.foundation_term, bank->inflation.foundation_term==0 ? ".0" : "",
                           bank->inflation.initial, bank->inflation.initial==0 ? ".0" : "",
                           bank->inflation.taper, bank->inflation.taper==0 ? ".0" : "",
                           bank->inflation.terminal, bank->inflation.terminal==0 ? ".0" : "",
                           id_cstr );
}

static fd_http_server_response_t
getInflationRate( fd_rpc_tile_t *         ctx,
                  char const *            id_cstr,
                  fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;
  if( FD_UNLIKELY( ctx->finalized_idx==ULONG_MAX || !ctx->has_epoch_schedule || !ctx->ns_per_slot ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: banks uninitialized" );
  bank_info_t const * bank = &ctx->banks[ ctx->finalized_idx ];

  /* Years of inflation elapsed, counted in slots from slot 0.  This is
     right for clusters where inflation started at genesis; one that
     enabled inflation later (mainnet) needs the activation slot of its
     inflation feature subtracted, which this tile is not told. */
  double slots_per_year = 365.242199*24.0*3600.0*1e9 / (double)ctx->ns_per_slot; /* Agave SECONDS_PER_YEAR */
  double year           = (double)fd_epoch_slot0( &ctx->epoch_schedule, bank->epoch+1UL ) / slots_per_year;
  double tapered        = bank->inflation.initial * pow( 1.0-bank->inflation.taper, year );
  double total          = tapered>bank->inflation.terminal ? tapered : bank->inflation.terminal;
  double foundation     = year<bank->inflation.foundation_term ? total*bank->inflation.foundation : 0.0;
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"epoch\":%lu,\"foundation\":%.17g,\"total\":%.17g,\"validator\":%.17g},\"id\":%s}\n",
                      bank->epoch, foundation, total, total-foundation, id_cstr );
}
static fd_http_server_response_t
getInflationReward( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_rpc_val_t const * addrs = &params->v[ 0 ];
  if( FD_UNLIKELY( addrs->kind!=FD_RPC_VAL_SEQ ) ) return fd_rpc_err_invalid( ctx, id_cstr, "type", addrs, "a sequence" );

  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_validate_config( ctx, id_cstr, &params->v[ 1 ], "struct RpcEpochConfig", 1, 0, 0, 1, &bank_idx, NULL, NULL, NULL, NULL, &response ) ) ) return response;
  if( FD_UNLIKELY( !ctx->has_epoch_schedule ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: banks uninitialized" );
  bank_info_t const * bank = &ctx->banks[ bank_idx ];

  /* Default: the epoch before the one the queried bank is in. */
  ulong epoch = bank->epoch ? bank->epoch-1UL : 0UL;
  fd_rpc_val_t ev[1];
  if( fd_rpc_cfg_member( &params->v[ 1 ], "epoch", ev ) && ev->kind!=FD_RPC_VAL_NULL ) {
    if( FD_UNLIKELY( ev->kind!=FD_RPC_VAL_INT || ev->neg ) ) return fd_rpc_err_invalid( ctx, id_cstr, "type", ev, "u64" );
    epoch = ev->u;
  }

  /* Agave checks every address before it looks for the rewards. */
  {
    ulong addr_cnt = 0UL;
    fd_jtok_t j[1];
    fd_jtok_arr_enter( fd_jtok_init( j, addrs->raw, addrs->raw_sz ) );
    while( fd_jtok_arr_next( j ) ) {
      fd_rpc_val_t v[1]; fd_rpc_val_read( j, v );
      fd_pubkey_t  key;
      if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, v, &key, &response ) ) ) return response;
      if( FD_UNLIKELY( ++addr_cnt>32UL ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Too many inputs provided; max 32" );
    }
  }

  /* Rewards earned in epoch are paid at the start of the next one.
     Agave reads them back out of those blocks, and fails the request
     if it does not have the first one. */
  ulong pay_slot0 = fd_epoch_slot0( &ctx->epoch_schedule, epoch+1UL );
  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, bank, &next_slot ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: slot history unavailable" );
  fd_rpc_reward_epoch_t const * t = epoch+1UL<=bank->epoch ? fd_rpc_reward_table( ctx, epoch, 0 ) : NULL;
  if( FD_UNLIKELY( pay_slot0<fd_rpc_slot_history_oldest( next_slot ) ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Block %lu cleaned up, does not exist on node. First available block: %lu\"},\"id\":%s}\n",
                        FD_RPC_ERROR_BLOCK_CLEANED_UP, pay_slot0, fd_rpc_slot_history_oldest( next_slot ), id_cstr );
  }
  if( FD_UNLIKELY( !t || t->incomplete ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Block not available for slot %lu\"},\"id\":%s}\n", FD_RPC_ERROR_BLOCK_NOT_AVAILABLE, pay_slot0, id_cstr );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  fd_jtok_t j[1];
  ulong n = 0UL;
  fd_jtok_arr_enter( fd_jtok_init( j, addrs->raw, addrs->raw_sz ) );
  while( fd_jtok_arr_next( j ) ) {
    fd_rpc_val_t v[1]; fd_rpc_val_read( j, v );
    char  key_cstr[ 64 ];
    uchar key[ 32 ];
    if( FD_UNLIKELY( !fd_rpc_val_cstr( v, key_cstr, sizeof(key_cstr) ) || !fd_base58_decode_32( key_cstr, key ) ) ) {
      fd_http_server_unstage( ctx->http );
      return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: Invalid" );
    }
    if( n++ ) fd_http_server_printf( ctx->http, "," );
    fd_rpc_reward_ent_t const * hit = NULL;
    ulong idx = fd_ulong_hash( FD_LOAD( ulong, key ) ^ FD_LOAD( ulong, key+8UL ) ) & (FD_RPC_REWARD_ENT_CNT-1UL);
    for( ; t->ents[ idx ].slot; idx = (idx+1UL) & (FD_RPC_REWARD_ENT_CNT-1UL) ) {
      fd_rpc_reward_ent_t const * e = &t->ents[ idx ];
      if( memcmp( e->pubkey, key, 32UL ) ) continue;
      /* only a block on the queried fork counts */
      if( e->slot==bank->slot || fd_rpc_slot_history_has( ctx, next_slot, e->slot ) ) { hit = e; break; }
    }
    if( !hit ) { fd_http_server_printf( ctx->http, "null" ); continue; }
    fd_http_server_printf( ctx->http, "{\"amount\":%lu,\"blockRewardAmount\":null,\"commission\":null,\"effectiveSlot\":%lu,\"epoch\":%lu,\"postBalance\":%lu}",
                           hit->amount, hit->slot, epoch, hit->post_balance );
  }
  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getLatestBlockhash( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_LATEST_BLOCKHASH, 1UL );

  if( FD_UNLIKELY( ctx->processed_idx==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32065,\"message\":\"Firedancer Error: banks uninitialized\"},\"id\":%s}\n", id_cstr );
  }

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  bank_info_t * bank = &ctx->banks[ bank_idx ];
  FD_BASE58_ENCODE_32_BYTES( bank->block_hash, block_hash_b58 );

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":%lu,\"apiVersion\":\"%s\"},\"value\":{\"blockhash\":\"%s\",\"lastValidBlockHeight\":%lu}},\"id\":%s}\n", bank->slot, FD_RPC_AGAVE_API_VERSION, block_hash_b58, bank->block_height + 150UL, id_cstr );
}

/* Order getLeaderSchedule pairs by identity, breaking ties by rotation
   so each identity's rotations end up ascending (matching Agave, which
   folds the per-slot leaders into the result in slot order). */
#define SORT_NAME        sort_gls_pairs_by_id
#define SORT_KEY_T       fd_rpc_gls_pair_t
#define SORT_BEFORE(a,b) ( memcmp( (a).id_key.uc, (b).id_key.uc, sizeof(fd_pubkey_t) )<0 ? 1 : \
                           memcmp( (a).id_key.uc, (b).id_key.uc, sizeof(fd_pubkey_t) )>0 ? 0 : \
                           (a).rot<(b).rot )
#include "../../util/tmpl/fd_sort.c"

static fd_http_server_response_t
getLeaderSchedule( fd_rpc_tile_t *         ctx,
                   char const *            id_cstr,
                   fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_LEADER_SCHEDULE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 2, &response ) ) ) return response;

  fd_rpc_val_t const * p0             = &params->v[ 0 ];
  fd_rpc_val_t const * config         = &params->v[ 1 ];
  ulong                req_slot       = 0UL;
  int                  have_slot      = 0;
  int                  wrapper_config = 0;
  if( p0->kind==FD_RPC_VAL_NONE || p0->kind==FD_RPC_VAL_NULL ) {
    /* config stays the second param */
  } else if( p0->kind==FD_RPC_VAL_INT && !p0->neg ) {
    req_slot  = p0->u;
    have_slot = 1;
  } else if( p0->kind==FD_RPC_VAL_MAP ) {
    config         = p0;
    wrapper_config = 1;

    /* Clients can pass a second config object, which also needs
       validation. */
    fd_rpc_val_t const * fallback_config = &params->v[ 1 ];
    if( fallback_config->kind!=FD_RPC_VAL_NONE ) {
      ulong        fallback_bank_idx = ULONG_MAX;
      fd_rpc_val_t fallback_identity[1];
      int fallback_config_valid = fd_rpc_validate_config( ctx, id_cstr, fallback_config, "struct RpcLeaderScheduleConfig",
                                                          1, /* has_commitment */
                                                          0, /* has_encoding */
                                                          0, /* has_data_slice */
                                                          0, /* has_min_context_slot */
                                                          &fallback_bank_idx,
                                                          NULL,
                                                          NULL,
                                                          NULL,
                                                          fallback_identity,
                                                          &response );
      if( FD_UNLIKELY( !fallback_config_valid ) ) return response;

      if( FD_UNLIKELY( fallback_identity->kind!=FD_RPC_VAL_NONE && fallback_identity->kind!=FD_RPC_VAL_NULL && fallback_identity->kind!=FD_RPC_VAL_STR ) ) {
        return fd_rpc_err_invalid( ctx, id_cstr, "type", fallback_identity, "a string" );
      }
    }
  } else {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: data did not match any variant of untagged enum RpcLeaderScheduleConfigWrapper.\"},\"id\":%s}\n", id_cstr );
  }

  ulong        bank_idx = ULONG_MAX;
  fd_rpc_val_t identity[1];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcLeaderScheduleConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             0, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             identity,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) {
    if( !wrapper_config ) return response;
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: data did not match any variant of untagged enum RpcLeaderScheduleConfigWrapper.\"},\"id\":%s}\n", id_cstr );
  }

  /* Optional identity filter: restrict the result to a single validator. */
  int         have_identity = 0;
  fd_pubkey_t identity_filter[ 1 ];
  if( identity->kind!=FD_RPC_VAL_NONE && identity->kind!=FD_RPC_VAL_NULL ) {
    if( FD_UNLIKELY( wrapper_config && identity->kind!=FD_RPC_VAL_STR ) ) {
      return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: data did not match any variant of untagged enum RpcLeaderScheduleConfigWrapper.\"},\"id\":%s}\n", id_cstr );
    }
    if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, identity, identity_filter, &response ) ) ) return response;
    have_identity = 1;
  }

  ulong slot = have_slot ? req_slot : ctx->banks[ bank_idx ].slot;
  fd_epoch_leaders_t const * lsched = fd_rpc_mleaders_get_lsched_for_slot( ctx->mleaders, slot );
  if( FD_UNLIKELY( !lsched ) ) {
    /* Unlike getSlotLeader(s), Agave returns a null result (not an
       error) when the requested epoch's schedule is unavailable. */
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}\n", id_cstr );
  }

  ulong pub_cnt   = lsched->pub_cnt;
  ulong sched_cnt = lsched->sched_cnt;
  ulong slot_cnt  = lsched->slot_cnt;
  FD_TEST( pub_cnt<=MAX_STAKE_WEIGHTS );
  FD_TEST( sched_cnt<=(sizeof(ctx->scratch.gls_pairs)/sizeof(ctx->scratch.gls_pairs[0])) );

  fd_rpc_gls_pair_t * pairs    = ctx->scratch.gls_pairs;
  ulong               pair_cnt = 0UL;
  for( ulong r=0UL; r<sched_cnt; r++ ) {
    ulong idx = lsched->sched[ r ];
    if( FD_UNLIKELY( idx>=pub_cnt ) ) continue; /* indeterminate leader; not reported */
    if( have_identity && 0!=memcmp( lsched->pub[ idx ].uc, identity_filter->uc, sizeof(fd_pubkey_t) ) ) continue;
    pairs[ pair_cnt ].id_key = lsched->pub[ idx ];
    pairs[ pair_cnt ].rot    = (uint)r;
    pair_cnt++;
  }
  sort_gls_pairs_by_id_inplace( pairs, pair_cnt );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{" );
  int first = 1;
  for( ulong i=0UL; i<pair_cnt; ) {
    /* [i,j) is the run of pairs sharing pairs[i].id_key (one identity). */
    ulong j = i+1UL;
    while( j<pair_cnt && 0==memcmp( pairs[ j ].id_key.uc, pairs[ i ].id_key.uc, sizeof(fd_pubkey_t) ) ) j++;

    FD_BASE58_ENCODE_32_BYTES( pairs[ i ].id_key.uc, pub_b58 );
    fd_http_server_printf( ctx->http, "%s\"%s\":[", first ? "" : ",", pub_b58 );
    first = 0;

    int first_slot = 1;
    for( ulong b=i; b<j; b++ ) {
      ulong r = pairs[ b ].rot;
      for( ulong k=0UL; k<FD_EPOCH_SLOTS_PER_ROTATION; k++ ) {
        ulong rel = r*FD_EPOCH_SLOTS_PER_ROTATION + k;
        if( FD_UNLIKELY( rel>=slot_cnt ) ) break;
        fd_http_server_printf( ctx->http, "%s%lu", first_slot ? "" : ",", rel );
        first_slot = 0;
      }
    }
    fd_http_server_printf( ctx->http, "]" );
    i = j;
  }
  fd_http_server_printf( ctx->http, "},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getMaxRetransmitSlot( fd_rpc_tile_t *         ctx,
                      char const *            id_cstr,
                      fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_MAX_RETRANSMIT_SLOT, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  ulong max_retransmit_slot = 0UL;
  for( ulong i=0UL; i<ctx->shred_rtx_cnt; i++ ) {
    ulong slot = fd_fseq_query( ctx->shred_rtx[ i ] );
    if( FD_LIKELY( slot!=ULONG_MAX ) ) max_retransmit_slot = fd_ulong_max( max_retransmit_slot, slot );
  }
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", max_retransmit_slot, id_cstr );
}

/* Firedancer does not track a separate shred-insert high-water mark.
   The highest slot retransmitted is a lower bound for it. */
static fd_http_server_response_t
getMaxShredInsertSlot( fd_rpc_tile_t *         ctx,
                       char const *            id_cstr,
                       fd_rpc_params_t const * params ) {
  return getMaxRetransmitSlot( ctx, id_cstr, params );
}


static fd_http_server_response_t
getMinimumBalanceForRentExemption( fd_rpc_tile_t *         ctx,
                                   char const *            id_cstr,
                                   fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_MINIMUM_BALANCE_FOR_RENT_EXEMPTION, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  if( FD_UNLIKELY( !fd_rpc_validate_commitment_strict( ctx, id_cstr, config, &response ) ) ) return response;
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct CommitmentConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             0, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  fd_rpc_val_t const * acct_sz = &params->v[ 0 ];
  ulong acct_sz_val;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, acct_sz, "usize", &acct_sz_val, &response ) ) ) return response;
  if( FD_UNLIKELY( acct_sz_val>FD_RUNTIME_ACC_SZ_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
  }

  bank_info_t const * bank = &ctx->banks[ bank_idx ];

  fd_rent_t rent = {
    .lamports_per_uint8_year = bank->rent.lamports_per_uint8_year,
    .exemption_threshold = bank->rent.exemption_threshold,
    .burn_percent = bank->rent.burn_percent,
  };
  ulong minimum = fd_rent_exempt_minimum_balance( &rent, acct_sz_val );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", minimum, id_cstr );
}

static fd_http_server_response_t
getMultipleAccounts( fd_rpc_tile_t *         ctx,
                     char const *            id_cstr,
                     fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_MULTIPLE_ACCOUNTS, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;

  fd_rpc_val_t const * keys_arr = &params->v[ 0 ];
  if( FD_UNLIKELY( keys_arr->kind!=FD_RPC_VAL_SEQ ) ) {
    return fd_rpc_err_invalid( ctx, id_cstr, "type", keys_arr, "a sequence" );
  }

  fd_rpc_val_t keys[ 100UL ];
  ulong        cnt = 0UL;
  fd_jtok_t j[1];
  fd_jtok_arr_enter( fd_jtok_init( j, keys_arr->raw, keys_arr->raw_sz ) );
  while( fd_jtok_arr_next( j ) ) {
    if( cnt<100UL ) fd_rpc_val_read( j, &keys[ cnt ] );
    cnt++;
  }
  if( FD_UNLIKELY( cnt>100UL ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Too many inputs provided; max 100\"},\"id\":%s}\n", id_cstr );
  }

  ulong bank_idx = ULONG_MAX;
  char const * encoding_cstr = NULL;
  ulong slice_length = ULONG_MAX;
  ulong slice_offset = 0;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcAccountInfoConfig",
                                             1, 1, 1, 1,
                                             &bank_idx, &encoding_cstr,
                                             &slice_length, &slice_offset,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  /* Agave defaults getMultipleAccounts to base64 (getAccountInfo to binary) */
  fd_rpc_config_t cfg[1];
  fd_rpc_config_read( config, cfg );
  if( cfg->encoding.kind==FD_RPC_VAL_NONE || cfg->encoding.kind==FD_RPC_VAL_NULL ) encoding_cstr = "base64";

  bank_info_t * info = &ctx->banks[ bank_idx ];

  fd_pubkey_t addresses[ 100UL ];
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &keys[ i ], &addresses[ i ], &response ) ) ) return response;
  }

  fd_http_server_printf( ctx->http,
      "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":[",
      id_cstr, FD_RPC_AGAVE_API_VERSION, info->slot );

  for( ulong i=0UL; i<cnt; i++ ) {
    if( i>0UL ) fd_http_server_printf( ctx->http, "," );

    ulong acct_lamports;
    int   acct_executable;
    uchar acct_owner[ 32UL ];
    ulong acct_data_len;
    fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, addresses[i].uc,
                               &acct_lamports, &acct_executable, acct_owner,
                               ctx->scratch.accdb_data_buf, &acct_data_len );
    if( FD_UNLIKELY( !acct_lamports ) ) {
      fd_http_server_printf( ctx->http, "null" );
      continue;
    }

    fd_http_server_response_t err_response;
    ctx->encode_key = addresses[ i ].uc;
    int encoded = fd_rpc_encode_account_data( ctx, ctx->scratch.accdb_data_buf, acct_data_len, acct_owner, acct_lamports, acct_executable, encoding_cstr, slice_offset, slice_length, id_cstr, &err_response );
    ctx->encode_key = NULL;
    if( FD_UNLIKELY( !encoded ) ) {
      return err_response;
    }
  }

  fd_http_server_printf( ctx->http, "]}}\n" );
  return STAGE_JSON( ctx );
}

/* ---- account scans -------------------------------------------------------
   Firedancer keeps no secondary index of accounts by owner, so these
   calls walk every account.  That is what Agave does too when it runs
   without account indexes.  The walk blocks this tile for its duration
   (seconds on a database of millions of accounts). */

typedef int (*fd_rpc_scan_fn_t)( fd_rpc_tile_t * ctx,
                                 void *          arg,
                                 uchar const *   pubkey,
                                 ulong           lamports,
                                 int             executable,
                                 uchar const *   owner,
                                 uchar const *   data,      /* NULL unless need_data */
                                 ulong           data_len );

/* fd_rpc_scan calls fn for every account visible on the bank's fork.
   owner_filter, if not NULL, restricts it to accounts of that owner.
   min_data_len skips smaller accounts before their data is read.  fn
   returns 0 to stop the scan early.  Returns 0 if fn stopped it. */
static int
fd_rpc_scan( fd_rpc_tile_t *     ctx,
             bank_info_t const * info,
             uchar const *       owner_filter,
             ulong               min_data_len,
             int                 need_data,
             fd_rpc_scan_fn_t    fn,
             void *              arg ) {
  ulong chain_cnt = fd_accdb_scan_chain_cnt( ctx->accdb );
  ulong cursor    = 0UL;
  while( cursor<chain_cnt ) {
    ulong n = fd_accdb_scan_keys( ctx->accdb, &cursor, ctx->scan_keys, FD_RPC_SCAN_KEYS_MAX, FD_RPC_SCAN_CHAIN_BUDGET );
    for( ulong i=0UL; i<n; i++ ) {
      uchar const * key = ctx->scan_keys+i*32UL;
      uchar owner[ 32UL ];
      ulong data_len = 0UL;
      ulong lamports = 0UL;
      int   executable = 0;
      if( owner_filter || !need_data ) {
        fd_accdb_read_one_meta( ctx->accdb, info->accdb_fork_id, key, owner, &data_len );
        if( owner_filter && memcmp( owner, owner_filter, 32UL ) ) continue;
        if( data_len<min_data_len ) continue;
      }
      if( need_data ) {
        fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, key, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
        if( owner_filter && memcmp( owner, owner_filter, 32UL ) ) continue;
        if( data_len<min_data_len ) continue;
      } else {
        lamports = fd_accdb_lamports( ctx->accdb, info->accdb_fork_id, key );
      }
      if( !lamports ) continue; /* not on this fork, or deleted */
      if( FD_UNLIKELY( !fn( ctx, arg, key, lamports, executable, owner, need_data ? ctx->scratch.accdb_data_buf : NULL, data_len ) ) ) return 0;
    }
  }
  return 1;
}

/* Generic base58 decode for short filter values.  Returns the decoded
   length, or ULONG_MAX on a bad character or overflow. */
static ulong
fd_rpc_base58_decode( char const * in,
                      ulong        in_len,
                      uchar *      out,
                      ulong        out_max ) {
  static char const alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  static uchar tmp[ 2UL*FD_TXN_MTU_V0 ];
  ulong tmp_len = 0UL;
  ulong zeros   = 0UL;
  while( zeros<in_len && in[ zeros ]=='1' ) zeros++;
  for( ulong i=zeros; i<in_len; i++ ) {
    char const * p = in[ i ] ? strchr( alphabet, in[ i ] ) : NULL;
    if( FD_UNLIKELY( !p ) ) return ULONG_MAX;
    uint carry = (uint)( p-alphabet );
    for( ulong k=0UL; k<tmp_len; k++ ) {
      carry += (uint)tmp[ k ]*58U;
      tmp[ k ] = (uchar)( carry & 0xffU );
      carry >>= 8;
    }
    while( carry ) {
      if( FD_UNLIKELY( tmp_len==sizeof(tmp) ) ) return ULONG_MAX;
      tmp[ tmp_len++ ] = (uchar)( carry & 0xffU );
      carry >>= 8;
    }
  }
  if( FD_UNLIKELY( zeros+tmp_len>out_max ) ) return ULONG_MAX;
  memset( out, 0, zeros );
  for( ulong k=0UL; k<tmp_len; k++ ) out[ zeros+k ] = tmp[ tmp_len-1UL-k ];
  return zeros+tmp_len;
}

#define FD_RPC_GPA_FILTER_MAX       (4UL)
#define FD_RPC_GPA_MEMCMP_BYTES_MAX (128UL)

struct fd_rpc_gpa_filter {
  int   is_memcmp;  /* else dataSize */
  ulong data_size;
  ulong offset;
  ulong bytes_len;
  uchar bytes[ FD_RPC_GPA_MEMCMP_BYTES_MAX ];
};
typedef struct fd_rpc_gpa_filter fd_rpc_gpa_filter_t;

struct fd_rpc_gpa_arg {
  char const *        id_cstr;
  char const *        encoding_cstr;
  ulong               slice_offset;
  ulong               slice_length;
  ulong               filter_cnt;
  fd_rpc_gpa_filter_t filters[ FD_RPC_GPA_FILTER_MAX ];
  ulong               printed;
  int                 failed;
  fd_http_server_response_t err;
  /* token scans */
  int                 token_mode;      /* 0 none, 1 by owner, 2 by delegate */
  uchar               token_key[ 32 ];
  int                 has_mint;
  uchar               mint[ 32 ];
};
typedef struct fd_rpc_gpa_arg fd_rpc_gpa_arg_t;

/* Parses the "filters" array of a getProgramAccounts config.  Returns 1
   on success, 0 with *res set on a malformed filter. */
static int
fd_rpc_gpa_filters_read( fd_rpc_tile_t *             ctx,
                         char const *                id_cstr,
                         fd_rpc_val_t const *        config,
                         fd_rpc_gpa_arg_t *          arg,
                         fd_http_server_response_t * res ) {
  arg->filter_cnt = 0UL;
  fd_rpc_val_t filters[1];
  if( !fd_rpc_cfg_member( config, "filters", filters ) || filters->kind==FD_RPC_VAL_NULL ) return 1;
  if( FD_UNLIKELY( filters->kind!=FD_RPC_VAL_SEQ ) ) { *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: filters must be an array." ); return 0; }

  fd_jtok_t j[1];
  fd_jtok_arr_enter( fd_jtok_init( j, filters->raw, filters->raw_sz ) );
  while( fd_jtok_arr_next( j ) ) {
    fd_rpc_val_t f[1];
    fd_rpc_val_read( j, f );
    if( FD_UNLIKELY( arg->filter_cnt==FD_RPC_GPA_FILTER_MAX ) ) { *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Too many filters provided; max 4" ); return 0; }
    fd_rpc_gpa_filter_t * out = &arg->filters[ arg->filter_cnt ];
    memset( out, 0, sizeof(*out) );

    fd_rpc_val_t v[1];
    if( fd_rpc_cfg_member( f, "dataSize", v ) ) {
      if( FD_UNLIKELY( v->kind!=FD_RPC_VAL_INT || v->neg ) ) { *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: dataSize must be an unsigned integer." ); return 0; }
      out->data_size = v->u;
    } else if( fd_rpc_cfg_member( f, "memcmp", v ) && v->kind==FD_RPC_VAL_MAP ) {
      fd_rpc_val_t off[1], bytes[1], enc[1];
      if( FD_UNLIKELY( !fd_rpc_cfg_member( v, "offset", off ) || off->kind!=FD_RPC_VAL_INT || off->neg ||
                       !fd_rpc_cfg_member( v, "bytes", bytes ) || bytes->kind!=FD_RPC_VAL_STR ) ) {
        *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: memcmp needs an offset and a bytes string." ); return 0;
      }
      char bytes_cstr[ 256 ];
      if( FD_UNLIKELY( !fd_rpc_val_cstr( bytes, bytes_cstr, sizeof(bytes_cstr) ) ) ) { *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: memcmp bytes too long." ); return 0; }
      char enc_cstr[ 16 ] = "base58";
      if( fd_rpc_cfg_member( v, "encoding", enc ) && enc->kind==FD_RPC_VAL_STR ) fd_rpc_val_cstr( enc, enc_cstr, sizeof(enc_cstr) );
      ulong len;
      if( !strcmp( enc_cstr, "base64" ) ) {
        ulong in_len = strlen( bytes_cstr );
        if( FD_UNLIKELY( (ulong)FD_BASE64_DEC_SZ( in_len )>FD_RPC_GPA_MEMCMP_BYTES_MAX ) ) len = ULONG_MAX;
        else {
          long dec = fd_base64_decode( out->bytes, bytes_cstr, in_len );
          len = dec<0L ? ULONG_MAX : (ulong)dec;
        }
      } else {
        len = fd_rpc_base58_decode( bytes_cstr, strlen( bytes_cstr ), out->bytes, FD_RPC_GPA_MEMCMP_BYTES_MAX );
      }
      if( FD_UNLIKELY( len==ULONG_MAX ) ) { *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: memcmp bytes could not be decoded (max 128 bytes)." ); return 0; }
      out->is_memcmp = 1;
      out->offset    = off->u;
      out->bytes_len = len;
    } else {
      *res = fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: unsupported filter (supported: memcmp, dataSize)." ); return 0;
    }
    arg->filter_cnt++;
  }
  return 1;
}

static int
fd_rpc_gpa_emit( fd_rpc_tile_t * ctx,
                 void *          _arg,
                 uchar const *   pubkey,
                 ulong           lamports,
                 int             executable,
                 uchar const *   owner,
                 uchar const *   data,
                 ulong           data_len ) {
  fd_rpc_gpa_arg_t * arg = _arg;
  for( ulong i=0UL; i<arg->filter_cnt; i++ ) {
    fd_rpc_gpa_filter_t const * f = &arg->filters[ i ];
    if( f->is_memcmp ) {
      if( f->offset>data_len || f->bytes_len>data_len-f->offset ) return 1;
      if( memcmp( data+f->offset, f->bytes, f->bytes_len ) ) return 1;
    } else if( data_len!=f->data_size ) return 1;
  }
  if( arg->token_mode ) {
    /* SPL token account: mint 0, owner 32, amount 64, delegate option 72 */
    if( data_len>FD_RPC_TOKEN_ACCOUNT_MIN_SZ && data[ FD_RPC_TOKEN_ACCOUNT_MIN_SZ ]!=2 ) return 1;
    if( arg->token_mode==1 && memcmp( data+32UL, arg->token_key, 32UL ) ) return 1;
    if( arg->token_mode==2 && ( FD_LOAD( uint, data+72UL )!=1U || memcmp( data+76UL, arg->token_key, 32UL ) ) ) return 1;
    if( arg->has_mint && memcmp( data, arg->mint, 32UL ) ) return 1;
  }

  FD_BASE58_ENCODE_32_BYTES( pubkey, pubkey_b58 );
  fd_http_server_printf( ctx->http, "%s{\"pubkey\":\"%s\",\"account\":", arg->printed ? "," : "", pubkey_b58 );
  ctx->encode_key = pubkey;
  int encoded = fd_rpc_encode_account_data( ctx, data, data_len, owner, lamports, executable, arg->encoding_cstr, arg->slice_offset, arg->slice_length, arg->id_cstr, &arg->err );
  ctx->encode_key = NULL;
  if( FD_UNLIKELY( !encoded ) ) {
    arg->failed = 1;
    return 0;
  }
  fd_http_server_printf( ctx->http, "}" );
  arg->printed++;
  /* Stop once the response can no longer fit rather than scanning on. */
  if( FD_UNLIKELY( ctx->http->stage_err ) ) return 0;
  return 1;
}

static fd_http_server_response_t
getProgramAccounts( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_pubkey_t program;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &program, &response ) ) ) return response;

  fd_rpc_val_t const * config = &params->v[ 1 ];
  static fd_rpc_gpa_arg_t arg[1];
  memset( arg, 0, sizeof(arg) );
  arg->id_cstr      = id_cstr;
  arg->slice_length = ULONG_MAX;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcProgramAccountsConfig", 1, 1, 1, 1,
                                            &bank_idx, &arg->encoding_cstr, &arg->slice_length, &arg->slice_offset, NULL, &response ) ) ) return response;
  if( FD_UNLIKELY( !fd_rpc_gpa_filters_read( ctx, id_cstr, config, arg, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  fd_rpc_val_t v[1];
  int with_context = fd_rpc_cfg_member( config, "withContext", v ) && v->kind==FD_RPC_VAL_BOOL && v->raw_sz==4UL;

  if( with_context ) fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":[", FD_RPC_AGAVE_API_VERSION, info->slot );
  else               fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  fd_rpc_scan( ctx, info, program.uc, 0UL, 1, fd_rpc_gpa_emit, arg );
  if( FD_UNLIKELY( arg->failed ) ) return arg->err;
  fd_http_server_printf( ctx->http, with_context ? "]},\"id\":%s}\n" : "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

/* getTokenAccountsByOwner / getTokenAccountsByDelegate */
static fd_http_server_response_t
fd_rpc_token_accounts_by( fd_rpc_tile_t *         ctx,
                          char const *            id_cstr,
                          fd_rpc_params_t const * params,
                          int                     mode ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 2, 3, &response ) ) ) return response;
  fd_pubkey_t key;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &key, &response ) ) ) return response;

  static fd_rpc_gpa_arg_t arg[1];
  memset( arg, 0, sizeof(arg) );
  arg->id_cstr      = id_cstr;
  arg->slice_length = ULONG_MAX;
  arg->token_mode   = mode;
  memcpy( arg->token_key, key.uc, 32UL );

  fd_pubkey_t program = fd_solana_spl_token_id;
  int         all_programs = 0; /* a mint filter has to look in both token programs */
  fd_rpc_val_t v[1];
  if( fd_rpc_cfg_member( &params->v[ 1 ], "mint", v ) ) {
    fd_pubkey_t mint;
    if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, v, &mint, &response ) ) ) return response;
    arg->has_mint = 1;
    memcpy( arg->mint, mint.uc, 32UL );
    all_programs = 1;
  } else if( fd_rpc_cfg_member( &params->v[ 1 ], "programId", v ) ) {
    if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, v, &program, &response ) ) ) return response;
    if( FD_UNLIKELY( !fd_rpc_owner_is_token_program( program.uc ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: unrecognized Token program id" );
  } else {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: expected a mint or programId filter." );
  }

  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_validate_config( ctx, id_cstr, &params->v[ 2 ], "struct RpcAccountInfoConfig", 1, 1, 1, 1,
                                            &bank_idx, &arg->encoding_cstr, &arg->slice_length, &arg->slice_offset, NULL, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":[", FD_RPC_AGAVE_API_VERSION, info->slot );
  if( all_programs ) {
    fd_pubkey_t token2022;
    FD_TEST( fd_base58_decode_32( "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", token2022.uc ) );
    fd_rpc_scan( ctx, info, fd_solana_spl_token_id.uc, FD_RPC_TOKEN_ACCOUNT_MIN_SZ, 1, fd_rpc_gpa_emit, arg );
    if( !arg->failed ) fd_rpc_scan( ctx, info, token2022.uc, FD_RPC_TOKEN_ACCOUNT_MIN_SZ, 1, fd_rpc_gpa_emit, arg );
  } else {
    fd_rpc_scan( ctx, info, program.uc, FD_RPC_TOKEN_ACCOUNT_MIN_SZ, 1, fd_rpc_gpa_emit, arg );
  }
  if( FD_UNLIKELY( arg->failed ) ) return arg->err;
  fd_http_server_printf( ctx->http, "]},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

/* top-N helpers for getLargestAccounts / getTokenLargestAccounts */
#define FD_RPC_LARGEST_CNT (20UL)
struct fd_rpc_largest {
  ulong cnt;
  struct { uchar key[ 32 ]; ulong amount; } e[ FD_RPC_LARGEST_CNT ];
  ulong total;        /* sum over everything visited */
  int   token_mode;
  uchar mint[ 32 ];
};
typedef struct fd_rpc_largest fd_rpc_largest_t;

static void
fd_rpc_largest_insert( fd_rpc_largest_t * l,
                       uchar const *      key,
                       ulong              amount ) {
  ulong pos = l->cnt;
  while( pos && l->e[ pos-1UL ].amount<amount ) pos--;
  if( pos>=FD_RPC_LARGEST_CNT ) return;
  ulong last = fd_ulong_min( l->cnt, FD_RPC_LARGEST_CNT-1UL );
  for( ulong i=last; i>pos; i-- ) l->e[ i ] = l->e[ i-1UL ];
  memcpy( l->e[ pos ].key, key, 32UL );
  l->e[ pos ].amount = amount;
  if( l->cnt<FD_RPC_LARGEST_CNT ) l->cnt++;
}

static int
fd_rpc_largest_visit( fd_rpc_tile_t * ctx,
                      void *          _arg,
                      uchar const *   pubkey,
                      ulong           lamports,
                      int             executable,
                      uchar const *   owner,
                      uchar const *   data,
                      ulong           data_len ) {
  (void)ctx; (void)executable; (void)owner;
  fd_rpc_largest_t * l = _arg;
  if( l->token_mode ) {
    if( FD_UNLIKELY( !data ) ) return 1;
    if( data_len>FD_RPC_TOKEN_ACCOUNT_MIN_SZ && data[ FD_RPC_TOKEN_ACCOUNT_MIN_SZ ]!=2 ) return 1;
    if( memcmp( data, l->mint, 32UL ) ) return 1;
    fd_rpc_largest_insert( l, pubkey, FD_LOAD( ulong, data+64UL ) );
    return 1;
  }
  l->total += lamports;
  fd_rpc_largest_insert( l, pubkey, lamports );
  return 1;
}

static fd_http_server_response_t
getLargestAccounts( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 0 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  static fd_rpc_largest_t l[1];
  memset( l, 0, sizeof(l) );
  fd_rpc_scan( ctx, info, NULL, 0UL, 0, fd_rpc_largest_visit, l );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":[", FD_RPC_AGAVE_API_VERSION, info->slot );
  for( ulong i=0UL; i<l->cnt; i++ ) {
    FD_BASE58_ENCODE_32_BYTES( l->e[ i ].key, key_b58 );
    fd_http_server_printf( ctx->http, "%s{\"address\":\"%s\",\"lamports\":%lu}", i ? "," : "", key_b58, l->e[ i ].amount );
  }
  fd_http_server_printf( ctx->http, "]},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
static fd_http_server_response_t
getRecentPerformanceSamples( fd_rpc_tile_t *         ctx,
                             char const *            id_cstr,
                             fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_RECENT_PERFORMANCE_SAMPLES, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong                limit = FD_RPC_PERF_SAMPLE_MAX;
  fd_rpc_val_t const * p0    = &params->v[ 0 ];
  if( p0->kind!=FD_RPC_VAL_NONE && p0->kind!=FD_RPC_VAL_NULL ) {
    if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, p0, "usize", &limit, &response ) ) ) return response;
  }
  if( FD_UNLIKELY( limit>FD_RPC_PERF_SAMPLE_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid limit; max %lu\"},\"id\":%s}\n", FD_RPC_PERF_SAMPLE_MAX, id_cstr );
  }

  ulong cnt = fd_ulong_min( limit, fd_ulong_min( ctx->perf_sample_cnt, FD_RPC_PERF_SAMPLE_MAX ) );
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_rpc_perf_sample_t const * sample = &ctx->perf_samples[ (ctx->perf_sample_cnt-1UL-i) % FD_RPC_PERF_SAMPLE_MAX ];
    fd_http_server_printf( ctx->http, "%s{\"slot\":%lu,\"numTransactions\":%lu,\"numNonVoteTransactions\":%lu,\"numSlots\":%lu,\"samplePeriodSecs\":%u}",
                           i ? "," : "", sample->slot, sample->num_transactions, sample->num_transactions, sample->num_slots, (uint)sample->sample_period_secs );
  }
  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
/* Agave lists the last 150 blocks that carried a non-vote transaction,
   each with the lowest priority fee paid in it.  Replay tells this
   tile a block's total priority fees, not the lowest: a total of zero
   means the lowest was zero, and only those blocks are listed.  A
   block that did pay priority fees is left out, since its minimum is
   not known here (it may still have been zero). */
static fd_http_server_response_t
getRecentPrioritizationFees( fd_rpc_tile_t *         ctx,
                             char const *            id_cstr,
                             fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;
  fd_rpc_val_t const * accts = &params->v[ 0 ];
  if( accts->kind==FD_RPC_VAL_SEQ ) {
    fd_jtok_t j[1];
    ulong n = 0UL;
    fd_jtok_arr_enter( fd_jtok_init( j, accts->raw, accts->raw_sz ) );
    while( fd_jtok_arr_next( j ) ) {
      fd_rpc_val_t v[1]; fd_rpc_val_read( j, v );
      fd_pubkey_t key;
      if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, v, &key, &response ) ) ) return response;
      if( FD_UNLIKELY( ++n>128UL ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Too many inputs provided; max 128" );
    }
  } else if( FD_UNLIKELY( accts->kind!=FD_RPC_VAL_NONE && accts->kind!=FD_RPC_VAL_NULL ) ) {
    return fd_rpc_err_invalid( ctx, id_cstr, "type", accts, "a sequence" );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  for( ulong i=0UL; i<ctx->prio_fee_cnt; i++ ) {
    /* oldest first, as Agave */
    ulong slot = ctx->prio_fee_slots[ (ctx->prio_fee_next + FD_RPC_PRIO_FEE_CNT - ctx->prio_fee_cnt + i) % FD_RPC_PRIO_FEE_CNT ];
    fd_http_server_printf( ctx->http, "%s{\"prioritizationFee\":0,\"slot\":%lu}", i ? "," : "", slot );
  }
  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
static fd_rpc_txn_rec_t const *
fd_rpc_txn_query( fd_rpc_tile_t *     ctx,
                  uchar const *       sig,
                  bank_info_t const * tip,
                  ulong               next_slot ) {
  ulong home = fd_ulong_hash( fd_ulong_load_8( sig ) ^ fd_ulong_load_8( sig+8UL ) ) % FD_RPC_TXN_TABLE_CNT;
  fd_rpc_txn_rec_t const * best     = NULL;
  ulong                    best_seq = 0UL;
  for( ulong i=0UL; i<FD_RPC_TXN_PROBE_MAX; i++ ) {
    ulong entry = ctx->txn_table[ (home+i) % FD_RPC_TXN_TABLE_CNT ];
    if( !entry ) break;
    if( !fd_rpc_txn_seq_live( ctx, entry ) ) continue;
    fd_rpc_txn_rec_t const * rec = &ctx->txn_recs[ (entry-1UL) % FD_RPC_TXN_REC_CNT ];
    if( memcmp( rec->sig, sig, 64UL ) ) continue;
    /* on the fork of tip: tip's own slot, or marked in its SlotHistory */
    if( rec->slot!=tip->slot && !fd_rpc_slot_history_has( ctx, next_slot, rec->slot ) ) continue;
    if( !best || entry>best_seq ) { best = rec; best_seq = entry; }
  }
  return best;
}

/* Prints Agave's TransactionError for a runtime error code.  The
   message from replay carries the code only: for a failed instruction
   it does not say which instruction or what its error was, so those
   two are printed as null. */
static void
fd_rpc_print_exec_err( fd_rpc_tile_t * ctx, int txn_err, int exec_err, int exec_err_kind, uint exec_err_idx, uint custom_err );

static void
fd_rpc_print_txn_err( fd_rpc_tile_t * ctx,
                      int             txn_err ) {
  char const * name;
  switch( txn_err ) {
    case FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE:                      name = "AccountLoadedTwice";                    break;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND:                         name = "AccountNotFound";                       break;
    case FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND:                 name = "ProgramAccountNotFound";                break;
    case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE:                name = "InsufficientFundsForFee";               break;
    case FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE:                   name = "InvalidAccountForFee";                  break;
    case FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED:                         name = "AlreadyProcessed";                      break;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND:
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED:
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR:
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE:                name = "BlockhashNotFound";                     break;
    case FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE:                         name = "SignatureFailure";                      break;
    case FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION:             name = "InvalidProgramForExecution";            break;
    case FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE:                          name = "SanitizeFailure";                       break;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT:         name = "WouldExceedMaxBlockCostLimit";          break;
    case FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION:                       name = "UnsupportedVersion";                    break;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT:       name = "WouldExceedMaxAccountCostLimit";        break;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT:     name = "WouldExceedAccountDataBlockLimit";      break;
    case FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS:                    name = "TooManyAccountLocks";                   break;
    case FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND:            name = "AddressLookupTableNotFound";            break;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER:        name = "InvalidAddressLookupTableOwner";        break;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA:         name = "InvalidAddressLookupTableData";         break;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX:        name = "InvalidAddressLookupTableIndex";        break;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT:          name = "WouldExceedMaxVoteCostLimit";           break;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT:     name = "WouldExceedAccountDataTotalLimit";      break;
    case FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED:    name = "MaxLoadedAccountsDataSizeExceeded";     break;
    case FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT:   name = "InvalidLoadedAccountsDataSizeLimit";    break;
    case FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION:                    name = "UnbalancedTransaction";                 break;
    default:                                                           name = NULL;                                    break;
  }
  if( name ) fd_http_server_printf( ctx->http, "\"%s\"", name );
  else       fd_http_server_printf( ctx->http, "{\"InstructionError\":[null,null]}" );
}

/* Error of a recorded transaction.  The failed instruction is only
   known if replay passed it along. */
static void
fd_rpc_print_rec_err( fd_rpc_tile_t *          ctx,
                      fd_rpc_txn_rec_t const * rec ) {
  if( rec->txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR && rec->has_exec_err ) {
    fd_rpc_print_exec_err( ctx, rec->txn_err, rec->exec_err, rec->exec_err_kind, rec->exec_err_idx, rec->custom_err );
  } else {
    fd_rpc_print_txn_err( ctx, rec->txn_err );
  }
}

static void
fd_rpc_ws_sig_check( fd_rpc_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->processed_idx==ULONG_MAX || ctx->confirmed_idx==ULONG_MAX || ctx->finalized_idx==ULONG_MAX ) ) return;
  bank_info_t const * tip = &ctx->banks[ ctx->processed_idx ];
  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, tip, &next_slot ) ) ) return;
  ulong level_slot[ 3 ] = { tip->slot, ctx->banks[ ctx->confirmed_idx ].slot, ctx->banks[ ctx->finalized_idx ].slot };
  for( ulong i=0UL; i<FD_RPC_WS_SIG_SUB_MAX; i++ ) {
    if( !ctx->ws_sig_subs[ i ].sub_id ) continue;
    fd_rpc_txn_rec_t const * rec = fd_rpc_txn_query( ctx, ctx->ws_sig_subs[ i ].sig, tip, next_slot );
    if( !rec || rec->slot>level_slot[ ctx->ws_sig_subs[ i ].level ] ) continue;
    ulong ws_conn_id = ctx->ws_sig_subs[ i ].ws_conn_id;
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"method\":\"signatureNotification\",\"params\":{\"result\":{\"context\":{\"slot\":%lu},\"value\":{\"err\":", rec->slot );
    if( !rec->txn_err ) fd_http_server_printf( ctx->http, "null" );
    else                fd_rpc_print_rec_err( ctx, rec );
    fd_http_server_printf( ctx->http, "}},\"subscription\":%lu}}\n", ctx->ws_sig_subs[ i ].sub_id-1UL );
    /* a signature subscription ends with its one notification */
    ctx->ws_sig_subs[ i ].sub_id = 0UL;
    ctx->ws_sig_sub_cnt--;
    if( FD_UNLIKELY( fd_http_server_ws_send( ctx->http, ws_conn_id ) ) ) {
      fd_http_server_ws_close( ctx->http, ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_TOO_SLOW );
    }
  }
}

static fd_http_server_response_t
getSignatureStatuses( fd_rpc_tile_t *         ctx,
                      char const *            id_cstr,
                      fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_rpc_val_t const * sigs = &params->v[ 0 ];
  if( FD_UNLIKELY( sigs->kind!=FD_RPC_VAL_SEQ ) ) return fd_rpc_err_invalid( ctx, id_cstr, "type", sigs, "a sequence" );
  if( FD_UNLIKELY( ctx->processed_idx==ULONG_MAX || ctx->confirmed_idx==ULONG_MAX || ctx->finalized_idx==ULONG_MAX ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: banks uninitialized" );
  }
  bank_info_t const * tip       = &ctx->banks[ ctx->processed_idx ];
  ulong               confirmed = ctx->banks[ ctx->confirmed_idx ].slot;
  ulong               finalized = ctx->banks[ ctx->finalized_idx ].slot;
  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, tip, &next_slot ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: slot history unavailable" );

  /* Like Agave, a plain query only covers the recent status cache (the
     last 300 slots); older transactions need searchTransactionHistory,
     which here means the whole recent transaction window. */
  fd_rpc_val_t sv[1];
  int search_history = fd_rpc_cfg_member( &params->v[ 1 ], "searchTransactionHistory", sv ) && sv->kind==FD_RPC_VAL_BOOL && sv->raw_sz==4UL;

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":[", FD_RPC_AGAVE_API_VERSION, tip->slot );
  fd_jtok_t j[1];
  ulong n = 0UL;
  fd_jtok_arr_enter( fd_jtok_init( j, sigs->raw, sigs->raw_sz ) );
  while( fd_jtok_arr_next( j ) ) {
    fd_rpc_val_t v[1]; fd_rpc_val_read( j, v );
    char  sig_cstr[ 96 ];
    uchar sig[ 64 ];
    if( FD_UNLIKELY( ++n>256UL ) ) {
      fd_http_server_unstage( ctx->http );
      return fd_rpc_err_msg( ctx, id_cstr, -32602, "Too many inputs provided; max 256" );
    }
    if( FD_UNLIKELY( !fd_rpc_val_cstr( v, sig_cstr, sizeof(sig_cstr) ) || !fd_base58_decode_64( sig_cstr, sig ) ) ) {
      fd_http_server_unstage( ctx->http );
      return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: Invalid" );
    }
    fd_rpc_txn_rec_t const * rec = fd_rpc_txn_query( ctx, sig, tip, next_slot );
    if( n>1UL ) fd_http_server_printf( ctx->http, "," );
    if( !rec || ( !search_history && tip->slot>rec->slot+300UL ) ) { fd_http_server_printf( ctx->http, "null" ); continue; }

    char const * level = rec->slot<=finalized ? "finalized" : rec->slot<=confirmed ? "confirmed" : "processed";
    fd_http_server_printf( ctx->http, "{\"confirmationStatus\":\"%s\",", level );
    /* Agave: null once finalized, else the number of blocks built on it */
    if( rec->slot<=finalized ) fd_http_server_printf( ctx->http, "\"confirmations\":null," );
    else                       fd_http_server_printf( ctx->http, "\"confirmations\":%lu,", tip->slot-rec->slot );
    if( !rec->txn_err ) {
      fd_http_server_printf( ctx->http, "\"err\":null,\"slot\":%lu,\"status\":{\"Ok\":null}}", rec->slot );
    } else {
      fd_http_server_printf( ctx->http, "\"err\":" );
      fd_rpc_print_rec_err( ctx, rec );
      fd_http_server_printf( ctx->http, ",\"slot\":%lu,\"status\":{\"Err\":", rec->slot );
      fd_rpc_print_rec_err( ctx, rec );
      fd_http_server_printf( ctx->http, "}}" );
    }
  }
  fd_http_server_printf( ctx->http, "]},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

/* ---- transaction history from the recent transaction window ------------- */

/* Base58 for arbitrary lengths (instruction data, whole transactions).
   Quadratic, which is fine for at most a transaction's worth of bytes.
   out must hold 2*in_sz+2 chars. */
static void
fd_rpc_print_base58( fd_rpc_tile_t * ctx,
                     uchar const *   in,
                     ulong           in_sz ) {
  static char const alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  static uchar digits[ 2UL*FD_TXN_MTU_V0+2UL ];
  static char  out   [ 2UL*FD_TXN_MTU_V0+2UL ];
  if( FD_UNLIKELY( in_sz>FD_TXN_MTU_V0 ) ) return;
  ulong zeros = 0UL;
  while( zeros<in_sz && !in[ zeros ] ) zeros++;
  ulong len = 0UL;
  for( ulong i=zeros; i<in_sz; i++ ) {
    uint carry = in[ i ];
    for( ulong k=0UL; k<len; k++ ) {
      carry += (uint)digits[ k ]<<8;
      digits[ k ] = (uchar)( carry % 58U );
      carry /= 58U;
    }
    while( carry ) { digits[ len++ ] = (uchar)( carry % 58U ); carry /= 58U; }
  }
  ulong o = 0UL;
  for( ulong i=0UL; i<zeros; i++ ) out[ o++ ] = '1';
  for( ulong k=0UL; k<len; k++ ) out[ o++ ] = alphabet[ digits[ len-1UL-k ] ];
  fd_http_server_printf( ctx->http, "%.*s", (int)o, out );
}

static void
fd_rpc_print_json_text( fd_rpc_tile_t * ctx,
                        uchar const *   t,
                        ulong           sz ) {
  for( ulong i=0UL; i<sz; i++ ) {
    uchar c = t[ i ];
    if(      c=='"'  ) fd_http_server_printf( ctx->http, "\\\"" );
    else if( c=='\\' ) fd_http_server_printf( ctx->http, "\\\\" );
    else if( c<0x20  ) fd_http_server_printf( ctx->http, "\\u%04x", (uint)c );
    else               fd_http_server_printf( ctx->http, "%c", (char)c );
  }
}

static void
fd_rpc_print_txn_status( fd_rpc_tile_t *          ctx,
                         fd_rpc_txn_rec_t const * rec ) {
  if( !rec->txn_err ) { fd_http_server_printf( ctx->http, "\"err\":null,\"status\":{\"Ok\":null}" ); return; }
  fd_http_server_printf( ctx->http, "\"err\":" );
  fd_rpc_print_rec_err( ctx, rec );
  fd_http_server_printf( ctx->http, ",\"status\":{\"Err\":" );
  fd_rpc_print_rec_err( ctx, rec );
  fd_http_server_printf( ctx->http, "}" );
}

/* Prints the addresses a v0 transaction loads through address lookup
   tables, read from the tables as they are on the given bank (tables
   only grow, so this is what the transaction saw unless a table was
   closed since).  Prints empty lists if a table cannot be read. */
static void
fd_rpc_print_loaded_addresses( fd_rpc_tile_t *     ctx,
                               bank_info_t const * info,
                               fd_txn_t const *    txn,
                               uchar const *       payload ) {
  fd_txn_acct_addr_lut_t const * luts = fd_txn_get_address_tables_const( txn );
  int ok = 1;
  for( int pass=0; pass<2; pass++ ) { /* 0 writable, 1 readonly */
    fd_http_server_printf( ctx->http, pass ? "],\"readonly\":[" : "{\"writable\":[" );
    ulong printed = 0UL;
    for( ulong i=0UL; ok && i<txn->addr_table_lookup_cnt; i++ ) {
      ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
      fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, payload+luts[ i ].addr_off, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
      if( FD_UNLIKELY( !lamports || data_len<56UL || memcmp( owner, fd_solana_address_lookup_table_program_id.uc, 32UL ) ) ) { ok = 0; break; }
      ulong         cnt  = pass ? luts[ i ].readonly_cnt : luts[ i ].writable_cnt;
      uchar const * idxs = payload + ( pass ? luts[ i ].readonly_off : luts[ i ].writable_off );
      for( ulong k=0UL; k<cnt; k++ ) {
        ulong off = 56UL+32UL*(ulong)idxs[ k ];
        if( FD_UNLIKELY( off+32UL>data_len ) ) continue;
        FD_BASE58_ENCODE_32_BYTES( ctx->scratch.accdb_data_buf+off, key_b58 );
        fd_http_server_printf( ctx->http, "%s\"%s\"", printed ? "," : "", key_b58 );
        printed++;
      }
    }
  }
  fd_http_server_printf( ctx->http, "]}" );
}

/* Version of a stored transaction: -1 legacy, else 0 or 1.  A v1
   transaction starts with its version byte; legacy and v0 start with
   the signature count and carry the version after the signatures. */
static int
fd_rpc_txn_rec_version( fd_rpc_txn_rec_t const * rec ) {
  if( rec->payload_sz && (rec->payload[ 0 ] & 0x80) ) return (int)( rec->payload[ 0 ] & 0x7f );
  ulong off = 1UL+64UL*(ulong)rec->payload[ 0 ];
  if( FD_UNLIKELY( off>=rec->payload_sz ) ) return -1;
  return ( rec->payload[ off ] & 0x80 ) ? (int)( rec->payload[ off ] & 0x7f ) : -1;
}

#define FD_RPC_TXN_ENC_JSON   (0)
#define FD_RPC_TXN_ENC_BASE64 (1)
#define FD_RPC_TXN_ENC_BASE58 (2)

/* Prints "transaction":…,"meta":{…},"version":… for one record.
   Returns 0 if the stored payload does not parse (should not happen). */
static int
fd_rpc_print_txn( fd_rpc_tile_t *          ctx,
                  bank_info_t const *      info,
                  fd_rpc_txn_rec_t const * rec,
                  int                      enc ) {
  uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  if( FD_UNLIKELY( !fd_txn_parse( rec->payload, rec->payload_sz, txn_buf, NULL ) ) ) return 0;
  fd_txn_t const * txn = (fd_txn_t const *)txn_buf;
  uchar const *    p   = rec->payload;

  if( enc==FD_RPC_TXN_ENC_BASE64 ) {
    static char b64[ FD_BASE64_ENC_SZ( FD_TXN_MTU_V0 )+1UL ];
    ulong n = fd_base64_encode( b64, p, rec->payload_sz );
    fd_http_server_printf( ctx->http, "\"transaction\":[\"%.*s\",\"base64\"],", (int)n, b64 );
  } else if( enc==FD_RPC_TXN_ENC_BASE58 ) {
    fd_http_server_printf( ctx->http, "\"transaction\":[\"" );
    fd_rpc_print_base58( ctx, p, rec->payload_sz );
    fd_http_server_printf( ctx->http, "\",\"base58\"]," );
  } else {
    fd_http_server_printf( ctx->http, "\"transaction\":{\"signatures\":[" );
    for( ulong i=0UL; i<txn->signature_cnt; i++ ) {
      FD_BASE58_ENCODE_64_BYTES( p+txn->signature_off+64UL*i, sig_b58 );
      fd_http_server_printf( ctx->http, "%s\"%s\"", i ? "," : "", sig_b58 );
    }
    fd_http_server_printf( ctx->http, "],\"message\":{\"accountKeys\":[" );
    for( ulong i=0UL; i<txn->acct_addr_cnt; i++ ) {
      FD_BASE58_ENCODE_32_BYTES( p+txn->acct_addr_off+32UL*i, key_b58 );
      fd_http_server_printf( ctx->http, "%s\"%s\"", i ? "," : "", key_b58 );
    }
    FD_BASE58_ENCODE_32_BYTES( p+txn->recent_blockhash_off, bh_b58 );
    fd_http_server_printf( ctx->http, "],\"header\":{\"numReadonlySignedAccounts\":%u,\"numReadonlyUnsignedAccounts\":%u,\"numRequiredSignatures\":%u},\"recentBlockhash\":\"%s\",\"instructions\":[",
                           (uint)txn->readonly_signed_cnt, (uint)txn->readonly_unsigned_cnt, (uint)txn->signature_cnt, bh_b58 );
    for( ulong i=0UL; i<txn->instr_cnt; i++ ) {
      fd_txn_instr_t const * ix = &txn->instr[ i ];
      fd_http_server_printf( ctx->http, "%s{\"accounts\":[", i ? "," : "" );
      for( ulong k=0UL; k<ix->acct_cnt; k++ ) fd_http_server_printf( ctx->http, "%s%u", k ? "," : "", (uint)p[ ix->acct_off+k ] );
      fd_http_server_printf( ctx->http, "],\"data\":\"" );
      fd_rpc_print_base58( ctx, p+ix->data_off, ix->data_sz );
      fd_http_server_printf( ctx->http, "\",\"programIdIndex\":%u,\"stackHeight\":1}", (uint)ix->program_id );
    }
    fd_http_server_printf( ctx->http, "]" );
    if( txn->transaction_version==FD_TXN_V1 ) {
      /* v1 has no lookup tables; it carries its compute budget in the
         header, each field present only if its mask bit is set */
      uint          mask = fd_uint_load_4( p+4UL );
      uchar const * cv   = p+txn->v1_txn_config_values_off;
      fd_http_server_printf( ctx->http, ",\"transactionConfig\":{" );
      ulong fee = 0UL; int has_fee = 0;
      if( mask & 1U ) { fee = FD_LOAD( ulong, cv ); cv += 8UL; has_fee = 1; }
      if( (mask>>2)&1U ) { fd_http_server_printf( ctx->http, "\"computeUnitLimit\":%u,", FD_LOAD( uint, cv ) ); cv += 4UL; } else fd_http_server_printf( ctx->http, "\"computeUnitLimit\":null," );
      uint lads = 0U; int has_lads = 0;
      if( (mask>>3)&1U ) { lads = FD_LOAD( uint, cv ); cv += 4UL; has_lads = 1; }
      if( (mask>>4)&1U ) fd_http_server_printf( ctx->http, "\"heapSize\":%u,", FD_LOAD( uint, cv ) ); else fd_http_server_printf( ctx->http, "\"heapSize\":null," );
      if( has_lads ) fd_http_server_printf( ctx->http, "\"loadedAccountsDataSizeLimit\":%u,", lads ); else fd_http_server_printf( ctx->http, "\"loadedAccountsDataSizeLimit\":null," );
      if( has_fee ) fd_http_server_printf( ctx->http, "\"priorityFee\":%lu}", fee ); else fd_http_server_printf( ctx->http, "\"priorityFee\":null}" );
    } else if( txn->transaction_version!=FD_TXN_VLEGACY ) {
      fd_txn_acct_addr_lut_t const * luts = fd_txn_get_address_tables_const( txn );
      fd_http_server_printf( ctx->http, ",\"addressTableLookups\":[" );
      for( ulong i=0UL; i<txn->addr_table_lookup_cnt; i++ ) {
        FD_BASE58_ENCODE_32_BYTES( p+luts[ i ].addr_off, lut_b58 );
        fd_http_server_printf( ctx->http, "%s{\"accountKey\":\"%s\",\"readonlyIndexes\":[", i ? "," : "", lut_b58 );
        for( ulong k=0UL; k<luts[ i ].readonly_cnt; k++ ) fd_http_server_printf( ctx->http, "%s%u", k ? "," : "", (uint)p[ luts[ i ].readonly_off+k ] );
        fd_http_server_printf( ctx->http, "],\"writableIndexes\":[" );
        for( ulong k=0UL; k<luts[ i ].writable_cnt; k++ ) fd_http_server_printf( ctx->http, "%s%u", k ? "," : "", (uint)p[ luts[ i ].writable_off+k ] );
        fd_http_server_printf( ctx->http, "]}" );
      }
      fd_http_server_printf( ctx->http, "]" );
    }
    fd_http_server_printf( ctx->http, "}}," );
  }

  /* meta.  Replay reports a transaction's result code, fee, compute
     units and the lamport balances of its accounts before and after.
     Logs, inner instructions and token balances are not reported and
     are null, which is also what Agave prints when it did not record
     them.  Balances are empty lists if replay had none to report. */
  fd_rpc_meta_ent_t const * meta = fd_rpc_meta_query( ctx, rec->sig );
  if( meta && meta->slot!=rec->slot ) meta = NULL;
  /* costUnits is what the transaction cost the block; the compute
     units its programs used are only known from the exec tile. */
  if( meta && meta->has_cu ) fd_http_server_printf( ctx->http, "\"meta\":{\"computeUnitsConsumed\":%u,\"costUnits\":%u,", meta->cu_consumed, rec->compute_units );
  else                       fd_http_server_printf( ctx->http, "\"meta\":{\"computeUnitsConsumed\":null,\"costUnits\":%u,", rec->compute_units );
  fd_rpc_print_txn_status( ctx, rec );
  /* Logs, inner instructions and return data come from the exec tile
     that ran the transaction, matched by signature and slot.  null if
     nothing was kept (a block this node produced itself, an entry that
     aged out, or a message the tile missed). */
  uchar const * meta_body = meta ? (uchar const *)( meta+1 ) : NULL;
  if( !meta || meta->inner_truncated ) {
    fd_http_server_printf( ctx->http, ",\"fee\":%lu,\"innerInstructions\":null,\"loadedAddresses\":", rec->fee );
  } else {
    /* Same walk as simulateTransaction: an instruction at stack height
       1 is a top level one, what follows deeper was invoked from it. */
    fd_http_server_printf( ctx->http, ",\"fee\":%lu,\"innerInstructions\":[", rec->fee );
    ulong top = ULONG_MAX, groups = 0UL, off = 0UL; int open = 0;
    while( off+5UL<=meta->inner_sz ) {
      uchar const * e = meta_body+off;
      ulong acct_cnt = e[ 2 ], data_sz = FD_LOAD( ushort, e+3UL );
      if( FD_UNLIKELY( off+5UL+acct_cnt+data_sz>meta->inner_sz ) ) break;
      off += 5UL+acct_cnt+data_sz;
      if( e[ 0 ]<=1 ) { top = top==ULONG_MAX ? 0UL : top+1UL; if( open ) { fd_http_server_printf( ctx->http, "]}" ); open = 0; } continue; }
      if( !open ) { fd_http_server_printf( ctx->http, "%s{\"index\":%lu,\"instructions\":[", groups++ ? "," : "", top ); open = 1; }
      else          fd_http_server_printf( ctx->http, "," );
      fd_http_server_printf( ctx->http, "{\"accounts\":[" );
      for( ulong k=0UL; k<acct_cnt; k++ ) fd_http_server_printf( ctx->http, "%s%u", k ? "," : "", (uint)e[ 5UL+k ] );
      fd_http_server_printf( ctx->http, "],\"data\":\"" );
      fd_rpc_print_base58( ctx, e+5UL+acct_cnt, data_sz );
      fd_http_server_printf( ctx->http, "\",\"programIdIndex\":%u,\"stackHeight\":%u}", (uint)e[ 1 ], (uint)e[ 0 ] );
    }
    if( open ) fd_http_server_printf( ctx->http, "]}" );
    fd_http_server_printf( ctx->http, "],\"loadedAddresses\":" );
  }
  fd_rpc_print_loaded_addresses( ctx, info, txn, p );
  if( !meta ) {
    fd_http_server_printf( ctx->http, ",\"logMessages\":null" );
  } else {
    /* log collector: [tag][len, 1 or 2 bytes][text] per message */
    fd_http_server_printf( ctx->http, ",\"logMessages\":[" );
    uchar const * log = meta_body+meta->inner_sz;
    ulong off = 0UL, logs = 0UL;
    while( off+2UL<=meta->log_sz ) {
      ulong len = (ulong)( log[ off+1UL ] & 0x7F );
      ulong hdr = 2UL;
      if( log[ off+1UL ] & 0x80 ) { if( off+3UL>meta->log_sz ) break; len |= (ulong)log[ off+2UL ]<<7; hdr = 3UL; }
      if( off+hdr+len>meta->log_sz ) break;
      fd_http_server_printf( ctx->http, "%s\"", logs++ ? "," : "" );
      fd_rpc_print_json_text( ctx, log+off+hdr, len );
      fd_http_server_printf( ctx->http, "\"" );
      off += hdr+len;
    }
    fd_http_server_printf( ctx->http, "]" );
  }
  fd_http_server_printf( ctx->http, ",\"postBalances\":[" );
  for( ulong i=0UL; i<rec->bal_cnt; i++ ) fd_http_server_printf( ctx->http, "%s%lu", i ? "," : "", rec->post_lamports[ i ] );
  /* Token balances are not reported.  They are known to be empty if
     no token program and no token-owned account is involved. */
  char const * tok = meta && !meta->has_token ? "[]" : "null";
  fd_http_server_printf( ctx->http, "],\"postTokenBalances\":%s,\"preBalances\":[", tok );
  for( ulong i=0UL; i<rec->bal_cnt; i++ ) fd_http_server_printf( ctx->http, "%s%lu", i ? "," : "", rec->pre_lamports[ i ] );
  fd_http_server_printf( ctx->http, "],\"preTokenBalances\":%s", tok );
  if( meta && meta->has_return ) {
    static char b64[ FD_BASE64_ENC_SZ( FD_EXECRP_TXN_META_RETURN_MAX )+1UL ];
    ulong n = fd_base64_encode( b64, meta_body+meta->inner_sz+meta->log_sz, meta->return_sz );
    FD_BASE58_ENCODE_32_BYTES( meta->return_program, prog_b58 );
    fd_http_server_printf( ctx->http, ",\"returnData\":{\"data\":[\"%.*s\",\"base64\"],\"programId\":\"%s\"}", (int)n, b64, prog_b58 );
  }
  fd_http_server_printf( ctx->http, ",\"rewards\":[]}," );
  if( txn->transaction_version==FD_TXN_VLEGACY ) fd_http_server_printf( ctx->http, "\"version\":\"legacy\"" );
  else                                           fd_http_server_printf( ctx->http, "\"version\":%u", (uint)txn->transaction_version );
  return 1;
}

/* Reads "encoding" for getTransaction / getBlock.  Returns 1 on
   success. */
static int
fd_rpc_txn_encoding( fd_rpc_tile_t *             ctx,
                     char const *                id_cstr,
                     fd_rpc_val_t const *        config,
                     int *                       enc,
                     fd_http_server_response_t * res ) {
  fd_rpc_val_t v[1];
  char e[ 16 ] = "json";
  if( fd_rpc_cfg_member( config, "encoding", v ) && v->kind==FD_RPC_VAL_STR ) fd_rpc_val_cstr( v, e, sizeof(e) );
  if(      !strcmp( e, "json"   ) ) *enc = FD_RPC_TXN_ENC_JSON;
  else if( !strcmp( e, "base64" ) ) *enc = FD_RPC_TXN_ENC_BASE64;
  else if( !strcmp( e, "base58" ) ) *enc = FD_RPC_TXN_ENC_BASE58;
  else {
    *res = fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: supported transaction encodings are json, base64 and base58" );
    return 0;
  }
  return 1;
}

static fd_http_server_response_t
getTransaction( fd_rpc_tile_t *         ctx,
                char const *            id_cstr,
                fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  char  sig_cstr[ 96 ];
  uchar sig[ 64 ];
  if( FD_UNLIKELY( !fd_rpc_val_cstr( &params->v[ 0 ], sig_cstr, sizeof(sig_cstr) ) || !fd_base58_decode_64( sig_cstr, sig ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: Invalid" );
  }
  int enc;
  if( FD_UNLIKELY( !fd_rpc_txn_encoding( ctx, id_cstr, config, &enc, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, config, &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, info, &next_slot ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: slot history unavailable" );
  fd_rpc_txn_rec_t const * rec = fd_rpc_txn_query( ctx, sig, info, next_slot );
  if( !rec || rec->slot>info->slot ) return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":%s}\n", id_cstr );

  fd_rpc_val_t v[1];
  long max_version = ( fd_rpc_cfg_member( config, "maxSupportedTransactionVersion", v ) && v->kind==FD_RPC_VAL_INT && !v->neg ) ? (long)fd_ulong_min( v->u, 255UL ) : -1L;
  if( FD_UNLIKELY( (long)fd_rpc_txn_rec_version( rec )>max_version ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32015,\"message\":\"Transaction version (%d) is not supported by the requesting client. Please try the request again with the following configuration parameter: \\\"maxSupportedTransactionVersion\\\": %d\"},\"id\":%s}\n", fd_rpc_txn_rec_version( rec ), fd_rpc_txn_rec_version( rec ), id_cstr );
  }

  fd_rpc_block_time_t const * bt = fd_rpc_block_time_query( ctx, rec->slot );
  if( bt ) fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"blockTime\":%ld,\"slot\":%lu,\"transactionIndex\":%u,", bt->unix_timestamp, rec->slot, rec->index_in_slot );
  else     fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"blockTime\":null,\"slot\":%lu,\"transactionIndex\":%u,", rec->slot, rec->index_in_slot );
  if( FD_UNLIKELY( !fd_rpc_print_txn( ctx, info, rec, enc ) ) ) {
    fd_http_server_unstage( ctx->http );
    return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: stored transaction is unreadable" );
  }
  fd_http_server_printf( ctx->http, "},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

/* getSignaturesForAddress walks the window newest first.  It matches
   the addresses written in the transaction itself; an address the
   transaction only reaches through an address lookup table is not
   matched. */
static fd_http_server_response_t
getSignaturesForAddress( fd_rpc_tile_t *         ctx,
                         char const *            id_cstr,
                         fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_pubkey_t address;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &address, &response ) ) ) return response;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, config, &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];
  ulong finalized = ctx->finalized_idx!=ULONG_MAX ? ctx->banks[ ctx->finalized_idx ].slot : 0UL;

  fd_rpc_val_t v[1];
  ulong limit = 1000UL;
  if( fd_rpc_cfg_member( config, "limit", v ) && v->kind==FD_RPC_VAL_INT ) {
    if( FD_UNLIKELY( v->neg || !v->u || v->u>1000UL ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid limit; max 1000" );
    limit = v->u;
  }
  uchar before[ 64 ]; int has_before = 0;
  uchar until [ 64 ]; int has_until  = 0;
  char  sig_cstr[ 96 ];
  if( fd_rpc_cfg_member( config, "before", v ) && v->kind==FD_RPC_VAL_STR ) {
    if( FD_UNLIKELY( !fd_rpc_val_cstr( v, sig_cstr, sizeof(sig_cstr) ) || !fd_base58_decode_64( sig_cstr, before ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: Invalid" );
    has_before = 1;
  }
  if( fd_rpc_cfg_member( config, "until", v ) && v->kind==FD_RPC_VAL_STR ) {
    if( FD_UNLIKELY( !fd_rpc_val_cstr( v, sig_cstr, sizeof(sig_cstr) ) || !fd_base58_decode_64( sig_cstr, until ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: Invalid" );
    has_until = 1;
  }

  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, info, &next_slot ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: slot history unavailable" );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  ulong printed  = 0UL;
  int   skipping = has_before;
  ulong live     = fd_ulong_min( ctx->txn_rec_next, FD_RPC_TXN_REC_CNT );
  for( ulong n=0UL; n<live && printed<limit; n++ ) {
    fd_rpc_txn_rec_t const * rec = &ctx->txn_recs[ (ctx->txn_rec_next-1UL-n) % FD_RPC_TXN_REC_CNT ];
    if( has_until && !memcmp( rec->sig, until, 64UL ) ) break;
    if( skipping ) { if( !memcmp( rec->sig, before, 64UL ) ) skipping = 0; continue; }
    if( rec->slot>info->slot ) continue;
    if( rec->slot!=info->slot && !fd_rpc_slot_history_has( ctx, next_slot, rec->slot ) ) continue;
    int match = 0;
    for( ulong k=0UL; k<rec->acct_cnt && !match; k++ ) match = !memcmp( rec->payload+rec->acct_off+32UL*k, address.uc, 32UL );
    if( !match ) continue;

    FD_BASE58_ENCODE_64_BYTES( rec->sig, sig_b58 );
    fd_rpc_block_time_t const * bt = fd_rpc_block_time_query( ctx, rec->slot );
    fd_http_server_printf( ctx->http, "%s{", printed ? "," : "" );
    if( bt ) fd_http_server_printf( ctx->http, "\"blockTime\":%ld,", bt->unix_timestamp );
    else     fd_http_server_printf( ctx->http, "\"blockTime\":null," );
    fd_http_server_printf( ctx->http, "\"confirmationStatus\":\"%s\",", rec->slot<=finalized ? "finalized" : "confirmed" );
    if( !rec->txn_err ) fd_http_server_printf( ctx->http, "\"err\":null," );
    else { fd_http_server_printf( ctx->http, "\"err\":" ); fd_rpc_print_rec_err( ctx, rec ); fd_http_server_printf( ctx->http, "," ); }

    /* memo: the data of every memo program instruction, as Agave formats it */
    uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    int   has_memo = 0;
    if( FD_LIKELY( fd_txn_parse( rec->payload, rec->payload_sz, txn_buf, NULL ) ) ) {
      fd_txn_t const * txn = (fd_txn_t const *)txn_buf;
      for( ulong i=0UL; i<txn->instr_cnt; i++ ) {
        fd_txn_instr_t const * ix = &txn->instr[ i ];
        if( ix->program_id>=txn->acct_addr_cnt ) continue;
        FD_BASE58_ENCODE_32_BYTES( rec->payload+txn->acct_addr_off+32UL*(ulong)ix->program_id, prog_b58 );
        if( strcmp( prog_b58, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" ) && strcmp( prog_b58, "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo" ) ) continue;
        fd_http_server_printf( ctx->http, has_memo ? "; [%u] " : "\"memo\":\"[%u] ", (uint)ix->data_sz );
        fd_rpc_print_json_text( ctx, rec->payload+ix->data_off, ix->data_sz );
        has_memo = 1;
      }
    }
    fd_http_server_printf( ctx->http, has_memo ? "\"," : "\"memo\":null," );
    fd_http_server_printf( ctx->http, "\"signature\":\"%s\",\"slot\":%lu,\"transactionIndex\":%u}", sig_b58, rec->slot, rec->index_in_slot );
    printed++;
  }
  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

/* getBlock answers from the recent transaction window, so it only
   knows blocks replayed since this node started whose transactions are
   all still in the window.  transactionDetails may be "full",
   "signatures" or "none".  Rewards are not known: "rewards" is null. */
static fd_http_server_response_t
getBlock( fd_rpc_tile_t *         ctx,
          char const *            id_cstr,
          fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  ulong slot;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, &params->v[ 0 ], "u64", &slot, &response ) ) ) return response;
  fd_rpc_val_t const * config = &params->v[ 1 ];
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, config, &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  fd_rpc_val_t v[1];
  char details[ 16 ] = "full";
  if( fd_rpc_cfg_member( config, "transactionDetails", v ) && v->kind==FD_RPC_VAL_STR ) fd_rpc_val_cstr( v, details, sizeof(details) );
  int want_full = !strcmp( details, "full" );
  int want_sigs = !strcmp( details, "signatures" );
  if( FD_UNLIKELY( !want_full && !want_sigs && strcmp( details, "none" ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: getBlock supports transactionDetails full, signatures or none" );
  }
  int enc = FD_RPC_TXN_ENC_JSON;
  if( want_full && FD_UNLIKELY( !fd_rpc_txn_encoding( ctx, id_cstr, config, &enc, &response ) ) ) return response;
  int want_rewards    = !( fd_rpc_cfg_member( config, "rewards", v ) && v->kind==FD_RPC_VAL_BOOL && v->raw_sz==5UL );
  long max_version = ( fd_rpc_cfg_member( config, "maxSupportedTransactionVersion", v ) && v->kind==FD_RPC_VAL_INT && !v->neg ) ? (long)fd_ulong_min( v->u, 255UL ) : -1L;

  if( FD_UNLIKELY( slot>info->slot ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32004,\"message\":\"Block not available for slot %lu\"},\"id\":%s}\n", slot, id_cstr );
  }
  ulong next_slot;
  if( FD_UNLIKELY( !fd_rpc_slot_history_load( ctx, info, &next_slot ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: slot history unavailable" );
  if( FD_UNLIKELY( slot!=info->slot && !fd_rpc_slot_history_has( ctx, next_slot, slot ) ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32007,\"message\":\"Slot %lu was skipped, or missing due to ledger jump to recent snapshot\"},\"id\":%s}\n", slot, id_cstr );
  }

  fd_rpc_block_meta_t const * meta   = &ctx->block_metas[ slot % FD_RPC_BLOCK_META_CNT ];
  fd_rpc_block_meta_t const * parent = meta->slot==slot ? &ctx->block_metas[ meta->parent_slot % FD_RPC_BLOCK_META_CNT ] : NULL;
  fd_rpc_block_time_t const * bt     = fd_rpc_block_time_query( ctx, slot );
  if( FD_UNLIKELY( meta->slot!=slot || !parent || parent->slot!=meta->parent_slot || !bt ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32004,\"message\":\"Block not available for slot %lu\"},\"id\":%s}\n", slot, id_cstr );
  }

  ulong cnt = 0UL;
  if( want_sigs || want_full ) {
    ulong live = fd_ulong_min( ctx->txn_rec_next, FD_RPC_TXN_REC_CNT );
    for( ulong i=0UL; i<live; i++ ) {
      if( ctx->txn_recs[ i ].slot!=slot ) continue;
      if( FD_UNLIKELY( cnt==FD_RPC_BLOCK_TXN_MAX ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: block has too many transactions for getBlock" );
      ctx->block_txns[ cnt ].index_in_slot = ctx->txn_recs[ i ].index_in_slot;
      ctx->block_txns[ cnt ].rec           = (uint)i;
      cnt++;
    }
    fd_rpc_block_txn_sort_inplace( ctx->block_txns, cnt );
    /* a slot replayed twice leaves two records per position: keep one */
    ulong uniq = 0UL;
    for( ulong i=0UL; i<cnt; i++ ) {
      if( uniq && ctx->block_txns[ uniq-1UL ].index_in_slot==ctx->block_txns[ i ].index_in_slot ) continue;
      ctx->block_txns[ uniq++ ] = ctx->block_txns[ i ];
    }
    cnt = uniq;
    /* Refuse rather than return a partial block: the window may have
       wrapped past part of it, or the tile may have missed transactions. */
    if( FD_UNLIKELY( meta->txn_cnt==ULONG_MAX || cnt!=meta->txn_cnt ) ) {
      return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32004,\"message\":\"Block not available for slot %lu\"},\"id\":%s}\n", slot, id_cstr );
    }
    if( want_full ) {
      for( ulong i=0UL; i<cnt; i++ ) {
        int version = fd_rpc_txn_rec_version( &ctx->txn_recs[ ctx->block_txns[ i ].rec ] );
        if( FD_UNLIKELY( (long)version>max_version ) ) {
          return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32015,\"message\":\"Transaction version (%d) is not supported by the requesting client. Please try the request again with the following configuration parameter: \\\"maxSupportedTransactionVersion\\\": %d\"},\"id\":%s}\n", version, version, id_cstr );
        }
      }
    }
  }

  FD_BASE58_ENCODE_32_BYTES( meta->block_hash,   blockhash_b58 );
  FD_BASE58_ENCODE_32_BYTES( parent->block_hash, prev_b58      );
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"blockHeight\":%lu,\"blockTime\":%ld,\"blockhash\":\"%s\",\"parentSlot\":%lu,\"previousBlockhash\":\"%s\"",
                         meta->block_height, bt->unix_timestamp, blockhash_b58, meta->parent_slot, prev_b58 );
  if( want_rewards ) {
    /* A block that paid no fees and no epoch rewards has an empty
       list.  Anything else is not reported. */
    int epoch_rewards = 0;
    for( ulong i=0UL; i<FD_RPC_REWARD_EPOCH_CNT; i++ ) {
      fd_rpc_reward_epoch_t const * t = &ctx->reward_epochs[ i ];
      if( t->epoch!=ULONG_MAX && t->slot_lo<=slot && slot<=t->slot_hi ) epoch_rewards = 1;
    }
    int near_epoch_start = !ctx->has_epoch_schedule || slot-fd_epoch_slot0( &ctx->epoch_schedule, fd_slot_to_epoch( &ctx->epoch_schedule, slot, NULL ) )<4096UL;
    if( epoch_rewards || !meta->has_leader || ( near_epoch_start && !fd_rpc_reward_table( ctx, fd_slot_to_epoch( &ctx->epoch_schedule, slot, NULL )-1UL, 0 ) ) ) {
      fd_http_server_printf( ctx->http, ",\"rewards\":null" );
    } else if( !meta->fee_reward ) {
      fd_http_server_printf( ctx->http, ",\"rewards\":[]" );
    } else {
      /* Who collects the fee reward depends on the vote account's
         collector settings, which this tile does not track. */
      fd_http_server_printf( ctx->http, ",\"rewards\":null" );
    }
  }
  if( want_sigs ) {
    fd_http_server_printf( ctx->http, ",\"signatures\":[" );
    for( ulong i=0UL; i<cnt; i++ ) {
      FD_BASE58_ENCODE_64_BYTES( ctx->txn_recs[ ctx->block_txns[ i ].rec ].sig, sig_b58 );
      fd_http_server_printf( ctx->http, "%s\"%s\"", i ? "," : "", sig_b58 );
    }
    fd_http_server_printf( ctx->http, "]" );
  } else if( want_full ) {
    fd_http_server_printf( ctx->http, ",\"transactions\":[" );
    for( ulong i=0UL; i<cnt; i++ ) {
      fd_http_server_printf( ctx->http, "%s{", i ? "," : "" );
      if( FD_UNLIKELY( !fd_rpc_print_txn( ctx, info, &ctx->txn_recs[ ctx->block_txns[ i ].rec ], enc ) ) ) {
        fd_http_server_unstage( ctx->http );
        return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: stored transaction is unreadable" );
      }
      fd_http_server_printf( ctx->http, "}" );
    }
    fd_http_server_printf( ctx->http, "]" );
  }
  fd_http_server_printf( ctx->http, "},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getSlot( fd_rpc_tile_t *         ctx,
         char const *            id_cstr,
         fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_SLOT, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  bank_info_t * bank = &ctx->banks[ bank_idx ];
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", bank->slot, id_cstr );
}

static fd_http_server_response_t
getSlotLeader( fd_rpc_tile_t *         ctx,
               char const *            id_cstr,
               fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_SLOT_LEADER, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  ulong slot = ctx->banks[ bank_idx ].slot;
  fd_pubkey_t const * leader = fd_rpc_mleaders_get_leader_for_slot( ctx->mleaders, slot );
  if( FD_UNLIKELY( !leader ) ) {
    ulong epoch = ctx->has_epoch_schedule ? fd_slot_to_epoch( &ctx->epoch_schedule, slot, NULL ) : 0UL;
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid slot range: leader schedule for epoch %lu is unavailable\"},\"id\":%s}\n", epoch, id_cstr );
  }

  FD_BASE58_ENCODE_32_BYTES( leader->uc, leader_b58 );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":%s}\n", leader_b58, id_cstr );
}

static fd_http_server_response_t
getSlotLeaders( fd_rpc_tile_t *         ctx,
                char const *            id_cstr,
                fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_SLOT_LEADERS, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( params->kind==FD_RPC_VAL_NULL ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid type: null, expected a tuple of size 2.\"},\"id\":%s}\n", id_cstr );
  }
  if( FD_UNLIKELY( params->kind==FD_RPC_VAL_MAP ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid type: map, expected a tuple of size 2.\"},\"id\":%s}\n", id_cstr );
  }
  fd_rpc_val_t const * p0 = &params->v[ 0 ];
  fd_rpc_val_t const * p1 = &params->v[ 1 ];
  if( FD_UNLIKELY( params->kind==FD_RPC_VAL_SEQ && params->cnt!=2UL ) ) {
    ulong param_cnt = params->cnt;
    ulong unused;
    if( FD_UNLIKELY( param_cnt>=1UL && !fd_rpc_validate_uint_param( ctx, id_cstr, p0, "u64", &unused, &response ) ) ) return response;
    if( FD_UNLIKELY( param_cnt>=2UL && !fd_rpc_validate_uint_param( ctx, id_cstr, p1, "u64", &unused, &response ) ) ) return response;
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid length %lu, expected a tuple of size 2.\"},\"id\":%s}\n", param_cnt, id_cstr );
  }
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 2, 2, &response ) ) ) return response;

  ulong start_slot;
  ulong limit;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, p0, "u64", &start_slot, &response ) ) ) return response;
  if( FD_UNLIKELY( !fd_rpc_validate_uint_param( ctx, id_cstr, p1, "u64", &limit,      &response ) ) ) return response;

  if( FD_UNLIKELY( limit>5000UL ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid limit; max 5000\"},\"id\":%s}\n", id_cstr );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":[" );
  for( ulong i=0UL; i<limit; i++ ) {
    ulong slot = start_slot + i;
    fd_pubkey_t const * leader = FD_LIKELY( slot>=start_slot ) ? fd_rpc_mleaders_get_leader_for_slot( ctx->mleaders, slot ) : NULL;
    if( FD_UNLIKELY( !leader ) ) {
      fd_http_server_unstage( ctx->http );
      ulong epoch = ctx->has_epoch_schedule ? fd_slot_to_epoch( &ctx->epoch_schedule, slot, NULL ) : 0UL;
      return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid slot range: leader schedule for epoch %lu is unavailable\"},\"id\":%s}\n", epoch, id_cstr );
    }
    FD_BASE58_ENCODE_32_BYTES( leader->uc, leader_b58 );
    fd_http_server_printf( ctx->http, "%s\"%s\"", i ? "," : "", leader_b58 );
  }
  fd_http_server_printf( ctx->http, "],\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
static fd_http_server_response_t
getSupply( fd_rpc_tile_t *         ctx,
           char const *            id_cstr,
           fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 0 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  /* Total supply is the sum of every account's lamports.  Firedancer
     has no list of non-circulating accounts (Agave's is a hard-coded
     mainnet list plus locked stake), so all of it is reported as
     circulating. */
  static fd_rpc_largest_t l[1];
  memset( l, 0, sizeof(l) );
  fd_rpc_scan( ctx, info, NULL, 0UL, 0, fd_rpc_largest_visit, l );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":{\"circulating\":%lu,\"nonCirculating\":0,\"nonCirculatingAccounts\":[],\"total\":%lu}},\"id\":%s}\n",
                      FD_RPC_AGAVE_API_VERSION, info->slot, l->total, l->total, id_cstr );
}
/* Reads a mint and returns its decimals and supply.  Returns 0 if the
   account is not a token mint. */
static int
fd_rpc_read_mint( fd_rpc_tile_t *     ctx,
                  bank_info_t const * info,
                  uchar const *       mint,
                  uchar *             decimals,
                  ulong *             supply ) {
  ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, mint, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
  if( FD_UNLIKELY( !lamports || data_len<FD_RPC_TOKEN_MINT_MIN_SZ || !fd_rpc_owner_is_token_program( owner ) ) ) return 0;
  /* A token-2022 mint with extensions is padded to the account size
     and tagged 1 at offset 165; an account is tagged 2. */
  if( FD_UNLIKELY( data_len==FD_RPC_TOKEN_ACCOUNT_MIN_SZ ) ) return 0;
  if( FD_UNLIKELY( data_len>FD_RPC_TOKEN_ACCOUNT_MIN_SZ && ctx->scratch.accdb_data_buf[ FD_RPC_TOKEN_ACCOUNT_MIN_SZ ]!=1 ) ) return 0;
  *supply   = FD_LOAD( ulong, ctx->scratch.accdb_data_buf+36UL );
  *decimals = ctx->scratch.accdb_data_buf[ 44UL ];
  return 1;
}

static fd_http_server_response_t
getTokenAccountBalance( fd_rpc_tile_t *         ctx,
                        char const *            id_cstr,
                        fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_pubkey_t address;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &address, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 1 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, address.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
  if( FD_UNLIKELY( !lamports ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: could not find account" );
  if( FD_UNLIKELY( data_len<FD_RPC_TOKEN_ACCOUNT_MIN_SZ || !fd_rpc_owner_is_token_program( owner ) ||
                   ( data_len>FD_RPC_TOKEN_ACCOUNT_MIN_SZ && ctx->scratch.accdb_data_buf[ FD_RPC_TOKEN_ACCOUNT_MIN_SZ ]!=2 ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: not a Token account" );
  }
  uchar mint[ 32UL ];
  memcpy( mint, ctx->scratch.accdb_data_buf, 32UL );
  ulong amount = FD_LOAD( ulong, ctx->scratch.accdb_data_buf+64UL );

  uchar decimals; ulong supply;
  if( FD_UNLIKELY( !fd_rpc_read_mint( ctx, info, mint, &decimals, &supply ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: mint could not be unpacked" );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":", FD_RPC_AGAVE_API_VERSION, info->slot );
  fd_rpc_print_ui_amount( ctx, amount, decimals );
  fd_http_server_printf( ctx->http, "},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
static fd_http_server_response_t
getTokenAccountsByDelegate( fd_rpc_tile_t *         ctx,
                            char const *            id_cstr,
                            fd_rpc_params_t const * params ) {
  return fd_rpc_token_accounts_by( ctx, id_cstr, params, 2 );
}

static fd_http_server_response_t
getTokenAccountsByOwner( fd_rpc_tile_t *         ctx,
                         char const *            id_cstr,
                         fd_rpc_params_t const * params ) {
  return fd_rpc_token_accounts_by( ctx, id_cstr, params, 1 );
}

static fd_http_server_response_t
getTokenLargestAccounts( fd_rpc_tile_t *         ctx,
                         char const *            id_cstr,
                         fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_pubkey_t mint;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &mint, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 1 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  /* the mint decides which token program holds its accounts */
  ulong lamports; int executable; uchar mint_owner[ 32UL ]; ulong data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, mint.uc, &lamports, &executable, mint_owner, ctx->scratch.accdb_data_buf, &data_len );
  uchar decimals; ulong supply;
  if( FD_UNLIKELY( !fd_rpc_read_mint( ctx, info, mint.uc, &decimals, &supply ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: not a Token mint" );

  static fd_rpc_largest_t l[1];
  memset( l, 0, sizeof(l) );
  l->token_mode = 1;
  memcpy( l->mint, mint.uc, 32UL );
  fd_rpc_scan( ctx, info, mint_owner, FD_RPC_TOKEN_ACCOUNT_MIN_SZ, 1, fd_rpc_largest_visit, l );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":[", FD_RPC_AGAVE_API_VERSION, info->slot );
  for( ulong i=0UL; i<l->cnt; i++ ) {
    FD_BASE58_ENCODE_32_BYTES( l->e[ i ].key, key_b58 );
    /* {"address":..,"amount":..,"decimals":..,"uiAmount":..,"uiAmountString":..} */
    fd_http_server_printf( ctx->http, "%s{\"address\":\"%s\",", i ? "," : "", key_b58 );
    fd_rpc_print_ui_amount_fields( ctx, l->e[ i ].amount, decimals );
    fd_http_server_printf( ctx->http, "}" );
  }
  fd_http_server_printf( ctx->http, "]},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
static fd_http_server_response_t
getTokenSupply( fd_rpc_tile_t *         ctx,
                char const *            id_cstr,
                fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_pubkey_t address;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &address, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 1 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  uchar decimals; ulong supply;
  if( FD_UNLIKELY( !fd_rpc_read_mint( ctx, info, address.uc, &decimals, &supply ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid param: not a Token mint" );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":", FD_RPC_AGAVE_API_VERSION, info->slot );
  fd_rpc_print_ui_amount( ctx, supply, decimals );
  fd_http_server_printf( ctx->http, "},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}

static fd_http_server_response_t
getTransactionCount( fd_rpc_tile_t *         ctx,
                     char const *            id_cstr,
                     fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_TRANSACTION_COUNT, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  ulong bank_idx = ULONG_MAX;
  fd_rpc_val_t const * config = &params->v[ 0 ];
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcContextConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             1, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  bank_info_t * bank = &ctx->banks[ bank_idx ];
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", bank->transaction_count, id_cstr );
}

static fd_http_server_response_t
getVersion( fd_rpc_tile_t *         ctx,
            char const *            id_cstr,
            fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_VERSION, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"solana-core\":\"%s\",\"feature-set\":%u},\"id\":%s}\n", fd_version_cstr, FD_FEATURE_SET_ID, id_cstr );
}

static fd_http_server_response_t
voteSubscribe( fd_rpc_tile_t *         ctx,
               char const *            id_cstr,
               fd_rpc_params_t const * params,
               ulong                   ws_conn_id ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_VOTE_SUBSCRIBE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  if( FD_UNLIKELY( ws_conn_id==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }
  FD_CHECK_CRIT( ws_conn_id < ctx->http->max_ws_conns, "OOB ws_conn_id" );

  fd_rpc_ws_subscriber_vote_add( ctx, ws_conn_id );

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", ctx->ws_sub_id_vote, id_cstr );
}

static fd_http_server_response_t
slotSubscribe( fd_rpc_tile_t *         ctx,
               char const *            id_cstr,
               fd_rpc_params_t const * params,
               ulong                   ws_conn_id ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_SLOT_SUBSCRIBE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 0, &response ) ) ) return response;

  if( FD_UNLIKELY( ws_conn_id==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }
  FD_CHECK_CRIT( ws_conn_id < ctx->http->max_ws_conns, "OOB ws_conn_id" );

  fd_rpc_ws_subscriber_slot_add( ctx, ws_conn_id );

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", ctx->ws_sub_id_slot, id_cstr );
}

static void
fd_rpc_ws_acct_check( fd_rpc_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->processed_idx==ULONG_MAX || ctx->confirmed_idx==ULONG_MAX || ctx->finalized_idx==ULONG_MAX ) ) return;
  ulong level_idx[ 3 ] = { ctx->processed_idx, ctx->confirmed_idx, ctx->finalized_idx };
  for( ulong i=0UL; i<FD_RPC_WS_ACCT_SUB_MAX; i++ ) {
    if( !ctx->ws_acct_subs[ i ].sub_id ) continue;
    bank_info_t const * info = &ctx->banks[ level_idx[ ctx->ws_acct_subs[ i ].level ] ];
    ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
    fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, ctx->ws_acct_subs[ i ].pubkey,
                               &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
    if( !lamports ) { data_len = 0UL; executable = 0; memset( owner, 0, 32UL ); }
    ulong h = fd_hash( lamports ^ (ulong)executable, owner, 32UL ) ^ fd_hash( data_len, ctx->scratch.accdb_data_buf, data_len );
    if( !ctx->ws_acct_subs[ i ].primed ) { ctx->ws_acct_subs[ i ].primed = 1; ctx->ws_acct_subs[ i ].last_hash = h; continue; }
    if( h==ctx->ws_acct_subs[ i ].last_hash ) continue;
    ctx->ws_acct_subs[ i ].last_hash = h;

    ulong ws_conn_id = ctx->ws_acct_subs[ i ].ws_conn_id;
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"method\":\"accountNotification\",\"params\":{\"result\":{\"context\":{\"slot\":%lu},\"value\":", info->slot );
    fd_http_server_response_t err_response;
    ctx->encode_key = ctx->ws_acct_subs[ i ].pubkey;
    int encoded = fd_rpc_encode_account_data( ctx, ctx->scratch.accdb_data_buf, data_len, owner, lamports, executable, ctx->ws_acct_subs[ i ].encoding, 0UL, ULONG_MAX, "null", &err_response );
    ctx->encode_key = NULL;
    if( FD_UNLIKELY( !encoded ) ) { fd_http_server_unstage( ctx->http ); continue; } /* e.g. too large for base58 */
    fd_http_server_printf( ctx->http, "},\"subscription\":%lu}}\n", ctx->ws_acct_subs[ i ].sub_id-1UL );
    if( FD_UNLIKELY( fd_http_server_ws_send( ctx->http, ws_conn_id ) ) ) {
      fd_http_server_ws_close( ctx->http, ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_TOO_SLOW );
    }
  }
}

static fd_http_server_response_t
accountSubscribe( fd_rpc_tile_t *         ctx,
                  char const *            id_cstr,
                  fd_rpc_params_t const * params,
                  ulong                   ws_conn_id ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  if( FD_UNLIKELY( ws_conn_id==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }
  FD_CHECK_CRIT( ws_conn_id < ctx->http->max_ws_conns, "OOB ws_conn_id" );

  fd_pubkey_t address;
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &address, &response ) ) ) return response;

  int  level = 2;
  char encoding[ 16 ] = "binary";
  fd_rpc_val_t cv[1];
  if( fd_rpc_cfg_member( &params->v[ 1 ], "commitment", cv ) ) {
    char c[ 16 ];
    if( FD_LIKELY( fd_rpc_val_cstr( cv, c, sizeof(c) ) ) ) level = !strcmp( c, "processed" ) ? 0 : !strcmp( c, "confirmed" ) ? 1 : 2;
  }
  if( fd_rpc_cfg_member( &params->v[ 1 ], "encoding", cv ) ) {
    char e[ 16 ];
    if( FD_UNLIKELY( !fd_rpc_val_cstr( cv, e, sizeof(e) ) ||
                     ( strcmp( e, "binary" ) && strcmp( e, "base58" ) && strcmp( e, "base64" ) && strcmp( e, "base64+zstd" ) && strcmp( e, "jsonParsed" ) ) ) ) {
      fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: unknown variant `" );
      if( cv->kind==FD_RPC_VAL_STR ) fd_rpc_print_str( ctx, &cv->str );
      fd_http_server_printf( ctx->http, "`, expected one of `binary`, `base58`, `base64`, `jsonParsed`, `base64+zstd`.\"},\"id\":%s}\n", id_cstr );
      return STAGE_JSON( ctx );
    }
    strcpy( encoding, e );
  }

  ulong pick = 0UL;
  for( ulong i=0UL; i<FD_RPC_WS_ACCT_SUB_MAX; i++ ) {
    if( !ctx->ws_acct_subs[ i ].sub_id ) { pick = i; break; }
    if( ctx->ws_acct_subs[ i ].sub_id<ctx->ws_acct_subs[ pick ].sub_id ) pick = i;
  }
  if( !ctx->ws_acct_subs[ pick ].sub_id ) ctx->ws_acct_sub_cnt++;
  ulong sub_id = ctx->ws_sub_id_next++;
  ctx->ws_acct_subs[ pick ].sub_id     = sub_id+1UL;
  ctx->ws_acct_subs[ pick ].ws_conn_id = ws_conn_id;
  ctx->ws_acct_subs[ pick ].level      = level;
  ctx->ws_acct_subs[ pick ].primed     = 0;
  memcpy( ctx->ws_acct_subs[ pick ].pubkey, address.uc, 32UL );
  strcpy( ctx->ws_acct_subs[ pick ].encoding, encoding );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", sub_id, id_cstr );
}

static fd_http_server_response_t
signatureSubscribe( fd_rpc_tile_t *         ctx,
                    char const *            id_cstr,
                    fd_rpc_params_t const * params,
                    ulong                   ws_conn_id ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  if( FD_UNLIKELY( ws_conn_id==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }
  FD_CHECK_CRIT( ws_conn_id < ctx->http->max_ws_conns, "OOB ws_conn_id" );

  char  sig_cstr[ 96 ];
  uchar sig[ 64 ];
  if( FD_UNLIKELY( !fd_rpc_val_cstr( &params->v[ 0 ], sig_cstr, sizeof(sig_cstr) ) || !fd_base58_decode_64( sig_cstr, sig ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid Request: Invalid signature provided" );
  }
  int level = 2;
  fd_rpc_val_t cv[1];
  if( fd_rpc_cfg_member( &params->v[ 1 ], "commitment", cv ) ) {
    char c[ 16 ];
    if( FD_LIKELY( fd_rpc_val_cstr( cv, c, sizeof(c) ) ) ) level = !strcmp( c, "processed" ) ? 0 : !strcmp( c, "confirmed" ) ? 1 : 2;
  }

  /* a free entry, else the oldest one */
  ulong pick = 0UL;
  for( ulong i=0UL; i<FD_RPC_WS_SIG_SUB_MAX; i++ ) {
    if( !ctx->ws_sig_subs[ i ].sub_id ) { pick = i; break; }
    if( ctx->ws_sig_subs[ i ].sub_id<ctx->ws_sig_subs[ pick ].sub_id ) pick = i;
  }
  if( !ctx->ws_sig_subs[ pick ].sub_id ) ctx->ws_sig_sub_cnt++;
  ulong sub_id = ctx->ws_sub_id_next++;
  ctx->ws_sig_subs[ pick ].sub_id     = sub_id+1UL;
  ctx->ws_sig_subs[ pick ].ws_conn_id = ws_conn_id;
  ctx->ws_sig_subs[ pick ].level      = level;
  memcpy( ctx->ws_sig_subs[ pick ].sig, sig, 64UL );
  /* A transaction that is already there is notified on the next slot,
     after this reply. */
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%s}\n", sub_id, id_cstr );
}

static fd_http_server_response_t
voteUnsubscribe( fd_rpc_tile_t *         ctx,
                 char const *            id_cstr,
                 fd_rpc_params_t const * params,
                 ulong                   ws_conn_id ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_VOTE_UNSUBSCRIBE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 1, &response ) ) ) return response;

  if( FD_UNLIKELY( ws_conn_id==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }
  FD_CHECK_CRIT( ws_conn_id < ctx->http->max_ws_conns, "OOB ws_conn_id" );

  fd_rpc_val_t const * subscription = &params->v[ 0 ];
  if( FD_UNLIKELY( subscription->kind!=FD_RPC_VAL_INT || subscription->neg ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid type: %s, expected usize.\"},\"id\":%s}\n", fd_rpc_val_kind_cstr( subscription ), id_cstr );
  }

  if( FD_UNLIKELY( !fd_rpc_ws_unsubscribe( ctx, subscription->u, ws_conn_id ) ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid subscription id.\"},\"id\":%s}\n", id_cstr );
  }

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":true,\"id\":%s}\n", id_cstr );
}

static fd_http_server_response_t
slotUnsubscribe( fd_rpc_tile_t *         ctx,
                 char const *            id_cstr,
                 fd_rpc_params_t const * params,
                 ulong                   ws_conn_id ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_SLOT_UNSUBSCRIBE, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 1, &response ) ) ) return response;

  if( FD_UNLIKELY( ws_conn_id==ULONG_MAX ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }
  FD_CHECK_CRIT( ws_conn_id < ctx->http->max_ws_conns, "OOB ws_conn_id" );

  fd_rpc_val_t const * subscription = &params->v[ 0 ];
  if( FD_UNLIKELY( subscription->kind!=FD_RPC_VAL_INT || subscription->neg ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid type: %s, expected usize.\"},\"id\":%s}\n", fd_rpc_val_kind_cstr( subscription ), id_cstr );
  }

  if( FD_UNLIKELY( !fd_rpc_ws_unsubscribe( ctx, subscription->u, ws_conn_id ) ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid subscription id.\"},\"id\":%s}\n", id_cstr );
  }

  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":true,\"id\":%s}\n", id_cstr );
}

static int
fd_rpc_vote_info_load( fd_rpc_tile_t *      ctx,
                       fd_accdb_fork_id_t   accdb_fork_id,
                       fd_pubkey_t const *  vote_key,
                       fd_rpc_vote_info_t * out ) {
  ulong lamports;
  int   executable;
  uchar owner[ 32UL ];
  ulong data_sz;
  fd_accdb_read_one_nocache( ctx->accdb, accdb_fork_id, vote_key->uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_sz );
  if( FD_UNLIKELY( !lamports || memcmp( owner, fd_solana_vote_program_id.uc, 32UL ) ) ) return 0;

  uchar const * data = ctx->scratch.accdb_data_buf;
  if( FD_UNLIKELY( data_sz<sizeof(uint) ) ) return 0;
  if( FD_UNLIKELY( fd_vote_account_node_pubkey( data, data_sz, &out->node_key ) ) ) return 0;
  if( FD_UNLIKELY( fd_vote_account_commission_bps( data, data_sz, 1, &out->commission_bps ) ) ) return 0;

  ulong                           credits_cnt;
  fd_vote_epoch_credits_t const * credits = fd_vote_account_epoch_credits( data, data_sz, &credits_cnt );
  if( FD_UNLIKELY( !credits ) ) return 0;

  switch( FD_LOAD( uint, data ) ) {
  case fd_vote_state_versioned_enum_v5: {
    ulong latest_vote = FD_LOAD( ulong, data+sizeof(uint)+offsetof( fd_vote_state_v5_t, latest_vote ) );
    ulong root_slot   = FD_LOAD( ulong, data+sizeof(uint)+offsetof( fd_vote_state_v5_t, root_slot   ) );
    out->last_vote = latest_vote==ULONG_MAX ? 0UL : latest_vote;
    out->root_slot = root_slot==ULONG_MAX   ? 0UL : root_slot;
    break;
  }
  case fd_vote_state_versioned_enum_v3:
  case fd_vote_state_versioned_enum_v4: {
    fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_deserialize( ctx->vote_state, data, data_sz );
    if( FD_UNLIKELY( !vsv ) ) return 0;
    int                      v3       = vsv->kind==fd_vote_state_versioned_enum_v3;
    fd_landed_vote_t const * votes    = v3 ? vsv->v3.votes         : vsv->v4.votes;
    int                      has_root = v3 ? vsv->v3.has_root_slot : vsv->v4.has_root_slot;
    ulong                    root     = v3 ? vsv->v3.root_slot     : vsv->v4.root_slot;
    out->last_vote = deq_fd_landed_vote_t_empty( votes ) ? 0UL : deq_fd_landed_vote_t_peek_tail_const( votes )->lockout.slot;
    out->root_slot = has_root ? root : 0UL;
    break;
  }
  default:
    return 0;
  }

  ulong skip = fd_ulong_sat_sub( credits_cnt, FD_RPC_VOTE_ACCOUNT_CREDITS_MAX );
  out->credits_cnt = credits_cnt-skip;
  fd_memcpy( out->credits, credits+skip, out->credits_cnt*sizeof(fd_vote_epoch_credits_t) );
  return 1;
}

static void
fd_rpc_print_vote_infos( fd_rpc_tile_t *            ctx,
                         fd_rpc_vote_info_t const * infos,
                         ulong                      info_cnt,
                         fd_pubkey_t const *        filter,
                         ulong                      slot,
                         ulong                      distance,
                         int                        keep_unstaked,
                         int                        delinquent ) {
  int first = 1;
  for( ulong i=0UL; i<info_cnt; i++ ) {
    fd_rpc_vote_info_t const * info = &infos[ i ];
    if( filter && !fd_pubkey_eq( &info->vote_key, filter ) ) continue;
    int info_delinquent = slot>=distance ? info->last_vote<=(slot-distance) : !info->last_vote;
    if( info_delinquent!=delinquent ) continue;
    if( info_delinquent && !info->stake && !keep_unstaked ) continue;

    FD_BASE58_ENCODE_32_BYTES( info->vote_key.uc, vote_b58 );
    FD_BASE58_ENCODE_32_BYTES( info->node_key.uc, node_b58 );
    ulong commission = fd_ulong_min( ((ulong)info->commission_bps+99UL)/100UL, (ulong)UCHAR_MAX );
    fd_http_server_printf( ctx->http, "%s{\"votePubkey\":\"%s\",\"nodePubkey\":\"%s\",\"activatedStake\":%lu,\"commission\":%lu,\"inflationRewardsCommissionBps\":%u,\"epochVoteAccount\":%s,\"epochCredits\":[",
                           first ? "" : ",", vote_b58, node_b58, info->stake, commission, (uint)info->commission_bps, info->epoch_vote_account ? "true" : "false" );
    for( ulong k=0UL; k<info->credits_cnt; k++ ) {
      fd_http_server_printf( ctx->http, "%s[%lu,%lu,%lu]", k ? "," : "", info->credits[ k ].epoch, info->credits[ k ].credits, info->credits[ k ].prev_credits );
    }
    fd_http_server_printf( ctx->http, "],\"lastVote\":%lu,\"rootSlot\":%lu}", info->last_vote, info->root_slot );
    first = 0;
  }
}

static ulong
fd_rpc_vote_infos_load( fd_rpc_tile_t *           ctx,
                        bank_info_t const *       bank,
                        fd_rpc_vote_set_t const * cur,
                        fd_rpc_vote_set_t const * nxt,
                        fd_pubkey_t const *       filter,
                        fd_rpc_vote_info_t *      infos ) {
  ulong nxt_cnt  = nxt ? nxt->cnt : 0UL;
  ulong info_cnt = 0UL;
  ulong i        = 0UL;
  ulong j        = 0UL;
  while( i<cur->cnt || j<nxt_cnt ) {
    int cmp;
    if(      i>=cur->cnt ) cmp =  1;
    else if( j>=nxt_cnt  ) cmp = -1;
    else                   cmp = memcmp( cur->ele[ i ].vote_key.uc, nxt->ele[ j ].vote_key.uc, 32UL );

    fd_rpc_vote_set_ele_t const * ele_cur = NULL;
    fd_rpc_vote_set_ele_t const * ele_nxt = NULL;
    if( cmp<=0 ) ele_cur = &cur->ele[ i++ ];
    if( cmp>=0 ) ele_nxt = &nxt->ele[ j++ ];
    fd_pubkey_t const * vote_key = ele_cur ? &ele_cur->vote_key : &ele_nxt->vote_key;

    if( filter && !fd_pubkey_eq( vote_key, filter ) ) continue;

    fd_rpc_vote_info_t * info = &infos[ info_cnt ];
    if( FD_UNLIKELY( !fd_rpc_vote_info_load( ctx, bank->accdb_fork_id, vote_key, info ) ) ) continue;
    info->vote_key           = *vote_key;
    info->stake              = ele_nxt ? ele_nxt->stake : ( nxt ? 0UL : ele_cur->stake );
    info->epoch_vote_account = !!ele_cur;
    info_cnt++;
    if( filter ) break;
  }
  return info_cnt;
}

static fd_http_server_response_t
getVoteAccounts( fd_rpc_tile_t *         ctx,
                 char const *            id_cstr,
                 fd_rpc_params_t const * params ) {
  FD_MCNT_INC( RPC, REQUEST_HANDLED_GET_VOTE_ACCOUNTS, 1UL );

  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;

  fd_rpc_val_t const * config   = &params->v[ 0 ];
  ulong                bank_idx = ULONG_MAX;
  int config_valid = fd_rpc_validate_config( ctx, id_cstr, config, "struct RpcGetVoteAccountsConfig",
                                             1, /* has_commitment */
                                             0, /* has_encoding */
                                             0, /* has_data_slice */
                                             0, /* has_min_context_slot */
                                             &bank_idx,
                                             NULL,
                                             NULL,
                                             NULL,
                                             NULL,
                                             &response );
  if( FD_UNLIKELY( !config_valid ) ) return response;

  fd_rpc_config_t cfg[ 1 ];
  fd_rpc_config_read( config, cfg );

  fd_rpc_val_t const * vote_pubkey = &cfg->vote_pubkey;
  int                  has_filter  = vote_pubkey->kind!=FD_RPC_VAL_NONE && vote_pubkey->kind!=FD_RPC_VAL_NULL;
  if( FD_UNLIKELY( has_filter && vote_pubkey->kind!=FD_RPC_VAL_STR ) ) {
    return fd_rpc_err_invalid( ctx, id_cstr, "type", vote_pubkey, "a string" );
  }

  fd_rpc_val_t const * keep          = &cfg->keep_unstaked_delinquents;
  int                  keep_unstaked = 0;
  if( keep->kind==FD_RPC_VAL_BOOL ) {
    keep_unstaked = keep->raw_sz && keep->raw[ 0 ]=='t';
  } else if( FD_UNLIKELY( keep->kind!=FD_RPC_VAL_NONE && keep->kind!=FD_RPC_VAL_NULL ) ) {
    return fd_rpc_err_invalid( ctx, id_cstr, "type", keep, "a boolean" );
  }

  fd_rpc_val_t const * distance_val = &cfg->delinquent_slot_distance;
  ulong                distance     = FD_RPC_DELINQUENT_SLOT_DISTANCE;
  if( distance_val->kind==FD_RPC_VAL_INT ) {
    if( FD_UNLIKELY( distance_val->neg ) ) return fd_rpc_err_invalid( ctx, id_cstr, "value", distance_val, "u64" );
    distance = distance_val->u;
  } else if( FD_UNLIKELY( distance_val->kind!=FD_RPC_VAL_NONE && distance_val->kind!=FD_RPC_VAL_NULL ) ) {
    return fd_rpc_err_invalid( ctx, id_cstr, "type", distance_val, "u64" );
  }

  fd_pubkey_t filter[ 1 ];
  if( has_filter && FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, vote_pubkey, filter, &response ) ) ) return response;

  bank_info_t const *       bank = &ctx->banks[ bank_idx ];
  fd_rpc_vote_set_t const * cur  = fd_rpc_vote_set_query( ctx, bank->epoch );
  if( FD_UNLIKELY( !cur ) ) {
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
  }
  fd_rpc_vote_set_t const * nxt = fd_rpc_vote_set_query( ctx, bank->epoch+1UL );

  fd_rpc_vote_info_t         filtered[ 1 ];
  fd_rpc_vote_info_t const * infos    = ctx->vote_infos;
  ulong                      info_cnt = ctx->vote_infos_cnt;
  int cached = ctx->vote_infos_valid && ctx->vote_infos_slot==bank->slot && ctx->vote_infos_has_nxt==!!nxt &&
               !memcmp( ctx->vote_infos_block_hash, bank->block_hash, 32UL );
  if( !cached ) {
    if( has_filter ) {
      info_cnt = fd_rpc_vote_infos_load( ctx, bank, cur, nxt, filter, filtered );
      infos    = filtered;
    } else {
      ctx->vote_infos_valid   = 0;
      ctx->vote_infos_cnt     = fd_rpc_vote_infos_load( ctx, bank, cur, nxt, NULL, ctx->vote_infos );
      ctx->vote_infos_slot    = bank->slot;
      ctx->vote_infos_has_nxt = !!nxt;
      fd_memcpy( ctx->vote_infos_block_hash, bank->block_hash, 32UL );
      ctx->vote_infos_valid   = 1;
      info_cnt                = ctx->vote_infos_cnt;
    }
  }
  fd_pubkey_t const * print_filter = has_filter ? filter : NULL;

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"current\":[" );
  fd_rpc_print_vote_infos( ctx, infos, info_cnt, print_filter, bank->slot, distance, keep_unstaked, 0 );
  fd_http_server_printf( ctx->http, "],\"delinquent\":[" );
  fd_rpc_print_vote_infos( ctx, infos, info_cnt, print_filter, bank->slot, distance, keep_unstaked, 1 );
  fd_http_server_printf( ctx->http, "]},\"id\":%s}\n", id_cstr );
  return STAGE_JSON( ctx );
}
static fd_http_server_response_t
isBlockhashValid( fd_rpc_tile_t *         ctx,
                  char const *            id_cstr,
                  fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_pubkey_t hash; /* a blockhash has the same 32 byte base58 form as an address */
  if( FD_UNLIKELY( !fd_rpc_validate_address( ctx, id_cstr, &params->v[ 0 ], &hash, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 1 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  /* The bank's own blockhash, then the RecentBlockhashes sysvar: the
     150 blockhashes before it, which is the window a transaction may
     still reference. */
  int valid = !memcmp( info->block_hash, hash.uc, 32UL );
  if( !valid ) {
    ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
    fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, fd_sysvar_recent_block_hashes_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
    if( FD_LIKELY( lamports && data_len>=8UL ) ) {
      ulong cnt = FD_LOAD( ulong, ctx->scratch.accdb_data_buf );
      cnt = fd_ulong_min( cnt, (data_len-8UL)/40UL );
      for( ulong i=0UL; i<cnt && !valid; i++ ) valid = !memcmp( ctx->scratch.accdb_data_buf+8UL+40UL*i, hash.uc, 32UL );
    }
  }
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":%s},\"id\":%s}\n", FD_RPC_AGAVE_API_VERSION, info->slot, valid ? "true" : "false", id_cstr );
}
static fd_http_server_response_t
minimumLedgerSlot( fd_rpc_tile_t *         ctx,
                   char const *            id_cstr,
                   fd_rpc_params_t const * params ) {
  return fd_rpc_first_slot( ctx, id_cstr, params );
}
UNIMPLEMENTED(requestAirdrop)
/* sendTransaction checks what it can without executing the transaction
   (well formed, signatures valid and, unless skipPreflight, a recent
   blockhash), then sends it to the upcoming leaders over UDP and keeps
   resending it each leader rotation until it lands or expires.  There
   is no simulation: a transaction that would fail on chain is still
   sent, and lands as a failed transaction. */
static fd_http_server_response_t
sendTransaction( fd_rpc_tile_t *         ctx,
                 char const *            id_cstr,
                 fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_rpc_val_t const * t      = &params->v[ 0 ];
  fd_rpc_val_t const * config = &params->v[ 1 ];
  if( FD_UNLIKELY( t->kind!=FD_RPC_VAL_STR ) ) return fd_rpc_err_invalid( ctx, id_cstr, "type", t, "a string" );
  if( FD_UNLIKELY( ctx->processed_idx==ULONG_MAX ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: banks uninitialized" );
  bank_info_t const * tip = &ctx->banks[ ctx->processed_idx ];

  fd_rpc_val_t v[1];
  char enc[ 16 ] = "base58";
  if( fd_rpc_cfg_member( config, "encoding", v ) && v->kind==FD_RPC_VAL_STR ) fd_rpc_val_cstr( v, enc, sizeof(enc) );
  int skip_preflight = fd_rpc_cfg_member( config, "skipPreflight", v ) && v->kind==FD_RPC_VAL_BOOL && v->raw_sz==4UL;

  static char  txt[ 2UL*FD_TXN_MTU_V0 ];
  static uchar payload[ 2UL*FD_TXN_MTU_V0 ];
  if( FD_UNLIKELY( !fd_rpc_val_cstr( t, txt, sizeof(txt) ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: transaction too large." );
  ulong txt_len = strlen( txt );
  ulong payload_sz;
  if( !strcmp( enc, "base64" ) ) {
    long dec = (ulong)FD_BASE64_DEC_SZ( txt_len )<=sizeof(payload) ? fd_base64_decode( payload, txt, txt_len ) : -1L;
    payload_sz = dec<0L ? ULONG_MAX : (ulong)dec;
  } else if( !strcmp( enc, "base58" ) ) {
    payload_sz = fd_rpc_base58_decode( txt, txt_len, payload, sizeof(payload) );
  } else {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: unsupported encoding, expected base58 or base64." );
  }
  uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  if( FD_UNLIKELY( payload_sz==ULONG_MAX || payload_sz>FD_TXN_MTU_V0 || !fd_txn_parse( payload, payload_sz, txn_buf, NULL ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: failed to deserialize transaction." );
  }
  fd_txn_t const * txn = (fd_txn_t const *)txn_buf;
  if( FD_UNLIKELY( !txn->signature_cnt ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: transaction has no signatures." );

  uchar const * sigs  = payload+txn->signature_off;
  uchar const * accts = payload+txn->acct_addr_off;
  uchar const * msg   = payload+txn->message_off;
  ulong         msg_sz = fd_txn_msg_sz( txn, payload_sz );
  for( ulong i=0UL; i<txn->signature_cnt; i++ ) {
    if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( msg, msg_sz, sigs+64UL*i, accts+32UL*i, ctx->sha ) ) ) {
      return fd_rpc_err_msg( ctx, id_cstr, -32003, "Transaction signature verification failure" );
    }
  }

  if( !skip_preflight ) {
    /* A durable nonce transaction (first instruction is the system
       program's AdvanceNonceAccount) carries a nonce, not a recent
       blockhash, so it is exempt. */
    int is_nonce = 0;
    if( txn->instr_cnt ) {
      fd_txn_instr_t const * ix = &txn->instr[ 0 ];
      is_nonce = !memcmp( accts+32UL*ix->program_id, fd_solana_system_program_id.uc, 32UL ) && ix->data_sz>=4UL && FD_LOAD( uint, payload+ix->data_off )==4U;
    }
    uchar const * bh = payload+txn->recent_blockhash_off;
    int valid = is_nonce || !memcmp( tip->block_hash, bh, 32UL );
    if( !valid ) {
      ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
      fd_accdb_read_one_nocache( ctx->accdb, tip->accdb_fork_id, fd_sysvar_recent_block_hashes_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
      if( FD_LIKELY( lamports && data_len>=8UL ) ) {
        ulong cnt = fd_ulong_min( FD_LOAD( ulong, ctx->scratch.accdb_data_buf ), (data_len-8UL)/40UL );
        for( ulong i=0UL; i<cnt && !valid; i++ ) valid = !memcmp( ctx->scratch.accdb_data_buf+8UL+40UL*i, bh, 32UL );
      }
    }
    if( FD_UNLIKELY( !valid ) ) {
      return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32002,\"message\":\"Transaction simulation failed: Blockhash not found\",\"data\":{\"accounts\":null,\"err\":\"BlockhashNotFound\",\"innerInstructions\":null,\"logs\":[],\"returnData\":null,\"unitsConsumed\":0}},\"id\":%s}\n", id_cstr );
    }
  }

  fd_rpc_send_to_leaders( ctx, payload, payload_sz, tip->slot+1UL );

  /* remember it for resending, replacing the oldest entry if full */
  fd_rpc_send_pending_t * slot_p = NULL;
  for( ulong i=0UL; i<FD_RPC_SEND_PENDING_MAX; i++ ) {
    fd_rpc_send_pending_t * p = &ctx->send_pending[ i ];
    if( p->used && !memcmp( p->sig, sigs, 64UL ) ) { slot_p = p; break; }
    if( !p->used ) { if( !slot_p || slot_p->used ) slot_p = p; }
    else if( !slot_p || ( slot_p->used && p->submit_slot<slot_p->submit_slot ) ) slot_p = p;
  }
  slot_p->used        = 1;
  slot_p->sz          = (ushort)payload_sz;
  slot_p->submit_slot = tip->slot;
  memcpy( slot_p->sig, sigs, 64UL );
  memcpy( slot_p->payload, payload, payload_sz );

  FD_BASE58_ENCODE_64_BYTES( sigs, sig_b58 );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":%s}\n", sig_b58, id_cstr );
}
/* ---- simulateTransaction --------------------------------------------------
   Runs the transaction in the tile's private runtime (fd_rpc_sim.h)
   against copies of the live accounts it names. */

/* Copies one account from the live accounts database into the
   simulator.  If it is an upgradeable program, its programdata account
   is copied too.  Returns 0 if the account does not exist. */
static int
fd_rpc_sim_load( fd_rpc_tile_t *     ctx,
                 bank_info_t const * info,
                 uchar const *       key ) {
  ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
  fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, key, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
  if( !lamports ) return 0;
  fd_rpc_sim_put( ctx->sim, key, lamports, owner, executable, ctx->scratch.accdb_data_buf, data_len );
  if( executable && data_len>=36UL && !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.uc, 32UL ) &&
      FD_LOAD( uint, ctx->scratch.accdb_data_buf )==2U ) {
    uchar programdata[ 32 ];
    memcpy( programdata, ctx->scratch.accdb_data_buf+4UL, 32UL );
    fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, programdata, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
    if( lamports ) fd_rpc_sim_put( ctx->sim, programdata, lamports, owner, executable, ctx->scratch.accdb_data_buf, data_len );
  }
  return 1;
}

/* fd_rpc_sim_prepare resets the simulator and loads it with the state
   a transaction needs: the bank's sysvars and blockhashes, the
   transaction's accounts and whatever its lookup tables resolve to. */
static void
fd_rpc_sim_prepare( fd_rpc_tile_t *     ctx,
                    bank_info_t const * info,
                    uchar const *       payload,
                    fd_txn_t const *    txn ) {
  uchar const * accts = payload+txn->acct_addr_off;
  fd_rent_t rent = { .lamports_per_uint8_year = info->rent.lamports_per_uint8_year, .exemption_threshold = info->rent.exemption_threshold, .burn_percent = info->rent.burn_percent };
  fd_rpc_sim_begin( ctx->sim, info->slot, info->epoch, &ctx->features, &rent, &ctx->epoch_schedule );

  /* sysvars, as they are on the bank */
  fd_pubkey_t const * sysvars[] = {
    &fd_sysvar_clock_id, &fd_sysvar_epoch_schedule_id, &fd_sysvar_rent_id, &fd_sysvar_last_restart_slot_id,
    &fd_sysvar_recent_block_hashes_id, &fd_sysvar_slot_hashes_id, &fd_sysvar_slot_history_id,
    &fd_sysvar_stake_history_id, &fd_sysvar_epoch_rewards_id, &fd_sysvar_fees_id,
  };
  for( ulong i=0UL; i<sizeof(sysvars)/sizeof(sysvars[ 0 ]); i++ ) fd_rpc_sim_load( ctx, info, sysvars[ i ]->uc );
  fd_pubkey_t inflation = fd_epoch_inflation_account_address();
  fd_rpc_sim_load( ctx, info, inflation.uc );
  fd_rpc_sim_load( ctx, info, ctx->fd_genesis_cert_addr->uc );

  /* blockhash queue: the bank's own hash is newest, then the
     RecentBlockhashes sysvar, newest first */
  {
    ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
    fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, fd_sysvar_recent_block_hashes_id.uc, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
    ulong cnt = ( lamports && data_len>=8UL ) ? fd_ulong_min( FD_LOAD( ulong, ctx->scratch.accdb_data_buf ), (data_len-8UL)/40UL ) : 0UL;
    for( ulong i=cnt; i>0UL; i-- ) {
      uchar const * e = ctx->scratch.accdb_data_buf+8UL+40UL*(i-1UL);
      if( !memcmp( e, info->block_hash, 32UL ) ) continue;
      fd_rpc_sim_blockhash( ctx->sim, e, FD_LOAD( ulong, e+32UL ) );
    }
    fd_rpc_sim_blockhash( ctx->sim, info->block_hash, 5000UL );
  }

  /* the transaction's accounts, and what its lookup tables resolve to */
  for( ulong i=0UL; i<txn->acct_addr_cnt; i++ ) fd_rpc_sim_load( ctx, info, accts+32UL*i );
  fd_txn_acct_addr_lut_t const * luts = fd_txn_get_address_tables_const( txn );
  for( ulong i=0UL; i<txn->addr_table_lookup_cnt; i++ ) {
    uchar const * table = payload+luts[ i ].addr_off;
    if( !fd_rpc_sim_load( ctx, info, table ) ) continue;
    for( int pass=0; pass<2; pass++ ) {
      ulong         cnt  = pass ? luts[ i ].readonly_cnt : luts[ i ].writable_cnt;
      uchar const * idxs = payload + ( pass ? luts[ i ].readonly_off : luts[ i ].writable_off );
      for( ulong k=0UL; k<cnt; k++ ) {
        /* each load reuses the scratch buffer, so re-read the table */
        ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
        fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, table, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
        ulong off = 56UL+32UL*(ulong)idxs[ k ];
        if( FD_UNLIKELY( !lamports || off+32UL>data_len ) ) continue;
        uchar key[ 32 ]; memcpy( key, ctx->scratch.accdb_data_buf+off, 32UL );
        fd_rpc_sim_load( ctx, info, key );
      }
    }
  }

}

/* Agave's InstructionError variant for a runtime instruction error. */
static char const *
fd_rpc_instr_err_name( int err ) {
  switch( err ) {
    case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR:                        return "GenericError";
    case FD_EXECUTOR_INSTR_ERR_INVALID_ARG:                        return "InvalidArgument";
    case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA:                 return "InvalidInstructionData";
    case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA:                   return "InvalidAccountData";
    case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL:                 return "AccountDataTooSmall";
    case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS:                 return "InsufficientFunds";
    case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID:               return "IncorrectProgramId";
    case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE:         return "MissingRequiredSignature";
    case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED:            return "AccountAlreadyInitialized";
    case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT:              return "UninitializedAccount";
    case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR:                   return "UnbalancedInstruction";
    case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID:                return "ModifiedProgramId";
    case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND:     return "ExternalAccountLamportSpend";
    case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED:             return "ExternalAccountDataModified";
    case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE:            return "ReadonlyLamportChange";
    case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED:             return "ReadonlyDataModified";
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED:                return "ExecutableModified";
    case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS:                return "NotEnoughAccountKeys";
    case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED:              return "AccountDataSizeChanged";
    case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED:                  return "AccountBorrowFailed";
    case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING:             return "AccountBorrowOutstanding";
    case FD_EXECUTOR_INSTR_ERR_INVALID_ERR:                        return "InvalidError";
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT: return "ExecutableAccountNotRentExempt";
    case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID:             return "UnsupportedProgramId";
    case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH:                         return "CallDepth";
    case FD_EXECUTOR_INSTR_ERR_MISSING_ACC:                        return "MissingAccount";
    case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED:             return "ReentrancyNotAllowed";
    case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED:           return "MaxSeedLengthExceeded";
    case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS:                      return "InvalidSeeds";
    case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC:                    return "InvalidRealloc";
    case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED:            return "ComputationalBudgetExceeded";
    case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION:               return "PrivilegeEscalation";
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE:  return "ProgramEnvironmentSetupFailure";
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE:         return "ProgramFailedToComplete";
    case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE:                      return "Immutable";
    case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY:                return "IncorrectAuthority";
    case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR:                     return "BorshIoError";
    case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT:                return "AccountNotRentExempt";
    case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER:                  return "InvalidAccountOwner";
    case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW:                return "ArithmeticOverflow";
    case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR:                 return "UnsupportedSysvar";
    case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER:                      return "IllegalOwner";
    case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED:      return "MaxAccountsDataAllocationsExceeded";
    case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED:                  return "MaxAccountsExceeded";
    case FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED:       return "MaxInstructionTraceLengthExceeded";
    case FD_EXECUTOR_INSTR_ERR_BUILTINS_MUST_CONSUME_CUS:          return "BuiltinProgramsMustConsumeComputeUnits";
    default:                                                       return "ProgramFailedToComplete";
  }
}

static void
fd_rpc_print_sim_err( fd_rpc_tile_t *             ctx,
                      fd_rpc_sim_result_t const * r ) {
  if( !r->txn_err ) { fd_http_server_printf( ctx->http, "null" ); return; }
  fd_rpc_print_exec_err( ctx, r->txn_err, r->exec_err, r->exec_err_kind, r->exec_err_idx, r->custom_err );
}

static void
fd_rpc_print_exec_err( fd_rpc_tile_t * ctx,
                       int             txn_err,
                       int             exec_err,
                       int             exec_err_kind,
                       uint            exec_err_idx,
                       uint            custom_err ) {
  if( txn_err!=FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) { fd_rpc_print_txn_err( ctx, txn_err ); return; }
  if( exec_err_kind==FD_EXECUTOR_ERR_KIND_INSTR && exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
    fd_http_server_printf( ctx->http, "{\"InstructionError\":[%u,{\"Custom\":%u}]}", exec_err_idx, custom_err );
  } else {
    /* a VM or syscall fault surfaces as ProgramFailedToComplete */
    char const * name = exec_err_kind==FD_EXECUTOR_ERR_KIND_INSTR ? fd_rpc_instr_err_name( exec_err ) : "ProgramFailedToComplete";
    fd_http_server_printf( ctx->http, "{\"InstructionError\":[%u,\"%s\"]}", exec_err_idx, name );
  }
}

static fd_http_server_response_t
simulateTransaction( fd_rpc_tile_t *         ctx,
                     char const *            id_cstr,
                     fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 1, 2, &response ) ) ) return response;
  fd_rpc_val_t const * t      = &params->v[ 0 ];
  fd_rpc_val_t const * config = &params->v[ 1 ];
  if( FD_UNLIKELY( t->kind!=FD_RPC_VAL_STR ) ) return fd_rpc_err_invalid( ctx, id_cstr, "type", t, "a string" );
  if( FD_UNLIKELY( !ctx->sim || !ctx->has_features || !ctx->has_epoch_schedule ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: transaction simulator unavailable" );
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, config, &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];

  fd_rpc_val_t v[1];
  char enc[ 16 ] = "base58";
  if( fd_rpc_cfg_member( config, "encoding", v ) && v->kind==FD_RPC_VAL_STR ) fd_rpc_val_cstr( v, enc, sizeof(enc) );
  int sig_verify      = fd_rpc_cfg_member( config, "sigVerify",              v ) && v->kind==FD_RPC_VAL_BOOL && v->raw_sz==4UL;
  int replace_bh      = fd_rpc_cfg_member( config, "replaceRecentBlockhash", v ) && v->kind==FD_RPC_VAL_BOOL && v->raw_sz==4UL;
  int want_inner      = fd_rpc_cfg_member( config, "innerInstructions",      v ) && v->kind==FD_RPC_VAL_BOOL && v->raw_sz==4UL;
  if( FD_UNLIKELY( sig_verify && replace_bh ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "sigVerify may not be used with replaceRecentBlockhash" );

  static char  txt[ 2UL*FD_TXN_MTU_V0 ];
  static uchar payload[ 2UL*FD_TXN_MTU_V0 ];
  if( FD_UNLIKELY( !fd_rpc_val_cstr( t, txt, sizeof(txt) ) ) ) return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: transaction too large." );
  ulong txt_len = strlen( txt );
  ulong payload_sz;
  if( !strcmp( enc, "base64" ) ) {
    long dec = (ulong)FD_BASE64_DEC_SZ( txt_len )<=sizeof(payload) ? fd_base64_decode( payload, txt, txt_len ) : -1L;
    payload_sz = dec<0L ? ULONG_MAX : (ulong)dec;
  } else if( !strcmp( enc, "base58" ) ) {
    payload_sz = fd_rpc_base58_decode( txt, txt_len, payload, sizeof(payload) );
  } else {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: unsupported encoding, expected base58 or base64." );
  }
  uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  if( FD_UNLIKELY( payload_sz==ULONG_MAX || payload_sz>FD_TXN_MTU_V0 || !fd_txn_parse( payload, payload_sz, txn_buf, NULL ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32602, "Invalid params: failed to deserialize transaction." );
  }
  fd_txn_t const * txn   = (fd_txn_t const *)txn_buf;
  uchar const *    accts = payload+txn->acct_addr_off;

  if( sig_verify ) {
    uchar const * msg    = payload+txn->message_off;
    ulong         msg_sz = fd_txn_msg_sz( txn, payload_sz );
    for( ulong i=0UL; i<txn->signature_cnt; i++ ) {
      if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( msg, msg_sz, payload+txn->signature_off+64UL*i, accts+32UL*i, ctx->sha ) ) ) {
        return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":{\"accounts\":null,\"err\":\"SignatureFailure\",\"fee\":null,\"innerInstructions\":null,\"loadedAccountsDataSize\":0,\"loadedAddresses\":{\"readonly\":[],\"writable\":[]},\"logs\":[],\"postBalances\":null,\"postTokenBalances\":null,\"preBalances\":null,\"preTokenBalances\":null,\"replacementBlockhash\":null,\"returnData\":null,\"unitsConsumed\":0}},\"id\":%s}\n", FD_RPC_AGAVE_API_VERSION, info->slot, id_cstr );
      }
    }
  }
  if( replace_bh ) memcpy( payload+txn->recent_blockhash_off, info->block_hash, 32UL );

  fd_rpc_sim_prepare( ctx, info, payload, txn );

  /* --- run it ------------------------------------------------------- */
  fd_rpc_sim_result_t r[1];
  if( FD_UNLIKELY( !fd_rpc_sim_exec( ctx->sim, payload, payload_sz, r ) ) ) {
    return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: the transaction could not be simulated" );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":{\"accounts\":", FD_RPC_AGAVE_API_VERSION, info->slot );

  /* requested post-simulation accounts */
  fd_rpc_val_t accounts_cfg[1], addrs[1];
  int failed = 0; fd_http_server_response_t err_response;
  if( fd_rpc_cfg_member( config, "accounts", accounts_cfg ) && accounts_cfg->kind==FD_RPC_VAL_MAP &&
      fd_rpc_cfg_member( accounts_cfg, "addresses", addrs ) && addrs->kind==FD_RPC_VAL_SEQ ) {
    {
      fd_jtok_t jc[1]; ulong addr_cnt = 0UL;
      fd_jtok_arr_enter( fd_jtok_init( jc, addrs->raw, addrs->raw_sz ) );
      while( fd_jtok_arr_next( jc ) ) { fd_rpc_val_t a[1]; fd_rpc_val_read( jc, a ); addr_cnt++; }
      if( FD_UNLIKELY( addr_cnt>txn->acct_addr_cnt+(ulong)txn->addr_table_adtl_cnt ) ) {
        fd_http_server_unstage( ctx->http );
        fd_rpc_sim_end( ctx->sim );
        return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Too many accounts provided; max %lu\"},\"id\":%s}\n", txn->acct_addr_cnt+(ulong)txn->addr_table_adtl_cnt, id_cstr );
      }
    }
    fd_http_server_printf( ctx->http, "[" );
    fd_jtok_t j[1];
    ulong n = 0UL;
    fd_jtok_arr_enter( fd_jtok_init( j, addrs->raw, addrs->raw_sz ) );
    while( fd_jtok_arr_next( j ) ) {
      fd_rpc_val_t a[1]; fd_rpc_val_read( j, a );
      char  key_cstr[ 64 ]; uchar key[ 32 ];
      if( n++ ) fd_http_server_printf( ctx->http, "," );
      if( FD_UNLIKELY( !fd_rpc_val_cstr( a, key_cstr, sizeof(key_cstr) ) || !fd_base58_decode_32( key_cstr, key ) ) ) { fd_http_server_printf( ctx->http, "null" ); continue; }
      int found = 0;
      for( ulong i=0UL; !r->txn_err && i<r->acct_cnt && !found; i++ ) {
        uchar const * pk; ulong lamports; uchar const * owner; int executable; uchar const * data; ulong data_len; ulong pre;
        if( !fd_rpc_sim_account( ctx->sim, i, &pk, &lamports, &owner, &executable, &data, &data_len, &pre ) || memcmp( pk, key, 32UL ) ) continue;
        found = 1;
        if( !lamports ) { fd_http_server_printf( ctx->http, "null" ); break; }
        if( FD_UNLIKELY( !fd_rpc_encode_account_data( ctx, data, data_len, owner, lamports, executable, "base64", 0UL, ULONG_MAX, id_cstr, &err_response ) ) ) failed = 1;
      }
      if( failed ) break;
      if( !found && r->txn_err ) {
        fd_http_server_printf( ctx->http, "null" ); /* Agave reports no accounts for a failed simulation */
      } else if( !found ) {
        /* not changed by the simulation: the account as it is on the bank */
        ulong lamports; int executable; uchar owner[ 32UL ]; ulong data_len;
        fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, key, &lamports, &executable, owner, ctx->scratch.accdb_data_buf, &data_len );
        if( !lamports ) fd_http_server_printf( ctx->http, "null" );
        else if( FD_UNLIKELY( !fd_rpc_encode_account_data( ctx, ctx->scratch.accdb_data_buf, data_len, owner, lamports, executable, "base64", 0UL, ULONG_MAX, id_cstr, &err_response ) ) ) { failed = 1; break; }
      }
    }
    if( !failed ) fd_http_server_printf( ctx->http, "]" );
  } else {
    fd_http_server_printf( ctx->http, "null" );
  }
  if( FD_UNLIKELY( failed ) ) { fd_rpc_sim_end( ctx->sim ); return err_response; }

  fd_http_server_printf( ctx->http, ",\"err\":" );
  fd_rpc_print_sim_err( ctx, r );
  if( r->fee_charged ) fd_http_server_printf( ctx->http, ",\"fee\":%lu", r->fee );
  else                 fd_http_server_printf( ctx->http, ",\"fee\":null" );
  if( !want_inner ) {
    fd_http_server_printf( ctx->http, ",\"innerInstructions\":null" );
  } else {
    /* The runtime's trace lists every instruction in execution order.
       Stack height 1 is a top level instruction; whatever follows it
       at a greater height was invoked from it. */
    fd_http_server_printf( ctx->http, ",\"innerInstructions\":[" );
    ulong top = ULONG_MAX, groups = 0UL; int open = 0;
    for( ulong i=0UL; ; i++ ) {
      fd_instr_info_t const * ix = fd_rpc_sim_trace( ctx->sim, i );
      if( !ix ) break;
      if( ix->stack_height<=1 ) { top = top==ULONG_MAX ? 0UL : top+1UL; if( open ) { fd_http_server_printf( ctx->http, "]}" ); open = 0; } continue; }
      if( !open ) { fd_http_server_printf( ctx->http, "%s{\"index\":%lu,\"instructions\":[", groups++ ? "," : "", top ); open = 1; }
      else          fd_http_server_printf( ctx->http, "," );
      fd_http_server_printf( ctx->http, "{\"accounts\":[" );
      for( ulong k=0UL; k<ix->acct_cnt; k++ ) fd_http_server_printf( ctx->http, "%s%u", k ? "," : "", (uint)ix->accounts[ k ].index_in_transaction );
      fd_http_server_printf( ctx->http, "],\"data\":\"" );
      fd_rpc_print_base58( ctx, ix->data, fd_ulong_min( ix->data_sz, FD_TXN_MTU_V0 ) );
      fd_http_server_printf( ctx->http, "\",\"programIdIndex\":%u,\"stackHeight\":%u}", (uint)ix->program_id, (uint)ix->stack_height );
    }
    if( open ) fd_http_server_printf( ctx->http, "]}" );
    fd_http_server_printf( ctx->http, "]" );
  }
  fd_http_server_printf( ctx->http, ",\"loadedAccountsDataSize\":%lu,\"loadedAddresses\":{\"readonly\":[", r->loaded_accounts_data_size );
  /* accounts past the static ones were loaded from lookup tables:
     writable first, then read-only */
  {
    ulong wr_end = (ulong)txn->acct_addr_cnt+(ulong)txn->addr_table_adtl_writable_cnt;
    for( int pass=0; pass<2; pass++ ) { /* 0 readonly, 1 writable */
      ulong printed = 0UL;
      for( ulong i=txn->acct_addr_cnt; i<r->acct_cnt; i++ ) {
        if( (i<wr_end)!=pass ) continue;
        uchar const * pk; ulong lamports; uchar const * owner; int executable; uchar const * data; ulong data_len; ulong pre;
        if( !fd_rpc_sim_account( ctx->sim, i, &pk, &lamports, &owner, &executable, &data, &data_len, &pre ) ) continue;
        FD_BASE58_ENCODE_32_BYTES( pk, pk_b58 );
        fd_http_server_printf( ctx->http, "%s\"%s\"", printed++ ? "," : "", pk_b58 );
      }
      if( !pass ) fd_http_server_printf( ctx->http, "],\"writable\":[" );
    }
  }
  fd_http_server_printf( ctx->http, "]},\"logs\":[" );
  /* log collector: [tag][len, 1 or 2 bytes][text] per message */
  ulong off = 0UL, logs = 0UL;
  while( off+2UL<=r->log_buf_sz ) {
    ulong len = (ulong)( r->log_buf[ off+1UL ] & 0x7F );
    ulong hdr = 2UL;
    if( r->log_buf[ off+1UL ] & 0x80 ) { if( off+3UL>r->log_buf_sz ) break; len |= (ulong)r->log_buf[ off+2UL ]<<7; hdr = 3UL; }
    if( off+hdr+len>r->log_buf_sz ) break;
    fd_http_server_printf( ctx->http, "%s\"", logs++ ? "," : "" );
    fd_rpc_print_json_text( ctx, r->log_buf+off+hdr, len );
    fd_http_server_printf( ctx->http, "\"" );
    off += hdr+len;
  }
  /* Balances before and after.  "Before" is the live bank.  A failed
     transaction changes nothing but the fee payer's balance, and that
     only if it gets as far as being charged the fee. */
  ulong key_cnt = fd_ulong_max( r->acct_cnt, (ulong)txn->acct_addr_cnt );
  static uchar sim_keys[ MAX_TX_ACCOUNT_LOCKS+FD_TXN_ACCT_ADDR_MAX ][ 32 ];
  key_cnt = fd_ulong_min( key_cnt, sizeof(sim_keys)/32UL );
  for( ulong i=0UL; i<key_cnt; i++ ) {
    uchar const * pk; ulong lamports; uchar const * owner; int executable; uchar const * data; ulong data_len; ulong pre;
    if( i<txn->acct_addr_cnt ) memcpy( sim_keys[ i ], accts+32UL*i, 32UL );
    else if( fd_rpc_sim_account( ctx->sim, i, &pk, &lamports, &owner, &executable, &data, &data_len, &pre ) ) memcpy( sim_keys[ i ], pk, 32UL );
    else memset( sim_keys[ i ], 0, 32UL );
  }
  for( int pass=0; pass<2; pass++ ) { /* 0 post, 1 pre */
    fd_http_server_printf( ctx->http, pass ? "],\"preBalances\":[" : "],\"postBalances\":[" );
    for( ulong i=0UL; i<key_cnt; i++ ) {
      ulong bal = fd_accdb_lamports( ctx->accdb, info->accdb_fork_id, sim_keys[ i ] );
      if( !pass ) {
        uchar const * pk; ulong lamports; uchar const * owner; int executable; uchar const * data; ulong data_len; ulong pre;
        if( !r->txn_err && fd_rpc_sim_account( ctx->sim, i, &pk, &lamports, &owner, &executable, &data, &data_len, &pre ) ) bal = lamports;
        else if( r->txn_err && !i && r->fee_charged ) bal = fd_ulong_sat_sub( bal, r->fee );
      }
      fd_http_server_printf( ctx->http, "%s%lu", i ? "," : "", bal );
    }
    /* token balances: every SPL token account among the transaction's
       accounts, as it is before (live) and after (simulated, or
       unchanged if the transaction failed) */
    fd_http_server_printf( ctx->http, pass ? "],\"preTokenBalances\":[" : "],\"postTokenBalances\":[" );
    ulong printed = 0UL;
    for( ulong i=0UL; i<key_cnt; i++ ) {
      uchar tok[ 165 ]; uchar tok_owner_prog[ 32 ]; int have = 0;
      uchar const * pk; ulong lamports; uchar const * owner; int executable; uchar const * data; ulong data_len; ulong pre;
      if( !pass && !r->txn_err && fd_rpc_sim_account( ctx->sim, i, &pk, &lamports, &owner, &executable, &data, &data_len, &pre ) ) {
        if( lamports && data_len>=165UL && fd_rpc_owner_is_token_program( owner ) ) { memcpy( tok, data, 165UL ); memcpy( tok_owner_prog, owner, 32UL ); have = 1; }
      } else {
        ulong l; int e; uchar o[ 32UL ]; ulong dl;
        fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, sim_keys[ i ], &l, &e, o, ctx->scratch.accdb_data_buf, &dl );
        if( l && dl>=165UL && fd_rpc_owner_is_token_program( o ) ) { memcpy( tok, ctx->scratch.accdb_data_buf, 165UL ); memcpy( tok_owner_prog, o, 32UL ); have = 1; }
      }
      if( !have || tok[ 108 ]==0 ) continue; /* not a token account, or uninitialized */
      ulong ml; int me; uchar mo[ 32UL ]; ulong mdl;
      fd_accdb_read_one_nocache( ctx->accdb, info->accdb_fork_id, tok, &ml, &me, mo, ctx->scratch.accdb_data_buf, &mdl );
      if( FD_UNLIKELY( !ml || mdl<82UL ) ) continue;
      uchar decimals = ctx->scratch.accdb_data_buf[ 44 ];
      FD_BASE58_ENCODE_32_BYTES( tok,            mint_b58 );
      FD_BASE58_ENCODE_32_BYTES( tok+32UL,       tok_owner_b58 );
      FD_BASE58_ENCODE_32_BYTES( tok_owner_prog, prog_b58 );
      fd_http_server_printf( ctx->http, "%s{\"accountIndex\":%lu,\"mint\":\"%s\",\"owner\":\"%s\",\"programId\":\"%s\",\"uiTokenAmount\":", printed++ ? "," : "", i, mint_b58, tok_owner_b58, prog_b58 );
      fd_rpc_print_ui_amount( ctx, FD_LOAD( ulong, tok+64UL ), decimals );
      fd_http_server_printf( ctx->http, "}" );
    }
  }
  fd_http_server_printf( ctx->http, "],\"replacementBlockhash\":" );
  if( replace_bh ) {
    FD_BASE58_ENCODE_32_BYTES( info->block_hash, bh_b58 );
    fd_http_server_printf( ctx->http, "{\"blockhash\":\"%s\",\"lastValidBlockHeight\":%lu}", bh_b58, info->block_height+150UL );
  } else {
    fd_http_server_printf( ctx->http, "null" );
  }
  fd_http_server_printf( ctx->http, ",\"returnData\":" );
  if( r->return_data_len ) {
    static char b64[ FD_BASE64_ENC_SZ( 1024UL )+1UL ];
    ulong n = fd_base64_encode( b64, r->return_data, fd_ulong_min( r->return_data_len, 1024UL ) );
    FD_BASE58_ENCODE_32_BYTES( r->return_program, prog_b58 );
    fd_http_server_printf( ctx->http, "{\"data\":[\"%.*s\",\"base64\"],\"programId\":\"%s\"}", (int)n, b64, prog_b58 );
  } else {
    fd_http_server_printf( ctx->http, "null" );
  }
  fd_http_server_printf( ctx->http, ",\"unitsConsumed\":%lu}},\"id\":%s}\n", r->units_consumed, id_cstr );
  fd_rpc_sim_end( ctx->sim );
  return STAGE_JSON( ctx );
}

/* The minimum delegation is decided by the stake program deployed on
   the cluster (a BPF program since the core-BPF migration), not by a
   feature gate.  So ask the program: simulate its GetMinimumDelegation
   instruction, paid for by a made-up account that exists only in the
   simulator, and read the answer from the return data. */
static fd_http_server_response_t
getStakeMinimumDelegation( fd_rpc_tile_t *         ctx,
                           char const *            id_cstr,
                           fd_rpc_params_t const * params ) {
  fd_http_server_response_t response;
  if( FD_UNLIKELY( !fd_rpc_validate_params( ctx, id_cstr, params, 0, 1, &response ) ) ) return response;
  ulong bank_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_rpc_cfg_bank( ctx, id_cstr, &params->v[ 0 ], &bank_idx, &response ) ) ) return response;
  bank_info_t const * info = &ctx->banks[ bank_idx ];
  if( FD_UNLIKELY( !ctx->sim || !ctx->has_features || !ctx->has_epoch_schedule ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: transaction simulator unavailable" );

  /* legacy transaction: [1 sig][header 1,0,1][2 keys][blockhash][1 instruction: program 1, no accounts, data u32 13] */
  uchar payer[ 32 ]; memset( payer, 0x5a, 32UL );
  uchar payload[ 1UL+64UL+3UL+1UL+64UL+32UL+1UL+1UL+1UL+1UL+4UL ];
  uchar * p = payload;
  *p++ = 1; memset( p, 0, 64UL ); p += 64UL;
  *p++ = 1; *p++ = 0; *p++ = 1; *p++ = 2;
  memcpy( p, payer, 32UL ); p += 32UL;
  memcpy( p, fd_solana_stake_program_id.uc, 32UL ); p += 32UL;
  memcpy( p, info->block_hash, 32UL ); p += 32UL;
  *p++ = 1; *p++ = 1; *p++ = 0; *p++ = 4;
  FD_STORE( uint, p, 13U ); p += 4UL;
  ulong payload_sz = (ulong)( p-payload );
  uchar txn_buf[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  FD_TEST( fd_txn_parse( payload, payload_sz, txn_buf, NULL ) );

  fd_rpc_sim_prepare( ctx, info, payload, (fd_txn_t const *)txn_buf );
  fd_rpc_sim_put( ctx->sim, payer, 1000000000UL, fd_solana_system_program_id.uc, 0, NULL, 0UL );
  fd_rpc_sim_result_t r[1];
  int   ran   = fd_rpc_sim_exec( ctx->sim, payload, payload_sz, r );
  int   ok    = ran && !r->txn_err && r->return_data_len==8UL && !memcmp( r->return_program, fd_solana_stake_program_id.uc, 32UL );
  ulong value = ok ? FD_LOAD( ulong, r->return_data ) : 0UL;
  if( ran ) fd_rpc_sim_end( ctx->sim );
  if( FD_UNLIKELY( !ok ) ) return fd_rpc_err_msg( ctx, id_cstr, -32065, "Firedancer Error: the stake program did not report a minimum delegation" );
  return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"%s\",\"slot\":%lu},\"value\":%lu},\"id\":%s}\n", FD_RPC_AGAVE_API_VERSION, info->slot, value, id_cstr );
}

static fd_http_server_response_t
rpc_json_request( fd_rpc_tile_t * ctx,
                  uchar const *   body,
                  ulong           body_len,
                  ulong           ws_conn_id );

static fd_http_server_response_t
rpc_http_request1( fd_rpc_tile_t *                  ctx,
                   fd_http_server_request_t const * request ) {
  if( FD_UNLIKELY( request->method==FD_HTTP_SERVER_METHOD_GET &&
                   request->headers.upgrade_websocket &&
                   (!strcmp( request->path, "/" ) || !strcmp( request->path, "/websocket" )) ) ) {
    if( FD_UNLIKELY( !ctx->http->max_ws_conns ) ) return (fd_http_server_response_t){ .status = 404 };
    return (fd_http_server_response_t){
      .status            = 200,
      .upgrade_websocket = 1,
    };
  }

  if( FD_UNLIKELY( ( request->method==FD_HTTP_SERVER_METHOD_GET || request->method==FD_HTTP_SERVER_METHOD_HEAD ) && !strcmp( request->path, "/health" ) ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_HEALTH, 1UL );
    int health_status = _getHealth( ctx );

    switch( health_status ) {
      case FD_RPC_HEALTH_STATUS_UNKNOWN: return PRINTF_JSON( ctx, "unknown" );
      case FD_RPC_HEALTH_STATUS_BEHIND:  return PRINTF_JSON( ctx, "behind" );
      case FD_RPC_HEALTH_STATUS_OK:      return PRINTF_JSON( ctx, "ok" );
      default: FD_LOG_ERR(( "unknown health status" ));
    }
  }

  if( FD_UNLIKELY( ( request->method==FD_HTTP_SERVER_METHOD_GET || request->method==FD_HTTP_SERVER_METHOD_HEAD ) && !strcmp( request->path, "/genesis.tar.bz2" ) ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_GENESIS, 1UL );
    if( FD_UNLIKELY( ctx->genesis_tar_bz_sz==ULONG_MAX ) ) return (fd_http_server_response_t){ .status = 404 };

    return (fd_http_server_response_t) {
      .status          = 200,
      .static_body     = ctx->genesis_tar_bz,
      .static_body_len = ctx->genesis_tar_bz_sz,
    };
  }

  if( FD_UNLIKELY( ( request->method==FD_HTTP_SERVER_METHOD_GET || request->method==FD_HTTP_SERVER_METHOD_HEAD ) &&
                   ( !strncmp( request->path, "/snapshot",             9UL ) ||
                     !strncmp( request->path, "/incremental-snapshot", 21UL ) ) ) ) {
    if( FD_UNLIKELY( !ctx->snapshot_server_enabled ) ) {
      return (fd_http_server_response_t){ .status = 403 }; /* forbidden */
    }
    return (fd_http_server_response_t){
      .status       = 302,
      .location     = { ctx->snapshot_server_url, request->path_raw },
      .location_len = { strlen( ctx->snapshot_server_url ), request->path_len },
    };
  }


  if( FD_UNLIKELY( request->method==FD_HTTP_SERVER_METHOD_GET || request->method==FD_HTTP_SERVER_METHOD_HEAD ) ) {
    return (fd_http_server_response_t){ .status = 404 };
  }

  if( FD_UNLIKELY( request->method!=FD_HTTP_SERVER_METHOD_POST ) ) {
    return (fd_http_server_response_t){ .status = 405 };
  }

  return rpc_json_request( ctx, request->post.body, request->post.body_len, ULONG_MAX );
}

static fd_http_server_response_t
rpc_json_request( fd_rpc_tile_t * ctx,
                  uchar const *   body,
                  ulong           body_len,
                  ulong           ws_conn_id ) { /* ULONG_MAX implies HTTP */
  fd_jtok_t j[1];
  fd_jtok_init( j, body, body_len );
  int kind = fd_jtok_peek( j );

  if( FD_UNLIKELY( kind==FD_JTOK_ARR ) ) {
    /* A bug in Agave ¯\_(ツ)_/¯ */
    fd_jtok_arr_enter( j );
    if( FD_LIKELY( !fd_jtok_arr_next( j ) && !fd_jtok_fini( j ) ) ) return (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n" );
  }

  if( FD_UNLIKELY( kind!=FD_JTOK_OBJ ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n" );
  }

  /* For duplicate members the first occurrence wins, later ones are
     skipped. */
  fd_rpc_val_t id     [1] = {{ .kind = FD_RPC_VAL_NONE }};
  fd_rpc_val_t jsonrpc[1] = {{ .kind = FD_RPC_VAL_NONE }};
  fd_rpc_val_t _method[1] = {{ .kind = FD_RPC_VAL_NONE }};
  fd_rpc_val_t _params[1] = {{ .kind = FD_RPC_VAL_NONE }};
  int unknown_member = 0;

  fd_jtok_str_t key;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    fd_rpc_val_t * member;
    if(      fd_jtok_str_eq( &key, "jsonrpc" ) ) member = jsonrpc;
    else if( fd_jtok_str_eq( &key, "id"      ) ) member = id;
    else if( fd_jtok_str_eq( &key, "method"  ) ) member = _method;
    else if( fd_jtok_str_eq( &key, "params"  ) ) member = _params;
    else { unknown_member = 1; continue; }
    if( member->kind==FD_RPC_VAL_NONE ) fd_rpc_val_read( j, member );
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n" );
  }

  /* Echo the id back verbatim. */
  char id_buf[ FD_RPC_ID_MAX_SZ+1UL ];
  char const * id_cstr = "null";
  if( id->kind!=FD_RPC_VAL_NONE ) {
    if( FD_UNLIKELY( id->raw_sz>FD_RPC_ID_MAX_SZ ) ) {
      FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n" );
    }
    fd_memcpy( id_buf, id->raw, id->raw_sz );
    id_buf[ id->raw_sz ] = '\0';
    id_cstr = id_buf;
  }

  if( FD_UNLIKELY( unknown_member ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
  }

  if( FD_UNLIKELY( _method->kind!=FD_RPC_VAL_NONE && id->kind==FD_RPC_VAL_NONE ) ) {
    /* A bug in Agave ¯\_(ツ)_/¯ */
    return (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
  }

  if( FD_UNLIKELY( jsonrpc->kind==FD_RPC_VAL_NONE && _method->kind!=FD_RPC_VAL_NONE ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"error\":{\"code\":-32600,\"message\":\"Unsupported JSON-RPC protocol version\"},\"id\":%s}\n", id_cstr );
  }

  if( FD_UNLIKELY( jsonrpc->kind==FD_RPC_VAL_NONE || _method->kind==FD_RPC_VAL_NONE ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
  }

  if( FD_UNLIKELY( !(id->kind==FD_RPC_VAL_INT && !id->neg) && id->kind!=FD_RPC_VAL_STR && id->kind!=FD_RPC_VAL_NULL ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n" );
  }

  if( FD_UNLIKELY( jsonrpc->kind==FD_RPC_VAL_NULL ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"error\":{\"code\":-32600,\"message\":\"Unsupported JSON-RPC protocol version\"},\"id\":%s}\n", id_cstr );
  }

  if( FD_UNLIKELY( jsonrpc->kind!=FD_RPC_VAL_STR || !fd_jtok_str_eq( &jsonrpc->str, "2.0" ) ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
  }

  fd_http_server_response_t response;

  if( FD_UNLIKELY( _method->kind!=FD_RPC_VAL_STR ) ) {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_INVALID, 1UL );
    return PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid request\"},\"id\":%s}\n", id_cstr );
  }
  char method[ 64 ];
  fd_rpc_val_cstr( _method, method, sizeof(method) ); /* too long or undecodable is an unknown method */

  fd_rpc_params_t params[1];
  fd_rpc_params_read( _params, params );

  if( FD_LIKELY(      !strcmp( method, "getAccountInfo"                    ) ) ) response = getAccountInfo( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBalance"                        ) ) ) response = getBalance( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlock"                          ) ) ) response = getBlock( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlockCommitment"                ) ) ) response = getBlockCommitment( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlockHeight"                    ) ) ) response = getBlockHeight( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlockProduction"                ) ) ) response = getBlockProduction( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlocks"                         ) ) ) response = getBlocks( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlocksWithLimit"                ) ) ) response = getBlocksWithLimit( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getBlockTime"                      ) ) ) response = getBlockTime( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getClusterNodes"                   ) ) ) response = getClusterNodes( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getEpochInfo"                      ) ) ) response = getEpochInfo( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getEpochSchedule"                  ) ) ) response = getEpochSchedule( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getFeeForMessage"                  ) ) ) response = getFeeForMessage( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getFirstAvailableBlock"            ) ) ) response = getFirstAvailableBlock( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getGenesisHash"                    ) ) ) response = getGenesisHash( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getHealth"                         ) ) ) response = getHealth( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getHighestSnapshotSlot"            ) ) ) response = getHighestSnapshotSlot( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getIdentity"                       ) ) ) response = getIdentity( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getInflationGovernor"              ) ) ) response = getInflationGovernor( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getInflationRate"                  ) ) ) response = getInflationRate( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getInflationReward"                ) ) ) response = getInflationReward( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getLargestAccounts"                ) ) ) response = getLargestAccounts( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getLatestBlockhash"                ) ) ) response = getLatestBlockhash( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getLeaderSchedule"                 ) ) ) response = getLeaderSchedule( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getMaxRetransmitSlot"              ) ) ) response = getMaxRetransmitSlot( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getMaxShredInsertSlot"             ) ) ) response = getMaxShredInsertSlot( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getMinimumBalanceForRentExemption" ) ) ) response = getMinimumBalanceForRentExemption( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getMultipleAccounts"               ) ) ) response = getMultipleAccounts( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getProgramAccounts"                ) ) ) response = getProgramAccounts( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getRecentPerformanceSamples"       ) ) ) response = getRecentPerformanceSamples( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getRecentPrioritizationFees"       ) ) ) response = getRecentPrioritizationFees( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getSignaturesForAddress"           ) ) ) response = getSignaturesForAddress( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getSignatureStatuses"              ) ) ) response = getSignatureStatuses( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getSlot"                           ) ) ) response = getSlot( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getSlotLeader"                     ) ) ) response = getSlotLeader( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getSlotLeaders"                    ) ) ) response = getSlotLeaders( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getStakeMinimumDelegation"         ) ) ) response = getStakeMinimumDelegation( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getSupply"                         ) ) ) response = getSupply( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTokenAccountBalance"            ) ) ) response = getTokenAccountBalance( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTokenAccountsByDelegate"        ) ) ) response = getTokenAccountsByDelegate( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTokenAccountsByOwner"           ) ) ) response = getTokenAccountsByOwner( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTokenLargestAccounts"           ) ) ) response = getTokenLargestAccounts( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTokenSupply"                    ) ) ) response = getTokenSupply( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTransaction"                    ) ) ) response = getTransaction( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getTransactionCount"               ) ) ) response = getTransactionCount( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getVersion"                        ) ) ) response = getVersion( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getVoteAccounts"                   ) ) ) response = getVoteAccounts( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "slotSubscribe"                     ) ) ) response = slotSubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "slotUnsubscribe"                   ) ) ) response = slotUnsubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "signatureSubscribe"                ) ) ) response = signatureSubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "accountSubscribe"                  ) ) ) response = accountSubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "accountUnsubscribe"                ) ) ) response = slotUnsubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "signatureUnsubscribe"              ) ) ) response = slotUnsubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "voteSubscribe"                     ) ) ) response = voteSubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "voteUnsubscribe"                   ) ) ) response = voteUnsubscribe( ctx, id_cstr, params, ws_conn_id );
  else if( FD_LIKELY( !strcmp( method, "isBlockhashValid"                  ) ) ) response = isBlockhashValid( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "minimumLedgerSlot"                 ) ) ) response = minimumLedgerSlot( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "requestAirdrop"                    ) ) ) response = requestAirdrop( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "sendTransaction"                   ) ) ) response = sendTransaction( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "simulateTransaction"               ) ) ) response = simulateTransaction( ctx, id_cstr, params );
  else if( FD_LIKELY( !strcmp( method, "getAgGenesisCert"                  ) ) ) response = getAgGenesisCert( ctx, id_cstr, params );
  else {
    FD_MCNT_INC( RPC, REQUEST_HANDLED_UNKNOWN, 1UL );
    response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }

  /* Agave pubsub answers non-subscription methods with -32601 and
     keeps the socket; a bare 501 would close it and drop subscriptions */
  if( FD_UNLIKELY( ws_conn_id!=ULONG_MAX && response.status==501UL ) ) {
    response = PRINTF_JSON( ctx, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":%s}\n", id_cstr );
  }

  return response;
}

static fd_http_server_response_t
rpc_http_request( fd_http_server_request_t const * request ) {
  fd_rpc_tile_t * ctx = request->ctx;
  long dt = -fd_tickcount();
  fd_http_server_response_t response = rpc_http_request1( ctx, request );
  dt += fd_tickcount();
  fd_histf_sample( ctx->request_duration, (ulong)dt );
  return response;
}

static void
rpc_ws_open( ulong  ws_conn_id,
             void * ctx ) {
  (void)ws_conn_id; (void)ctx;
}

static void
rpc_ws_close( ulong  ws_conn_id,
              int    reason     FD_PARAM_UNUSED,
              void * _ctx ) {
  fd_rpc_tile_t * ctx = (fd_rpc_tile_t *)_ctx;
  if( FD_UNLIKELY( ws_conn_id>=ctx->http->max_ws_conns ) ) return;
  fd_rpc_ws_subscriber_vote_remove( ctx, ws_conn_id );
  fd_rpc_ws_subscriber_slot_remove( ctx, ws_conn_id );
  for( ulong i=0UL; i<FD_RPC_WS_SIG_SUB_MAX; i++ ) {
    if( ctx->ws_sig_subs[ i ].sub_id && ctx->ws_sig_subs[ i ].ws_conn_id==ws_conn_id ) { ctx->ws_sig_subs[ i ].sub_id = 0UL; ctx->ws_sig_sub_cnt--; }
  }
  for( ulong i=0UL; i<FD_RPC_WS_ACCT_SUB_MAX; i++ ) {
    if( ctx->ws_acct_subs[ i ].sub_id && ctx->ws_acct_subs[ i ].ws_conn_id==ws_conn_id ) { ctx->ws_acct_subs[ i ].sub_id = 0UL; ctx->ws_acct_sub_cnt--; }
  }
}

static void
rpc_ws_message( ulong         ws_conn_id,
                uchar const * data,
                ulong         data_len,
                void *        _ctx ) {
  fd_rpc_tile_t * ctx = (fd_rpc_tile_t *)_ctx;

  fd_http_server_unstage( ctx->http );

  long dt = -fd_tickcount();
  fd_http_server_response_t response = rpc_json_request( ctx, data, data_len, ws_conn_id );
  dt += fd_tickcount();
  fd_histf_sample( ctx->request_duration, (ulong)dt );

  /* fd_http_server_reserve may evict this connection while staging the response. */
  if( FD_UNLIKELY( ctx->http->pollfds[ ctx->http->max_conns+ws_conn_id ].fd==-1 ) ) return;

  if( FD_UNLIKELY( response.status!=200UL ) ) {
    fd_http_server_ws_close( ctx->http, ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
    return;
  }

  if( FD_LIKELY( response._body_len ) ) {
    ulong response_body_end = response._body_off + response._body_len;

    ctx->http->stage_off      = response._body_off;
    ctx->http->stage_len      = response._body_len;
    ctx->http->stage_comp_len = 0UL;

    int err = fd_http_server_ws_send( ctx->http, ws_conn_id );
    if( FD_UNLIKELY( ctx->http->stage_off<response_body_end ) ) ctx->http->stage_off = response_body_end;
    if( FD_UNLIKELY( err ) )
      fd_http_server_ws_close( ctx->http, ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_TOO_SLOW );
  }
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_params = derive_http_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );
  fd_http_server_t * _http = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( http_params ) );

  fd_memset( ctx, 0, sizeof(fd_rpc_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->rpc.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->rpc.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity_key, 32UL );

  fd_http_server_callbacks_t callbacks = {
    .request    = rpc_http_request,
    .ws_open    = rpc_ws_open,
    .ws_close   = rpc_ws_close,
    .ws_message = rpc_ws_message,
  };
  ctx->http = fd_http_server_join( fd_http_server_new( _http, http_params, callbacks, ctx ) );
  ctx->snapshot_server_enabled = tile->rpc.snapshot_server_enabled;
  if( FD_LIKELY( ctx->snapshot_server_enabled ) ) {
    uint ip_addr;
    if( FD_UNLIKELY( !fd_dns_resolve_address( tile->rpc.snapshot_server_host, &ip_addr ) ) )
      FD_LOG_ERR(( "failed to resolve [gossip.host] `%s`", tile->rpc.snapshot_server_host ));
    FD_TEST( fd_cstr_printf_check(
        ctx->snapshot_server_url, sizeof(ctx->snapshot_server_url), NULL,
        "http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( ip_addr ),
        tile->rpc.snapshot_server_port ) );
  }
  /* simulateTransaction runtime: memfds and anonymous memory, so also
     before the sandbox. */
  ctx->sim = fd_rpc_sim_boot();

  /* transaction logs: anonymous memory, paged in as it fills */
  ctx->meta_head = 0UL;
  ctx->meta_ring = mmap( NULL, FD_RPC_META_RING_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( ctx->meta_ring==MAP_FAILED ) ) { FD_LOG_WARNING(( "mmap failed (%i-%s), transaction logs disabled", errno, fd_io_strerror( errno ) )); ctx->meta_ring = NULL; }

  /* getInflationReward store: anonymous memory, paged in as it fills. */
  ctx->reward_seq_next  = ULONG_MAX;
  ctx->reward_dropped   = 0UL;
  ctx->reward_boot_slot = ULONG_MAX;
  for( ulong i=0UL; i<FD_RPC_REWARD_EPOCH_CNT; i++ ) {
    void * mem = mmap( NULL, FD_RPC_REWARD_ENT_CNT*sizeof(fd_rpc_reward_ent_t), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
    if( FD_UNLIKELY( mem==MAP_FAILED ) ) { FD_LOG_WARNING(( "mmap failed (%i-%s), getInflationReward disabled", errno, fd_io_strerror( errno ) )); mem = NULL; }
    ctx->reward_epochs[ i ].epoch      = ULONG_MAX;
    ctx->reward_epochs[ i ].slot_lo    = ULONG_MAX;
    ctx->reward_epochs[ i ].slot_hi    = 0UL;
    ctx->reward_epochs[ i ].cnt        = 0UL;
    ctx->reward_epochs[ i ].incomplete = 1;
    ctx->reward_epochs[ i ].ents       = mem;
  }

  /* sendTransaction socket.  Opened here, before the sandbox. */
  ctx->udp_fd = socket( AF_INET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( ctx->udp_fd<0 ) ) FD_LOG_WARNING(( "socket(AF_INET,SOCK_DGRAM) failed (%i-%s), sendTransaction will not send", errno, fd_io_strerror( errno ) ));

  ctx->waker_client_idx = tile->waker_client_idx;
  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
  fd_http_server_listen6( ctx->http, FD_WAKER_INNER_FD( ctx->waker_client_idx ), &tile->rpc.listen_addr, tile->rpc.listen_port );
  char listen_addr_cstr[ FD_IP6_ADDR_CSTR_MAX ]; fd_ip6_addr_cstr( listen_addr_cstr, &tile->rpc.listen_addr );
  FD_LOG_NOTICE(( "rpc server listening at %shttp://%s:%u%s", fd_log_style_bold(), listen_addr_cstr, tile->rpc.listen_port, fd_log_style_normal() ));
}

static inline fd_rpc_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_rpc_out_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0 };


  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_rpc_out_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX };

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_rpc_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_params = derive_http_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rpc_tile_t),            sizeof(fd_rpc_tile_t)                                              );
                           FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),            fd_http_server_footprint( http_params )                            );
  void * _bz2_alloc      = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),                  fd_alloc_footprint()                                               );
  void * _banks          = FD_SCRATCH_ALLOC_APPEND( l, alignof(bank_info_t),              tile->rpc.max_live_slots*sizeof(bank_info_t)                       );
  void * _nodes_dlist    = FD_SCRATCH_ALLOC_APPEND( l, fd_rpc_cluster_node_dlist_align(), fd_rpc_cluster_node_dlist_footprint()                              );
  void * _accdb_join     = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),                  fd_accdb_footprint( tile->rpc.max_live_slots, 0 )                     );
  void * _ws_sub_vote    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                    http_params.max_ws_connection_cnt*sizeof(ulong)                    );
  void * _ws_sub_slot    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                    http_params.max_ws_connection_cnt*sizeof(ulong)                    );
  void * _genesis_tar    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),                    fd_rpc_genesis_tar_max_sz( tile->rpc.genesis_max_message_size )    );
  void * _genesis_tar_bz = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),                    fd_rpc_genesis_tar_bz_max_sz( tile->rpc.genesis_max_message_size ) );
  ulong  zstd_wksp_sz = ZSTD_estimateCCtxSize( FD_RPC_ZSTD_LEVEL );
  void * _zstd_wksp   = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                     zstd_wksp_sz                                           );

  ctx->delay_startup       = tile->rpc.delay_startup;
  fd_alpenglow_pda( "carlgration", ctx->fd_genesis_cert_addr );
  ctx->waker_rearm_pending = 0;
  ctx->ws_subscribers_vote = _ws_sub_vote;
  ctx->ws_subscribers_vote_cnt = 0UL;
  ctx->ws_subscribers_slot = _ws_sub_slot;
  ctx->ws_subscribers_slot_cnt = 0UL;
  ctx->ws_sub_id_vote          = 0UL;
  ctx->ws_sub_id_slot          = 0UL;
  ctx->ws_sub_id_next          = 0UL;

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->bz2_alloc = fd_alloc_join( fd_alloc_new( _bz2_alloc, 1UL ), 1UL );
  FD_TEST( ctx->bz2_alloc );

  ctx->zstd_cctx = ZSTD_initStaticCCtx( _zstd_wksp, zstd_wksp_sz );
  FD_CHECK_ERR( ctx->zstd_cctx, "ZSTD_initStaticCCtx failed" );

  fd_clock_tile_init( ctx->clock );
  ctx->in_cnt          = tile->in_cnt;
  ctx->idle_cnt        = 0UL;

  FD_TEST( ctx->waker_client_idx!=ULONG_MAX );
  ctx->waker_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->waker_fseq_obj_id ) );
  FD_TEST( ctx->waker_fseq );

  ctx->cluster_confirmed_slot = ULONG_MAX;
  ctx->genesis_max_message_size = tile->rpc.genesis_max_message_size;
  ctx->genesis_tar_max_sz = fd_rpc_genesis_tar_max_sz( tile->rpc.genesis_max_message_size );
  ctx->genesis_tar_bz_max_sz = fd_rpc_genesis_tar_bz_max_sz( tile->rpc.genesis_max_message_size );
  ctx->genesis_tar = _genesis_tar;
  ctx->genesis_tar_bz = _genesis_tar_bz;
  ctx->genesis_tar_bz_sz = ULONG_MAX;

  ctx->processed_idx = ULONG_MAX;
  ctx->confirmed_idx = ULONG_MAX;
  ctx->finalized_idx = ULONG_MAX;

  ctx->cluster_nodes_dlist = fd_rpc_cluster_node_dlist_join( fd_rpc_cluster_node_dlist_new( _nodes_dlist ) );
  ctx->banks = _banks;
  ctx->max_live_slots = tile->rpc.max_live_slots;
  for( ulong i=0UL; i<ctx->max_live_slots; i++ ) ctx->banks[ i ].slot = ULONG_MAX;

  fd_rpc_mleaders_init( ctx->mleaders );
  ctx->prio_fee_cnt  = 0UL;
  ctx->snap_cnt      = 0UL;
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );
  memset( ctx->send_pending, 0, sizeof(ctx->send_pending) );
  ctx->send_datagram_cnt = 0UL;
  ctx->txn_rec_next  = 0UL;
  memset( ctx->txn_table, 0, sizeof(ctx->txn_table) );
  for( ulong i=0UL; i<FD_RPC_BLOCK_META_CNT; i++ ) ctx->block_metas[ i ].slot = ULONG_MAX;
  ctx->prio_fee_next = 0UL;
  ctx->ns_per_slot   = 0UL;
  ctx->has_epoch_schedule = 0;
  ctx->highest_replayed_slot    = 0UL;
  ctx->perf_sample_has_snapshot = 0;
  ctx->perf_sample_cnt          = 0UL;
  ctx->genesis_creation_time    = 0L;
  ctx->block_time_first_slot    = ULONG_MAX;
  ctx->block_time_newest_slot   = 0UL;
  for( ulong i=0UL; i<FD_RPC_BLOCK_TIME_MAX; i++ ) ctx->block_times[ i ].slot = ULONG_MAX;
  for( ulong i=0UL; i<FD_RPC_VOTE_SET_CNT; i++ ) ctx->vote_sets[ i ].epoch = ULONG_MAX;

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in_mcache[ i ] = link->mcache;
    ctx->in_depth [ i ] = fd_mcache_depth( link->mcache );

    if     ( FD_LIKELY( !strcmp( link->name, "replay_slot"  ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI;
    else if( FD_LIKELY( !strcmp( link->name, "gossip_ciaddr" ) ) ) ctx->in_kind[ i ] = IN_KIND_GOSSIP_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_UNLIKELY( !strcmp( link->name, "votor_out"  ) ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY_TXN;
    else if( FD_LIKELY( !strcmp( link->name, "snapmk_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SNAPMK;
    else if( FD_LIKELY( !strcmp( link->name, "execrp_rpc"   ) ) ) ctx->in_kind[ i ] = IN_KIND_EXECRP_META;
    else FD_LOG_ERR(( "unexpected link name %s", link->name ));
  }

  for( ctx->shred_rtx_cnt=0UL; ctx->shred_rtx_cnt<FD_TOPO_MAX_TILES; ctx->shred_rtx_cnt++ ) {
    ulong rtx_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "shred_rtx.%lu", ctx->shred_rtx_cnt );
    if( FD_UNLIKELY( rtx_obj_id==ULONG_MAX ) ) break;
    ctx->shred_rtx[ ctx->shred_rtx_cnt ] = fd_fseq_join( fd_topo_obj_laddr( topo, rtx_obj_id ) );
    FD_TEST( ctx->shred_rtx[ ctx->shred_rtx_cnt ] );
  }

  *ctx->replay_out = out1( topo, tile, "rpc_replay" ); FD_TEST( ctx->replay_out->idx!=ULONG_MAX );

  /* Read-only join to accdb.  The accdb workspace is mapped
     PROT_READ in this tile (see topology); the only writable
     external mapping is our private epoch fseq.  fd FD_ACCDB_FD_RO is
     the O_RDONLY dup of the accdb data file. */
  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->rpc.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem_ro = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem_ro );
  ulong * epoch_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, tile->rpc.accdb_epoch_fseq_obj_id ) );
  FD_TEST( epoch_fseq );
  ctx->accdb = fd_accdb_join_readonly( _accdb_join, accdb_shmem_ro, epoch_fseq, FD_ACCDB_FD_RO );
  FD_TEST( ctx->accdb );

  fd_histf_join( fd_metrics_histf_new_ns( ctx->request_duration, FD_MHIST_EDGES_NS( RPC, REQUEST_DURATION_NANOS ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );

  uint epoll_inner_fd = (uint)FD_WAKER_INNER_FD( tile->waker_client_idx );
  uint epoll_outer_fd = (uint)FD_WAKER_OUTER_FD;

  populate_sock_filter_policy_fd_rpc_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->http ), (uint)FD_ACCDB_FD_RO, epoll_inner_fd, epoll_outer_fd );
  return sock_filter_policy_fd_rpc_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );

  if( FD_UNLIKELY( out_fds_cnt<12UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->http ); /* rpc listen socket */
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RO; /* accounts db readonly fd */
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD;
  out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( tile->waker_client_idx );
  if( FD_LIKELY( ctx->udp_fd>=0 ) ) out_fds[ out_cnt++ ] = ctx->udp_fd; /* sendTransaction socket */
  out_cnt += fd_rpc_sim_fds( ctx->sim, out_fds+out_cnt, out_fds_cnt-out_cnt ); /* simulateTransaction memfds */

  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  ulong base = 5UL;
  return base + tile->rpc.max_http_connections + tile->rpc.max_websocket_connections;
}

#define STEM_BURST (3UL)

/* The default STEM_LAZY is based on cr_max, which is the minimum depth
   across all output links that have at least one reliable consumer.
   RPC has one tiny output link used to release banks, with a
   significantly slower line rate than assumed in the formula for the
   default STEM_LAZY value.

   Instead, lazy just needs to be frequent enough to relinquish credits
   to upstream producers faster than they are exhausted. 384us is a
   reasonable default used in many other non-critical tiles. */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rpc_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rpc_tile_t)

#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

#ifndef FD_TILE_TEST
fd_topo_run_tile_t fd_tile_rpc = {
  .name                     = "rpc",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
#endif
