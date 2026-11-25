#define _GNU_SOURCE
#include "fd_rpc_sim.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_blockhashes.h"
#include "../../flamenco/runtime/fd_cost_tracker.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/alpenglow/fd_alpenglow.h"
#include "../../flamenco/log_collector/fd_log_collector.h"
#include "../../flamenco/progcache/fd_progcache_admin.h"
#include "../../disco/fd_txn_p.h"

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

struct fd_rpc_sim {
  fd_svm_mini_t * mini;
  int             fds[ 4 ];

  ulong       root_idx;
  ulong       slot;
  fd_bank_t * bank;       /* bank the transaction runs on, NULL outside exec..end */
  int         executed;

  fd_txn_p_t   txn_p[ 1 ];
  fd_txn_in_t  txn_in[ 1 ];
  fd_txn_out_t txn_out[ 1 ];
};

static int
fd_rpc_sim_memfd( char const * name,
                  int          want_fd ) {
  int fd = memfd_create( name, 0 );
  if( FD_UNLIKELY( fd<0 ) ) return -1;
  if( fd!=want_fd ) {
    if( FD_UNLIKELY( dup2( fd, want_fd )!=want_fd ) ) { close( fd ); return -1; }
    close( fd );
  }
  return want_fd;
}

fd_rpc_sim_t *
fd_rpc_sim_boot( void ) {
  static fd_rpc_sim_t sim_[ 1 ];
  fd_rpc_sim_t * sim = sim_;
  memset( sim, 0, sizeof(fd_rpc_sim_t) );

  /* fd_banks spills to these well known fds.  This tile has no other
     use for them. */
  sim->fds[ 0 ] = fd_rpc_sim_memfd( "rpc_sim_stakedel",      FD_STAKE_DELEGATIONS_FD );
  sim->fds[ 1 ] = fd_rpc_sim_memfd( "rpc_sim_epoch_credits", FD_EPOCH_CREDITS_FD     );
  sim->fds[ 2 ] = fd_rpc_sim_memfd( "rpc_sim_cost_tracker",  FD_COST_TRACKER_FD      );
  sim->fds[ 3 ] = fd_rpc_sim_memfd( "rpc_sim_vote_stakes",   FD_VOTE_STAKES_FD       );
  for( ulong i=0UL; i<4UL; i++ ) {
    if( FD_UNLIKELY( sim->fds[ i ]<0 ) ) {
      FD_LOG_WARNING(( "memfd_create failed (%i-%s), simulateTransaction disabled", errno, fd_io_strerror( errno ) ));
      return NULL;
    }
  }

  fd_svm_mini_limits_t limits[ 1 ];
  fd_svm_mini_limits_default( limits );
  limits->max_accounts = 1024UL;

  /* Lazily paged anonymous memory: the simulator only touches what a
     simulation needs. */
  ulong data_max = fd_svm_mini_wksp_data_max( limits );
  ulong part_max = fd_wksp_part_max_est( data_max, 64UL<<10 );
  ulong wksp_sz  = fd_ulong_align_up( fd_wksp_footprint( part_max, data_max ), FD_SHMEM_NORMAL_PAGE_SZ );
  void * mem = mmap( NULL, wksp_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(%lu KiB) failed (%i-%s), simulateTransaction disabled", wksp_sz>>10, errno, fd_io_strerror( errno ) ));
    return NULL;
  }
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "rpcsim", 1U, part_max, data_max ) );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "fd_wksp_new failed, simulateTransaction disabled" )); return NULL; }
  if( FD_UNLIKELY( fd_shmem_join_anonymous( "rpcsim", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, FD_SHMEM_NORMAL_PAGE_SZ, wksp_sz>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) ) ) {
    FD_LOG_WARNING(( "fd_shmem_join_anonymous failed, simulateTransaction disabled" ));
    return NULL;
  }

  sim->mini = fd_svm_mini_create( wksp, limits );
  sim->mini->skip_fd_truncate = 1;
  FD_LOG_NOTICE(( "transaction simulator ready (%lu MiB reserved, lazily paged)", wksp_sz>>20 ));
  return sim;
}

ulong
fd_rpc_sim_fds( fd_rpc_sim_t const * sim,
                int *                out_fds,
                ulong                out_max ) {
  if( FD_UNLIKELY( !sim || out_max<5UL ) ) return 0UL;
  for( ulong i=0UL; i<4UL; i++ ) out_fds[ i ] = sim->fds[ i ];
  out_fds[ 4 ] = sim->mini->accdb_fd;
  return 5UL;
}

void
fd_rpc_sim_begin( fd_rpc_sim_t *              sim,
                  ulong                       slot,
                  ulong                       epoch,
                  fd_features_t const *       features,
                  fd_rent_t const *           rent,
                  fd_epoch_schedule_t const * epoch_schedule ) {
  fd_svm_mini_t * mini = sim->mini;

  /* The root bank is a container one slot behind: accounts are loaded
     into it, and the transaction runs on a child at slot. */
  fd_sol_sysvar_clock_t clock = { .slot = slot ? slot-1UL : 0UL, .epoch = epoch };
  fd_svm_mini_params_t params[ 1 ];
  fd_svm_mini_params_default( params );
  params->init_sysvars       = 0; /* the live sysvar accounts are loaded instead */
  params->init_builtins      = 1;
  params->mock_validator_cnt = 0UL;
  params->clock              = &clock;
  params->epoch_schedule     = epoch_schedule;
  params->rent               = rent;
  sim->root_idx = fd_svm_mini_reset( mini, params );
  sim->slot     = slot;
  sim->bank     = NULL;
  sim->executed = 0;

  fd_bank_t * root = fd_svm_mini_bank( mini, sim->root_idx );
  root->f.features             = *features;
  root->f.rbh_lamports_per_sig = 5000UL;
  fd_blockhashes_init( &root->f.block_hash_queue, 1UL );
}

void
fd_rpc_sim_put( fd_rpc_sim_t * sim,
                uchar const *  pubkey,
                ulong          lamports,
                uchar const *  owner,
                int            executable,
                uchar const *  data,
                ulong          data_len ) {
  fd_accdb_t * accdb = sim->mini->runtime->accdb;
  fd_acc_t acc = fd_accdb_write_one( accdb, fd_svm_mini_fork_id( sim->mini, sim->root_idx ), pubkey );
  acc.lamports   = lamports;
  fd_memcpy( acc.owner, owner, 32UL );
  acc.executable = !!executable;
  acc.data_len   = data_len;
  if( data_len ) fd_memcpy( acc.data, data, data_len );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

void
fd_rpc_sim_blockhash( fd_rpc_sim_t * sim,
                      uchar const *  hash,
                      ulong          lamports_per_signature ) {
  fd_bank_t * root = fd_svm_mini_bank( sim->mini, sim->root_idx );
  fd_hash_t h; memcpy( h.uc, hash, 32UL );
  fd_blockhashes_push_new( &root->f.block_hash_queue, &h )->lamports_per_signature = lamports_per_signature;
}

int
fd_rpc_sim_exec( fd_rpc_sim_t *        sim,
                 uchar const *         payload,
                 ulong                 payload_sz,
                 fd_rpc_sim_result_t * result ) {
  fd_svm_mini_t * mini  = sim->mini;
  fd_accdb_t *    accdb = mini->runtime->accdb;
  memset( result, 0, sizeof(fd_rpc_sim_result_t) );

  if( FD_UNLIKELY( payload_sz>FD_TPU_MTU ) ) return 0;
  memset( sim->txn_p, 0, sizeof(fd_txn_p_t) );
  memcpy( sim->txn_p->payload, payload, payload_sz );
  sim->txn_p->payload_sz = (ushort)payload_sz;
  if( FD_UNLIKELY( !fd_txn_parse( sim->txn_p->payload, payload_sz, TXN( sim->txn_p ), NULL ) ) ) return 0;
  fd_txn_t const * txn = TXN( sim->txn_p );

  /* A child of the root bank at the live slot.  This is what
     fd_svm_mini_attach_child does, minus the start-of-block processing:
     the sysvar accounts were copied from the live bank as they are and
     must not be advanced a second time. */
  fd_bank_t * parent = fd_svm_mini_bank( mini, sim->root_idx );
  fd_bank_t * bank   = fd_banks_new_bank( mini->banks, sim->root_idx, 0L, 0 );
  if( FD_UNLIKELY( !bank ) ) return 0;
  bank = fd_banks_clone_from_parent( mini->banks, bank->idx );
  if( FD_UNLIKELY( !bank ) ) return 0;
  bank->f.slot               = sim->slot;
  bank->progcache_fork_id    = fd_progcache_attach_child( mini->progcache->join, parent->progcache_fork_id );
  bank->txncache_fork_id     = fd_txncache_attach_child ( mini->txncache,        parent->txncache_fork_id  );
  bank->accdb_fork_id        = fd_accdb_attach_child    ( accdb,                 parent->accdb_fork_id     );
  bank->parent_accdb_fork_id = parent->accdb_fork_id;
  bank->f.alpenglow_migration_slot = fd_alpenglow_migration_slot( bank, accdb );
  {
    fd_cost_tracker_store_t * store   = fd_bank_cost_tracker( bank );
    fd_cost_tracker_t *       tracker = fd_cost_tracker_store_pin( store, bank->cost_tracker_fork_id );
    fd_cost_tracker_init( tracker, &bank->f.features, &bank->f.slot_params, bank->f.slot );
    fd_cost_tracker_store_unpin( store, bank->cost_tracker_fork_id );
  }

  /* The status cache resolves the transaction's blockhash only if it
     is registered on a fork the bank descends from. */
  fd_hash_t recent; memcpy( recent.uc, sim->txn_p->payload+txn->recent_blockhash_off, 32UL );
  fd_txncache_finalize_fork( mini->txncache, parent->txncache_fork_id, 0UL, recent.uc );

  fd_log_collector_init( mini->log_collector, 1 );
  mini->runtime->log.enable_log_collector = 1;
  mini->runtime->log.log_collector        = mini->log_collector;

  memset( sim->txn_in, 0, sizeof(fd_txn_in_t) );
  sim->txn_in->txn              = sim->txn_p;
  sim->txn_in->bundle.is_bundle = 0;

  fd_runtime_sysvar_cache_refresh( mini->runtime, bank );
  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, sim->txn_in, sim->txn_out );
  sim->bank     = bank;
  sim->executed = 1;

  fd_txn_out_t const * out = sim->txn_out;
  result->txn_err       = out->err.txn_err;
  result->exec_err      = out->err.exec_err;
  result->exec_err_kind = out->err.exec_err_kind;
  result->exec_err_idx  = out->err.exec_err_idx;
  result->custom_err    = out->err.custom_err;
  result->is_fees_only  = out->err.is_fees_only;
  result->fee_charged   = out->err.is_committable && !out->err.is_noop;
  result->units_consumed = out->details.compute_budget.compute_unit_limit>=out->details.compute_budget.compute_meter
                         ? out->details.compute_budget.compute_unit_limit-out->details.compute_budget.compute_meter : 0UL;
  result->loaded_accounts_data_size = out->details.loaded_accounts_data_size;
  result->fee             = out->details.execution_fee+out->details.priority_fee;
  result->log_buf_sz      = mini->log_collector->buf_sz;
  result->log_buf         = mini->log_collector->buf;
  result->return_data_len = out->details.return_data.len;
  result->return_data     = out->details.return_data.data;
  result->return_program  = out->details.return_data.program_id.uc;
  result->acct_cnt        = out->accounts.is_setup ? out->accounts.cnt : 0UL;
  return 1;
}

int
fd_rpc_sim_account( fd_rpc_sim_t *  sim,
                    ulong           idx,
                    uchar const **  pubkey,
                    ulong *         lamports,
                    uchar const **  owner,
                    int *           executable,
                    uchar const **  data,
                    ulong *         data_len,
                    ulong *         pre_lamports ) {
  fd_txn_out_t const * out = sim->txn_out;
  if( FD_UNLIKELY( !sim->executed || !out->accounts.is_setup || idx>=out->accounts.cnt ) ) return 0;
  fd_acc_t const * acc = out->accounts.account[ idx ];
  if( FD_UNLIKELY( !acc ) ) return 0;
  *pubkey     = out->accounts.keys[ idx ].uc;
  *lamports   = acc->lamports;
  *owner      = acc->owner;
  *executable = (int)acc->executable;
  *data       = acc->data;
  *data_len   = acc->data_len;
  *pre_lamports = out->accounts.starting_lamports[ idx ];
  return 1;
}

void
fd_rpc_sim_end( fd_rpc_sim_t * sim ) {
  if( FD_UNLIKELY( !sim->executed ) ) return;
  /* Release the transaction's accounts.  A committable transaction has
     to go through commit to do that; it commits into the private fork,
     which the next fd_rpc_sim_begin discards. */
  if( sim->txn_out->err.is_committable ) fd_runtime_commit_txn( sim->mini->runtime, sim->bank, sim->txn_in, sim->txn_out );
  else                                   fd_runtime_cancel_txn( sim->mini->runtime, sim->bank, sim->txn_in, sim->txn_out );
  sim->executed = 0;
  sim->bank     = NULL;
}
