#ifndef HEADER_fd_src_discof_rpc_fd_rpc_sim_h
#define HEADER_fd_src_discof_rpc_fd_rpc_sim_h

/* fd_rpc_sim is the rpc tile's private transaction simulator.

   It owns a complete, separate runtime (accounts database, program
   cache, status cache, bank) built from fd_svm_mini, with no link to
   replay or the exec tiles.  To simulate a transaction the caller
   copies the accounts it names out of the live accounts database into
   the private one, runs the transaction there with the live feature
   set and sysvars, reads the outcome and throws the state away.
   Nothing here can change what the validator executes or commits. */

#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/features/fd_features.h"

struct fd_rpc_sim;
typedef struct fd_rpc_sim fd_rpc_sim_t;

struct fd_rpc_sim_result {
  int   txn_err;         /* FD_RUNTIME_TXN_ERR_*, 0 on success */
  int   exec_err;        /* instruction error, if txn_err is INSTRUCTION_ERROR */
  int   exec_err_kind;
  uint  exec_err_idx;
  uint  custom_err;
  int   is_fees_only;
  int   fee_charged;     /* the fee payer pays the fee (the transaction would land) */
  ulong units_consumed;
  ulong loaded_accounts_data_size;
  ulong fee;

  ulong         log_buf_sz;
  uchar const * log_buf; /* fd_log_collector serialization */

  ulong         return_data_len;
  uchar const * return_data;
  uchar const * return_program;

  /* The transaction's accounts after execution, in transaction order */
  ulong acct_cnt;
};
typedef struct fd_rpc_sim_result fd_rpc_sim_result_t;

FD_PROTOTYPES_BEGIN

/* fd_rpc_sim_boot creates the simulator.  It opens memfds and maps
   memory, so it must run before the tile is sandboxed.  Returns NULL
   on failure (simulateTransaction is then unavailable). */
fd_rpc_sim_t *
fd_rpc_sim_boot( void );

/* fd_rpc_sim_fds lists the fds the simulator needs kept open. */
ulong
fd_rpc_sim_fds( fd_rpc_sim_t const * sim,
                int *                out_fds,
                ulong                out_max );

/* fd_rpc_sim_begin discards all simulator state and starts a fresh one
   whose bank will execute at slot.  Accounts and blockhashes are then
   loaded with fd_rpc_sim_put and fd_rpc_sim_blockhash. */
void
fd_rpc_sim_begin( fd_rpc_sim_t *              sim,
                  ulong                       slot,
                  ulong                       epoch,
                  fd_features_t const *       features,
                  fd_rent_t const *           rent,
                  fd_epoch_schedule_t const * epoch_schedule );

void
fd_rpc_sim_put( fd_rpc_sim_t * sim,
                uchar const *  pubkey,
                ulong          lamports,
                uchar const *  owner,
                int            executable,
                uchar const *  data,
                ulong          data_len );

/* Blockhashes are pushed oldest first. */
void
fd_rpc_sim_blockhash( fd_rpc_sim_t * sim,
                      uchar const *  hash,
                      ulong          lamports_per_signature );

/* fd_rpc_sim_exec runs the transaction.  Returns 0 if it could not be
   run at all (does not parse).  The result and the accounts read with
   fd_rpc_sim_account stay valid until fd_rpc_sim_end. */
int
fd_rpc_sim_exec( fd_rpc_sim_t *        sim,
                 uchar const *         payload,
                 ulong                 payload_sz,
                 fd_rpc_sim_result_t * result );

/* fd_rpc_sim_account returns transaction account idx as it stands
   after execution.  Returns 0 if idx is out of range. */
int
fd_rpc_sim_account( fd_rpc_sim_t *  sim,
                    ulong           idx,
                    uchar const **  pubkey,
                    ulong *         lamports,
                    uchar const **  owner,
                    int *           executable,
                    uchar const **  data,
                    ulong *         data_len,
                    ulong *         pre_lamports );

void
fd_rpc_sim_end( fd_rpc_sim_t * sim );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rpc_fd_rpc_sim_h */
