/* sae_pq.h - Hybrid post-quantum (ML-KEM) extension for WPA3-SAE.
 Isolates all liboqs-dependent code away from sae.c/sae.h so those stay
 buildable without liboqs when CONFIG_PQ_SAE is off, and so the OQS_KEM
 type never leaks into sae.h (included everywhere). Integration: sae.h
 stores an opaque pq_kem pointer + PQC buffers in sae_temporary_data;
 sae.c calls into these functions at commit-build, commit-process, and
 commit-parse time. Experimental research prototype, not for production.*/

#ifndef SAE_PQ_H
#define SAE_PQ_H

#include "utils/common.h"
#include "utils/wpabuf.h"

// ML-KEM-1024 upper bound
#define PQ_SAE_PUBKEY_MAX_LEN 1568

// ciphertext upper bound
#define PQ_SAE_CT_MAX_LEN 1568

// fixed ML-KEM shared-secret size
#define PQ_SAE_SECRET_LEN 32

// payload bytes per WLAN_EID_EXTENSION
#define PQ_SAE_FRAG_MAX 254

// hard cap on reassembled fragment count
#define PQ_SAE_MAX_FRAGS 16

struct sae_data;

// alloc liboqs KEM ctx, idempotent
int  sae_pq_init(struct sae_data *sae);

// free + zeroize all PQC state
void sae_pq_deinit(struct sae_data *sae);

// decide encapsulator vs decapsulator via MAC tie-break
void sae_pq_assign_role(struct sae_data *sae);

// decapsulator role only: generate ML-KEM keypair
int  sae_pq_generate_keypair(struct sae_data *sae);

// encapsulator role: derive secret + ciphertext from peer pubkey
int  sae_pq_encapsulate(struct sae_data *sae);

// decapsulator role: recover secret from peer ciphertext
int  sae_pq_decapsulate(struct sae_data *sae);

// fragment + append our payload to outgoing Commit
int  sae_pq_write_element(struct sae_data *sae, struct wpabuf *buf);

// bounds-checked reassembly of peer's fragments
u16  sae_pq_parse_element(struct sae_data *sae, const u8 **pos, const u8 *end);

#endif
