#ifndef SAE_PQ_H
#define SAE_PQ_H

#include "utils/common.h"
#include "utils/wpabuf.h"

#define PQ_SAE_PUBKEY_MAX_LEN 1568   /* ML-KEM-1024 upper bound; 1184 for -768 */
#define PQ_SAE_CT_MAX_LEN     1568
#define PQ_SAE_SECRET_LEN     32     /* ML-KEM shared secret is fixed 32 bytes */
#define PQ_SAE_FRAG_MAX       254    /* payload bytes per WLAN_EID_EXTENSION container */

struct sae_data;

/* Opaque handle management */
int  sae_pq_init(struct sae_data *sae);
void sae_pq_deinit(struct sae_data *sae);

/* Role + keypair lifecycle (call during Commit construction) */
void sae_pq_assign_role(struct sae_data *sae);
int  sae_pq_generate_keypair(struct sae_data *sae);

/* Protocol steps (called from sae_process_commit) */
int  sae_pq_encapsulate(struct sae_data *sae);
int  sae_pq_decapsulate(struct sae_data *sae);

/* Wire encoding/decoding (called from sae_write_commit / sae_parse_commit) */
int  sae_pq_write_element(struct sae_data *sae, struct wpabuf *buf);
u16  sae_pq_parse_element(struct sae_data *sae, const u8 **pos, const u8 *end);

#endif /* SAE_PQ_H */