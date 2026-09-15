#include "utils/includes.h"
#include "utils/common.h"
#include "sae.h"
#include "sae_pq.h"
#include "ieee802_11_defs.h"
#include <oqs/oqs.h>

#define PQ_SAE_ALG_NAME "ML-KEM-768"

int sae_pq_init(struct sae_data *sae)
{
	if (sae->tmp->pq_kem)
		return 0;
	sae->tmp->pq_kem = OQS_KEM_new(PQ_SAE_ALG_NAME);
	if (!sae->tmp->pq_kem) {
		wpa_printf(MSG_ERROR, "SAE: liboqs failed to init %s",
			   PQ_SAE_ALG_NAME);
		return -1;
	}
	return 0;
}


void sae_pq_deinit(struct sae_data *sae)
{
	if (!sae->tmp)
		return;
	if (sae->tmp->pq_kem) {
		OQS_KEM_free((OQS_KEM *) sae->tmp->pq_kem);
		sae->tmp->pq_kem = NULL;
	}
	wpabuf_free(sae->tmp->pq_own_pubkey);
	wpabuf_free(sae->tmp->pq_own_seckey_buf);
	wpabuf_free(sae->tmp->pq_peer_pubkey);
	wpabuf_free(sae->tmp->pq_own_ciphertext);
	wpabuf_free(sae->tmp->pq_peer_ciphertext);
	sae->tmp->pq_own_pubkey = NULL;
	sae->tmp->pq_own_seckey_buf = NULL;
	sae->tmp->pq_peer_pubkey = NULL;
	sae->tmp->pq_own_ciphertext = NULL;
	sae->tmp->pq_peer_ciphertext = NULL;
}


void sae_pq_assign_role(struct sae_data *sae)
{
	/* Higher MAC address = keypair owner / decapsulator.
	 * Lower MAC address = encapsulator. Reuses the existing
	 * own_addr_higher tie-break already computed for SAE. */
	sae->tmp->pq_role_is_encapsulator = !sae->tmp->own_addr_higher;
}


int sae_pq_generate_keypair(struct sae_data *sae)
{
	OQS_KEM *kem = (OQS_KEM *) sae->tmp->pq_kem;
	struct wpabuf *pk, *sk;

	if (!kem)
		return -1;

	pk = wpabuf_alloc(kem->length_public_key);
	sk = wpabuf_alloc(kem->length_secret_key);
	if (!pk || !sk) {
		wpabuf_free(pk);
		wpabuf_free(sk);
		return -1;
	}

	if (OQS_KEM_keypair(kem, wpabuf_put(pk, kem->length_public_key),
			     wpabuf_put(sk, kem->length_secret_key)) !=
	    OQS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SAE: PQC keypair generation failed");
		wpabuf_free(pk);
		wpabuf_free(sk);
		return -1;
	}

	sae->tmp->pq_own_pubkey = pk;
	sae->tmp->pq_own_seckey_buf = sk;
	return 0;
}


int sae_pq_encapsulate(struct sae_data *sae)
{
	OQS_KEM *kem = (OQS_KEM *) sae->tmp->pq_kem;
	struct wpabuf *ct;

	if (!kem || !sae->tmp->pq_peer_pubkey ||
	    wpabuf_len(sae->tmp->pq_peer_pubkey) != kem->length_public_key) {
		wpa_printf(MSG_ERROR, "SAE: peer PQC public key missing/bad size");
		return -1;
	}

	ct = wpabuf_alloc(kem->length_ciphertext);
	if (!ct)
		return -1;

	if (OQS_KEM_encaps(kem, wpabuf_put(ct, kem->length_ciphertext),
			    sae->tmp->pq_shared_secret,
			    wpabuf_head(sae->tmp->pq_peer_pubkey)) !=
	    OQS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SAE: PQC encapsulation failed");
		wpabuf_free(ct);
		return -1;
	}

	sae->tmp->pq_own_ciphertext = ct;
	return 0;
}


int sae_pq_decapsulate(struct sae_data *sae)
{
	OQS_KEM *kem = (OQS_KEM *) sae->tmp->pq_kem;

	if (!kem || !sae->tmp->pq_peer_ciphertext || !sae->tmp->pq_own_seckey_buf ||
	    wpabuf_len(sae->tmp->pq_peer_ciphertext) != kem->length_ciphertext) {
		wpa_printf(MSG_ERROR, "SAE: PQC ciphertext missing/bad size");
		return -1;
	}

	if (OQS_KEM_decaps(kem, sae->tmp->pq_shared_secret,
			    wpabuf_head(sae->tmp->pq_peer_ciphertext),
			    wpabuf_head(sae->tmp->pq_own_seckey_buf)) !=
	    OQS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SAE: PQC decapsulation failed");
		return -1;
	}

	return 0;
}


int sae_pq_write_element(struct sae_data *sae, struct wpabuf *buf)
{
	struct wpabuf *payload = sae->tmp->pq_role_is_encapsulator ?
		sae->tmp->pq_own_pubkey : sae->tmp->pq_own_ciphertext;
	u8 eid_ext = sae->tmp->pq_role_is_encapsulator ?
		WLAN_EID_EXT_PQ_SAE_PUBKEY_FRAG :
		WLAN_EID_EXT_PQ_SAE_CIPHERTEXT_FRAG;
	const u8 *p;
	size_t remaining;

	if (!payload) {
		wpa_printf(MSG_ERROR, "SAE: PQC payload missing at write time");
		return -1;
	}

	p = wpabuf_head(payload);
	remaining = wpabuf_len(payload);

	while (remaining > 0) {
		size_t chunk = remaining > PQ_SAE_FRAG_MAX ?
			PQ_SAE_FRAG_MAX : remaining;

		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + chunk);
		wpabuf_put_u8(buf, eid_ext);
		wpabuf_put_data(buf, p, chunk);

		p += chunk;
		remaining -= chunk;
	}

	wpa_printf(MSG_DEBUG, "SAE: appended PQC element (%zu bytes)",
		   wpabuf_len(payload));
	return 0;
}


u16 sae_pq_parse_element(struct sae_data *sae, const u8 **pos, const u8 *end)
{
	u8 eid_ext = sae->tmp->pq_role_is_encapsulator ?
		WLAN_EID_EXT_PQ_SAE_CIPHERTEXT_FRAG :
		WLAN_EID_EXT_PQ_SAE_PUBKEY_FRAG;
	struct wpabuf **target = sae->tmp->pq_role_is_encapsulator ?
		&sae->tmp->pq_peer_ciphertext : &sae->tmp->pq_peer_pubkey;
	struct wpabuf *reassembled = NULL;

	while (*pos + 2 <= end && (*pos)[0] == WLAN_EID_EXTENSION) {
		u8 elen = (*pos)[1];
		if (*pos + 2 + elen > end || elen < 1)
			break;
		if ((*pos)[2] != eid_ext)
			break;

		if (!reassembled) {
			reassembled = wpabuf_alloc(PQ_SAE_PUBKEY_MAX_LEN);
			if (!reassembled)
				return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		wpabuf_put_data(reassembled, *pos + 3, elen - 1);
		*pos += 2 + elen;

		if ((size_t) (elen - 1) < PQ_SAE_FRAG_MAX)
			break;
	}

	*target = reassembled;
	return WLAN_STATUS_SUCCESS;
}