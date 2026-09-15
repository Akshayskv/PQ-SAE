/*
 * sae_pq.c - Hybrid post-quantum (ML-KEM) extension for WPA3-SAE.
 * All liboqs calls live here, nowhere else in the tree. Flow: role is
 * assigned via MAC-address tie-break (reuses SAE's own_addr_higher);
 * the decapsulator role generates an ML-KEM keypair and publishes the
 * public key; the encapsulator role, once it receives that key, derives
 * a shared secret and sends back a ciphertext; the decapsulator then
 * recovers the same secret from that ciphertext. The secret is folded
 * into SAE's HKDF as a second IKM alongside the classical ECC/FFC value
 * (see sae.c patch). Oversized payloads are fragmented across repeated
 * WLAN_EID_EXTENSION containers - no kernel mac80211 changes needed.
 * Not fixed here: AKM downgrade protection, and the assumption that
 * hkdf_extract() concatenates multiple IKM parts (verify against the
 * real function before trusting the combiner). Build: CONFIG_PQ_SAE=y,
 * links -loqs.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/os.h"
#include "sae.h"
#include "sae_pq.h"
#include "ieee802_11_defs.h"
#include <oqs/oqs.h>

// NIST Level 3, reasonable pairing with P-256
#define PQ_SAE_ALG_NAME "ML-KEM-768"


int sae_pq_init(struct sae_data *sae)
{
	if (sae->tmp->pq_kem)
	    // already initialized
		return 0;

	sae->tmp->pq_kem = OQS_KEM_new(PQ_SAE_ALG_NAME);
	if (!sae->tmp->pq_kem) {
		wpa_printf(MSG_ERROR, "SAE: liboqs failed to init %s", PQ_SAE_ALG_NAME);
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

	// zeroize shared secret
	wpabuf_clear_free(sae->tmp->pq_own_seckey_buf);
	sae->tmp->pq_own_seckey_buf = NULL;

	// public values: ordinary free is fine
	wpabuf_free(sae->tmp->pq_own_pubkey);
	wpabuf_free(sae->tmp->pq_peer_pubkey);
	wpabuf_free(sae->tmp->pq_own_ciphertext);
	wpabuf_free(sae->tmp->pq_peer_ciphertext);
	sae->tmp->pq_own_pubkey = NULL;
	sae->tmp->pq_peer_pubkey = NULL;
	sae->tmp->pq_own_ciphertext = NULL;
	sae->tmp->pq_peer_ciphertext = NULL;

	// not a wpabuf, zeroize explicitly
	forced_memzero(sae->tmp->pq_shared_secret, PQ_SAE_SECRET_LEN);
}


void sae_pq_assign_role(struct sae_data *sae)
{
	// Higher MAC = decapsulator/keypair owner, lower MAC = encapsulator - reuses SAE's own tie-break
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
		wpabuf_clear_free(sk);
		return -1;
	}

	if (OQS_KEM_keypair(kem, wpabuf_put(pk, kem->length_public_key),
			     wpabuf_put(sk, kem->length_secret_key)) != OQS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SAE: PQC keypair generation failed");
		wpabuf_free(pk);
		wpabuf_clear_free(sk);
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

	// size-check peer pubkey before calling liboqs - avoids an OOB read on a short buffer
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
			    wpabuf_head(sae->tmp->pq_peer_pubkey)) != OQS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SAE: PQC encapsulation failed");
		wpabuf_free(ct);
		forced_memzero(sae->tmp->pq_shared_secret, PQ_SAE_SECRET_LEN);
		return -1;
	}

	sae->tmp->pq_own_ciphertext = ct;
	return 0;
}


int sae_pq_decapsulate(struct sae_data *sae)
{
	OQS_KEM *kem = (OQS_KEM *) sae->tmp->pq_kem;

	// size-check peer ciphertext before calling liboqs, same reasoning as encapsulate()
	if (!kem || !sae->tmp->pq_peer_ciphertext || !sae->tmp->pq_own_seckey_buf ||
	    wpabuf_len(sae->tmp->pq_peer_ciphertext) != kem->length_ciphertext) {
		wpa_printf(MSG_ERROR, "SAE: PQC ciphertext missing/bad size");
		return -1;
	}

	if (OQS_KEM_decaps(kem, sae->tmp->pq_shared_secret,
			    wpabuf_head(sae->tmp->pq_peer_ciphertext),
			    wpabuf_head(sae->tmp->pq_own_seckey_buf)) != OQS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SAE: PQC decapsulation failed");
		forced_memzero(sae->tmp->pq_shared_secret, PQ_SAE_SECRET_LEN);
		return -1;
	}

	return 0;
}


int sae_pq_write_element(struct sae_data *sae, struct wpabuf *buf)
{
	struct wpabuf *payload = sae->tmp->pq_role_is_encapsulator ?
		sae->tmp->pq_own_pubkey : sae->tmp->pq_own_ciphertext;
	u8 eid_ext = sae->tmp->pq_role_is_encapsulator ?
		WLAN_EID_EXT_PQ_SAE_PUBKEY_FRAG : WLAN_EID_EXT_PQ_SAE_CIPHERTEXT_FRAG;
	const u8 *p;
	size_t remaining;

	if (!payload) {
		wpa_printf(MSG_ERROR, "SAE: PQC payload missing at write time");
		return -1;
	}

	p = wpabuf_head(payload);
	remaining = wpabuf_len(payload);

	// split into WLAN_EID_EXTENSION containers of at most PQ_SAE_FRAG_MAX bytes each
	while (remaining > 0) {
		size_t chunk = remaining > PQ_SAE_FRAG_MAX ? PQ_SAE_FRAG_MAX : remaining;

		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + chunk);
		wpabuf_put_u8(buf, eid_ext);
		wpabuf_put_data(buf, p, chunk);

		p += chunk;
		remaining -= chunk;
	}

	wpa_printf(MSG_DEBUG, "SAE: appended PQC element (%zu bytes)", wpabuf_len(payload));
	return 0;
}


u16 sae_pq_parse_element(struct sae_data *sae, const u8 **pos, const u8 *end)
{
	u8 eid_ext = sae->tmp->pq_role_is_encapsulator ?
		WLAN_EID_EXT_PQ_SAE_CIPHERTEXT_FRAG : WLAN_EID_EXT_PQ_SAE_PUBKEY_FRAG;
	struct wpabuf **target = sae->tmp->pq_role_is_encapsulator ?
		&sae->tmp->pq_peer_ciphertext : &sae->tmp->pq_peer_pubkey;
	struct wpabuf *reassembled = NULL;
	size_t total = 0;
	unsigned int frag_count = 0;

	while (*pos + 2 <= end && (*pos)[0] == WLAN_EID_EXTENSION) {
		u8 elen = (*pos)[1];

		if (*pos + 2 + elen > end || elen < 1)
		// malformed/truncated container, stop consuming
		break;
		if ((*pos)[2] != eid_ext)
		    // not our fragment type, end of our run
			break;

		// bounds check BEFORE copying - fixes the earlier unbounded-write overflow
		frag_count++;
		if (frag_count > PQ_SAE_MAX_FRAGS ||
		    total + (size_t) (elen - 1) > PQ_SAE_PUBKEY_MAX_LEN) {
			wpa_printf(MSG_INFO, "SAE: PQC element exceeds limits, rejecting");
			wpabuf_free(reassembled);
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}

		if (!reassembled) {
			reassembled = wpabuf_alloc(PQ_SAE_PUBKEY_MAX_LEN);
			if (!reassembled)
				return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}

		wpabuf_put_data(reassembled, *pos + 3, elen - 1);
		total += elen - 1;
		*pos += 2 + elen;

		if ((size_t) (elen - 1) < PQ_SAE_FRAG_MAX)
			// short fragment = last one, mirrors the writer's behavior
			break;
	}

	// drop any stale value before overwriting
	wpabuf_free(*target);
	*target = reassembled;
	return WLAN_STATUS_SUCCESS;
}


/*
 * Integration points in sae.c/sae.h (see the .patch.md files for exact
 * insertions): sae.h adds the opaque PQC fields to sae_temporary_data and
 * grows SAE_COMMIT_MAX_LEN. sae.c calls, in order: sae_pq_assign_role() +
 * sae_pq_init() + sae_pq_generate_keypair() (decapsulator only) AFTER the
 * anti-clogging check passes; sae_pq_encapsulate()/decapsulate() inside
 * sae_process_commit(); the HKDF combiner change inside sae_derive_keys();
 * sae_pq_write_element() inside sae_write_commit(); sae_pq_parse_element()
 * inside sae_parse_commit(); sae_pq_deinit() on every temp-data teardown path.
 */
