#include <furi.h>
#include <furi_hal.h>

#define APPLICATION_NAME "Crypto Test"

static uint8_t key1[32] = {
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE,
	0xDE, 0xAD, 0xBA, 0xBE
};

static uint8_t key2[32] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};

static uint8_t iv1[16] = {
	0xC0, 0xFE, 0xD0, 0x0D,
	0xC0, 0xFE, 0xD0, 0x0D,
	0xC0, 0xFE, 0xD0, 0x0D,
	0xC0, 0xFE, 0xD0, 0x0D
};

static uint8_t pt1[32] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};

static uint8_t pt2[32] = {
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
	0x8b, 0xad, 0xf0, 0x0d,
};

static uint8_t aad1[32] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};

static uint8_t aad2[31] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e
};

static uint8_t aad3[28] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b,
};

static uint8_t aad4[27] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a
};

static uint8_t tv_ctr_ct_pt2_k1_iv1[32] = {
	0x42, 0x23, 0x4a, 0x39,
	0x8b, 0x39, 0x08, 0xb6,
	0x84, 0x6f, 0xd1, 0x65,
	0x32, 0xd5, 0x79, 0x26,
	0x57, 0xbc, 0x8e, 0x10,
	0x97, 0x4a, 0x2f, 0x41,
	0xc4, 0xf2, 0xdf, 0x48,
	0xa4, 0x51, 0x50, 0x5d
};

static uint8_t tv_ctr_ct_pt1_k2_iv1[32] = {
	0x81, 0x83, 0x7a, 0x20,
	0xfb, 0xf6, 0x72, 0xe7,
	0x88, 0x23, 0x46, 0x45,
	0xfa, 0x3c, 0x1f, 0x26,
	0xb0, 0x7a, 0x92, 0x88,
	0x34, 0xde, 0xd2, 0x0f,
	0x87, 0x0b, 0x2a, 0x07,
	0xe8, 0x55, 0x10, 0xe6
};

static uint8_t tv_gcm_ct_pt2_k1_iv1[32] = {
	0x57, 0xbc, 0x8e, 0x10,
	0x97, 0x4a, 0x2f, 0x41,
	0xc4, 0xf2, 0xdf, 0x48,
	0xa4, 0x51, 0x50, 0x5d,
	0x95, 0xc2, 0x32, 0xa3,
	0x07, 0xc6, 0x4e, 0x31,
	0xeb, 0x04, 0x74, 0x86,
	0x1f, 0x1e, 0x37, 0x78
};

static uint8_t tv_gcm_tag_pt2_k1_iv1_32[16] = {
	0xb4, 0xbf, 0x09, 0x39,
	0xc4, 0xf6, 0x7f, 0xcb,
	0xd9, 0x82, 0x00, 0x34,
	0xe5, 0xdf, 0x61, 0x12
};

static uint8_t tv_gcm_tag_pt2_k1_iv1_31[16] = {
	0x1b, 0xf5, 0xad, 0xa8,
	0x3a, 0xe6, 0x7f, 0xf1,
	0x8d, 0xde, 0xcb, 0x03,
	0x73, 0x4b, 0x9b, 0xc3
};

static uint8_t tv_gcm_tag_pt2_k1_iv1_28[16] = {
	0x13, 0xe4, 0xa6, 0x0c,
	0x01, 0x49, 0x58, 0x19,
	0x08, 0x48, 0x56, 0xfe,
	0x34, 0x66, 0x85, 0x37
};

static uint8_t tv_gcm_tag_pt2_k1_iv1_27[16] = {
	0x49, 0x79, 0x56, 0xc9,
	0x76, 0x4d, 0xf7, 0xed,
	0x95, 0x9b, 0xb2, 0xf6,
	0xd5, 0x58, 0xa6, 0x32
};

static uint8_t tv_gcm_ct_pt1_k2_iv1[32] = {
	0xa0, 0x6a, 0x82, 0x98,
	0x24, 0xce, 0xc2, 0x1f,
	0x97, 0x1b, 0x3a, 0x17,
	0xf8, 0x45, 0x00, 0xf6,
	0x95, 0xbc, 0xb0, 0x4f,
	0x8d, 0x3f, 0x2b, 0x92,
	0x48, 0xe4, 0x67, 0x40,
	0x8b, 0xf8, 0xca, 0x8e
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_32[16] = {
	0x8c, 0x46, 0x77, 0x7c,
	0x5d, 0xbb, 0x44, 0x4a,
	0x2c, 0x7c, 0x32, 0x14,
	0x59, 0xbe, 0xe1, 0x0c
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_31[16] = {
	0x44, 0xc0, 0x42, 0x43,
	0x22, 0x82, 0x20, 0x98,
	0x58, 0x42, 0x94, 0x88,
	0x7a, 0x80, 0xfa, 0x75
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_28[16] = {
	0xd3, 0x18, 0x7d, 0x56,
	0x1a, 0x59, 0xc5, 0x51,
	0xed, 0xb9, 0xb3, 0x68,
	0xb9, 0xfc, 0x45, 0xd9
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_27[16] = {
	0x77, 0xc5, 0x09, 0x78,
	0xa1, 0xfa, 0x39, 0xa6,
	0xbb, 0x04, 0x89, 0x19,
	0x2b, 0x2f, 0x07, 0x9f
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_aad1_32[16] = {
	0x1a, 0xb1, 0xfa, 0x68,
	0x34, 0x65, 0x67, 0xea,
	0x52, 0xca, 0x32, 0x0b,
	0x1f, 0x84, 0xc4, 0xd1
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_aad2_32[16] = {
	0x80, 0x83, 0x2c, 0x9f,
	0x24, 0x12, 0xc4, 0x4f,
	0x4a, 0xd6, 0x10, 0x9e,
	0x74, 0x46, 0x20, 0x62
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_aad3_32[16] = {
	0x3f, 0x5f, 0x18, 0x6f,
	0x30, 0x90, 0xa8, 0x4c,
	0x72, 0x1f, 0xb4, 0x61,
	0xe2, 0x2a, 0x5b, 0x69
};

static uint8_t tv_gcm_tag_pt1_k2_iv1_aad4_32[16] = {
	0x9e, 0xbf, 0xfe, 0xfa,
	0xae, 0x61, 0x70, 0xc1,
	0xdc, 0x73, 0x5a, 0xad,
	0x09, 0xc0, 0xfc, 0x26
};

static void log_hex_str(const char *prefix, uint8_t *data, size_t len)
{
	FuriString *logmsg = furi_string_alloc();

	furi_string_printf(logmsg, "%s: ", prefix);

	size_t i;
	for (i = 0; i < len; i++) {
		furi_string_cat_printf(logmsg, "%02hx ", data[i]);
	}

	furi_string_cat_printf(logmsg, "[%u]", len);

	FURI_LOG_I(APPLICATION_NAME, furi_string_get_cstr(logmsg));
}

static bool encrypt_test(int iv_id, int key_id, int pt_id,
		uint8_t *iv, uint8_t *key, uint8_t *pt)
{

	FURI_LOG_I(APPLICATION_NAME, "Testing encryption of Plaintext %d "
			"using Key %d and IV %d...", pt_id, key_id, iv_id);

	FURI_LOG_I(APPLICATION_NAME, "Loading Key %d with IV %d...", key_id,
			iv_id);
	if (!furi_hal_crypto_load_key(key, iv)) {
		FURI_LOG_I(APPLICATION_NAME, "Loading of Key %d failed.",
				key_id);
		furi_hal_crypto_unload_key();
		return false;
	}
	FURI_LOG_I(APPLICATION_NAME, "Key %d loaded.", key_id);

	uint8_t ct[48];

	FURI_LOG_I(APPLICATION_NAME, "Encrypting Plaintext %d...", pt_id);
	if (!furi_hal_crypto_encrypt(pt, ct, 32)) {
		FURI_LOG_I(APPLICATION_NAME,
				"Encryption of Plaintext %d failed.", pt_id);
		furi_hal_crypto_unload_key();
		return false;
	}
	FURI_LOG_I(APPLICATION_NAME, "Plaintext %d encrypted.", pt_id);

	FURI_LOG_I(APPLICATION_NAME, "Unloading Key %d...", key_id);
	if (!furi_hal_crypto_unload_key()) {
		FURI_LOG_I(APPLICATION_NAME, "Unloading of Key %d failed.",
				key_id);
		return false;
	}
	FURI_LOG_I(APPLICATION_NAME, "Key %d unloaded.", key_id);

	FURI_LOG_I(APPLICATION_NAME, "Encryption test successful.");

	FURI_LOG_I(APPLICATION_NAME, "Testing decryption of Ciphertext %d "
			"using Key %d and IV %d...", pt_id, key_id, iv_id);

	FURI_LOG_I(APPLICATION_NAME, "Loading Key %d with IV %d...", key_id,
			iv_id);
	if (!furi_hal_crypto_load_key(key, iv)) {
		FURI_LOG_I(APPLICATION_NAME, "Loading of Key %d failed.",
				key_id);
		furi_hal_crypto_unload_key();
		return false;
	}
	FURI_LOG_I(APPLICATION_NAME, "Key %d loaded.", key_id);

	uint8_t dec_pt[48];

	FURI_LOG_I(APPLICATION_NAME, "Decrypting Ciphertext %d...", pt_id);
	if (!furi_hal_crypto_decrypt(ct, dec_pt, 32)) {
		FURI_LOG_I(APPLICATION_NAME,
				"Decryption of Ciphertext %d failed.", pt_id);
		furi_hal_crypto_unload_key();
		return false;
	}
	FURI_LOG_I(APPLICATION_NAME, "Ciphertext %d decrypted.", pt_id);

	FURI_LOG_I(APPLICATION_NAME, "Unloading Key %d...", key_id);
	if (!furi_hal_crypto_unload_key()) {
		FURI_LOG_I(APPLICATION_NAME, "Unloading of Key %d failed.",
				key_id);
		return false;
	}
	FURI_LOG_I(APPLICATION_NAME, "Key %d unloaded.", key_id);

	if (memcmp(pt, dec_pt, 32) != 0) {
		FURI_LOG_I(APPLICATION_NAME, "Decrypted ciphertext does not "
				"match plaintext!");
		FURI_LOG_I(APPLICATION_NAME, "Decryption test failed.");
	} else {
		FURI_LOG_I(APPLICATION_NAME, "Decryption test successful.");
	}

	FuriString *prefix = furi_string_alloc();

	furi_string_printf(prefix, "Key %d", key_id);
	log_hex_str(furi_string_get_cstr(prefix), key, 32);

	furi_string_printf(prefix, "IV %d", iv_id);
	log_hex_str(furi_string_get_cstr(prefix), iv, 16);

	furi_string_printf(prefix, "Plaintext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), pt, 32);

	furi_string_printf(prefix, "Ciphertext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), ct, 32);

	furi_string_printf(prefix, "Decrypted Ciphertext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), dec_pt, 32);

	return true;
}

static bool ctr_test(int iv_id, int key_id, int pt_id, uint8_t *iv, uint8_t
		*key, uint8_t *pt, size_t length, uint8_t *tv)
{

	FURI_LOG_I(APPLICATION_NAME, "Testing CTR encryption of Plaintext %d "
			"using Key %d and IV %d...", pt_id, key_id, iv_id);

	uint8_t ct[length];

	FURI_LOG_I(APPLICATION_NAME, "CTR encrypting Plaintext %d...", pt_id);
	if (!furi_hal_crypto_ctr(key, iv, pt, ct, length)) {
		FURI_LOG_I(APPLICATION_NAME,
				"CTR encryption of Plaintext %d failed.",
				pt_id);
		return false;

	}
	FURI_LOG_I(APPLICATION_NAME, "Plaintext %d CTR encrypted.", pt_id);

	FURI_LOG_I(APPLICATION_NAME, "Encryption test successful.");

	FURI_LOG_I(APPLICATION_NAME, "Testing CTR decryption of Ciphertext %d "
			"using Key %d and IV %d...", pt_id, key_id, iv_id);

	uint8_t dec_pt[length];

	FURI_LOG_I(APPLICATION_NAME, "CTR decrypting Ciphertext %d...", pt_id);
	if (!furi_hal_crypto_ctr(key, iv, ct, dec_pt, length)) {
		FURI_LOG_I(APPLICATION_NAME,
				"CTR decryption of Ciphertext %d failed.",
				pt_id);
		return false;

	}
	FURI_LOG_I(APPLICATION_NAME, "Ciphertext %d CTR decrypted.", pt_id);

	bool ct_ok = (memcmp(pt, dec_pt, length) == 0);
	bool tv_ok = (memcmp(ct, tv, length) == 0);

	if (!ct_ok) {
		FURI_LOG_I(APPLICATION_NAME, "CTR decrypted ciphertext does "
				"not match plaintext!");
	}

	if (!tv_ok) {
		FURI_LOG_I(APPLICATION_NAME, "CTR ciphertext does not match "
				"test vector!");
	}

	if (!ct_ok || !tv_ok) {
		FURI_LOG_I(APPLICATION_NAME, "CTR decryption test failed.");
	} else {
		FURI_LOG_I(APPLICATION_NAME, "CTR decryption test successful.");
	}

	FuriString *prefix = furi_string_alloc();

	furi_string_printf(prefix, "Key %d", key_id);
	log_hex_str(furi_string_get_cstr(prefix), key, 32);

	furi_string_printf(prefix, "IV %d", iv_id);
	log_hex_str(furi_string_get_cstr(prefix), iv, 16);

	furi_string_printf(prefix, "Plaintext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), pt, length);

	furi_string_printf(prefix, "Ciphertext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), ct, length);

	furi_string_printf(prefix, "Decrypted Ciphertext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), dec_pt, length);

	return true;
}

static bool gcm_test(int iv_id, int key_id, int aad_id, int pt_id, uint8_t *iv,
		uint8_t *key, uint8_t *aad, size_t aad_length, uint8_t *pt,
		size_t length, uint8_t *tv_ct, uint8_t *tv_tag)
{

	FURI_LOG_I(APPLICATION_NAME, "Testing GCM encryption of AAD %d and "
			"Plaintext %d using Key %d and IV %d...", aad_id,
			pt_id, key_id, iv_id);

	uint8_t ct[length];
	uint8_t tag_enc[16];

	FURI_LOG_I(APPLICATION_NAME, "GCM encrypting Plaintext %d...", pt_id);
	if (!furi_hal_crypto_gcm(key, iv, aad, aad_length, pt, ct, length,
				tag_enc, false)) {
		FURI_LOG_I(APPLICATION_NAME,
				"GCM encryption of Plaintext %d failed.",
				pt_id);
		return false;

	}
	FURI_LOG_I(APPLICATION_NAME, "Plaintext %d GCM encrypted.", pt_id);

	FURI_LOG_I(APPLICATION_NAME, "Encryption test successful.");

	FURI_LOG_I(APPLICATION_NAME, "Testing GCM decryption of AAD %d and "
			"Ciphertext %d using Key %d and IV %d...", aad_id,
			pt_id, key_id, iv_id);

	uint8_t dec_pt[length];
	uint8_t tag_dec[16];

	FURI_LOG_I(APPLICATION_NAME, "GCM decrypting Ciphertext %d...", pt_id);
	if (!furi_hal_crypto_gcm(key, iv, aad, aad_length, ct, dec_pt, length,
				tag_dec, true)) {
		FURI_LOG_I(APPLICATION_NAME,
				"GCM decryption of Ciphertext %d failed.",
				pt_id);
		return false;

	}
	FURI_LOG_I(APPLICATION_NAME, "Ciphertext %d GCM decrypted.", pt_id);

	bool ct_ok = (memcmp(pt, dec_pt, length) == 0);
	bool tag_ok = (memcmp(tag_enc, tag_dec, 16) == 0);
	bool tv_ct_ok = (memcmp(ct, tv_ct, length) == 0);
	bool tv_tag_ok = (memcmp(tag_enc, tv_tag, 16) == 0);

	if (!ct_ok) {
		FURI_LOG_I(APPLICATION_NAME, "GCM decrypted ciphertext does "
				"not match plaintext!");
	}

	if (!tag_ok) {
		FURI_LOG_I(APPLICATION_NAME, "GCM encryption tag does not "
				"match decryption tag!");
	}

	if (!tv_ct_ok) {
		FURI_LOG_I(APPLICATION_NAME, "GCM ciphertext does not match "
				"test vector!");
	}

	if (!tv_tag_ok) {
		FURI_LOG_I(APPLICATION_NAME, "GCM tag does not match test "
				"vector!");
	}

	if (!ct_ok || !tag_ok || !tv_ct_ok || !tv_tag_ok) {
		FURI_LOG_I(APPLICATION_NAME, "GCM decryption test failed.");
	} else {
		FURI_LOG_I(APPLICATION_NAME, "GCM decryption test successful.");
	}

	FuriString *prefix = furi_string_alloc();

	furi_string_printf(prefix, "Key %d", key_id);
	log_hex_str(furi_string_get_cstr(prefix), key, 32);

	furi_string_printf(prefix, "IV %d", iv_id);
	log_hex_str(furi_string_get_cstr(prefix), iv, 16);

	furi_string_printf(prefix, "AAD %d", aad_id);
	log_hex_str(furi_string_get_cstr(prefix), aad, aad_length);

	furi_string_printf(prefix, "Plaintext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), pt, length);

	furi_string_printf(prefix, "Ciphertext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), ct, length);

	furi_string_printf(prefix, "Encryption Tag %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), tag_enc, 16);

	furi_string_printf(prefix, "Decrypted Ciphertext %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), dec_pt, length);

	furi_string_printf(prefix, "Decryption Tag %d", pt_id);
	log_hex_str(furi_string_get_cstr(prefix), tag_dec, 16);

	return true;
}

int32_t crypto_test(void)
{
	FURI_LOG_I(APPLICATION_NAME, "Starting...");

	if (!encrypt_test(1, 1, 1, iv1, key1, pt1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!encrypt_test(1, 2, 1, iv1, key2, pt1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!encrypt_test(1, 1, 2, iv1, key1, pt2)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 1, 2, iv1, key1, pt2, 32, tv_ctr_ct_pt2_k1_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 1, 2, iv1, key1, pt2, 31, tv_ctr_ct_pt2_k1_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 1, 2, iv1, key1, pt2, 28, tv_ctr_ct_pt2_k1_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 1, 2, iv1, key1, pt2, 27, tv_ctr_ct_pt2_k1_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 2, 1, iv1, key2, pt1, 32, tv_ctr_ct_pt1_k2_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 2, 1, iv1, key2, pt1, 31, tv_ctr_ct_pt1_k2_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 2, 1, iv1, key2, pt1, 28, tv_ctr_ct_pt1_k2_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(1, 2, 1, iv1, key2, pt1, 27, tv_ctr_ct_pt1_k2_iv1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 1, 0, 2, iv1, key1, NULL, 0, pt2, 32,
				tv_gcm_ct_pt2_k1_iv1,
				tv_gcm_tag_pt2_k1_iv1_32)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 1, 0, 2, iv1, key1, NULL, 0, pt2, 31,
				tv_gcm_ct_pt2_k1_iv1,
				tv_gcm_tag_pt2_k1_iv1_31)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 1, 0, 2, iv1, key1, NULL, 0, pt2, 28,
				tv_gcm_ct_pt2_k1_iv1,
				tv_gcm_tag_pt2_k1_iv1_28)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 1, 0, 2, iv1, key1, NULL, 0, pt2, 27,
				tv_gcm_ct_pt2_k1_iv1,
				tv_gcm_tag_pt2_k1_iv1_27)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 0, 1, iv1, key2, NULL, 0, pt1, 32,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_32)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 0, 1, iv1, key2, NULL, 0, pt1, 31,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_31)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 0, 1, iv1, key2, NULL, 0, pt1, 28,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_28)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 0, 1, iv1, key2, NULL, 0, pt1, 27,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_27)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 1, 1, iv1, key2, aad1, 32, pt1, 32,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_aad1_32)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 2, 1, iv1, key2, aad2, 31, pt1, 32,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_aad2_32)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 3, 1, iv1, key2, aad3, 28, pt1, 32,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_aad3_32)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 2, 4, 1, iv1, key2, aad4, 27, pt1, 32,
				tv_gcm_ct_pt1_k2_iv1,
				tv_gcm_tag_pt1_k2_iv1_aad4_32)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	FURI_LOG_I(APPLICATION_NAME, "Terminating...");

	return 0;
}
