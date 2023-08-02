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

static uint8_t key_ctr_1[32] = {
	0x77, 0x6B, 0xEF, 0xF2,
	0x85, 0x1D, 0xB0, 0x6F,
	0x4C, 0x8A, 0x05, 0x42,
	0xC8, 0x69, 0x6F, 0x6C,
	0x6A, 0x81, 0xAF, 0x1E,
	0xEC, 0x96, 0xB4, 0xD3,
	0x7F, 0xC1, 0xD6, 0x89,
	0xE6, 0xC1, 0xC1, 0x04, 
};

static uint8_t iv_ctr_1[16] = {
	0x00, 0x00, 0x00, 0x60,
	0xDB, 0x56, 0x72, 0xC9,
	0x7A, 0xA8, 0xF0, 0xB2,
	0x00, 0x00, 0x00, 0x01, 
};

static uint8_t pt_ctr_1[16] = {
	0x53, 0x69, 0x6E, 0x67,
	0x6C, 0x65, 0x20, 0x62,
	0x6C, 0x6F, 0x63, 0x6B,
	0x20, 0x6D, 0x73, 0x67, 
};

static uint8_t tv_ctr_ct_1[16] = {
	0x14, 0x5A, 0xD0, 0x1D,
	0xBF, 0x82, 0x4E, 0xC7,
	0x56, 0x08, 0x63, 0xDC,
	0x71, 0xE3, 0xE0, 0xC0, 
};

static uint8_t key_ctr_2[32] = {
	0x77, 0x6B, 0xEF, 0xF2,
	0x85, 0x1D, 0xB0, 0x6F,
	0x4C, 0x8A, 0x05, 0x42,
	0xC8, 0x69, 0x6F, 0x6C,
	0x6A, 0x81, 0xAF, 0x1E,
	0xEC, 0x96, 0xB4, 0xD3,
	0x7F, 0xC1, 0xD6, 0x89,
	0xE6, 0xC1, 0xC1, 0x04, 
};

static uint8_t iv_ctr_2[16] = {
	0x00, 0x00, 0x00, 0x60,
	0xDB, 0x56, 0x72, 0xC9,
	0x7A, 0xA8, 0xF0, 0xB2,
	0x00, 0x00, 0x00, 0x01, 
};

static uint8_t pt_ctr_2[0] = {};

static uint8_t tv_ctr_ct_2[0] = {};

static uint8_t key_ctr_3[32] = {
	0xF6, 0xD6, 0x6D, 0x6B,
	0xD5, 0x2D, 0x59, 0xBB,
	0x07, 0x96, 0x36, 0x58,
	0x79, 0xEF, 0xF8, 0x86,
	0xC6, 0x6D, 0xD5, 0x1A,
	0x5B, 0x6A, 0x99, 0x74,
	0x4B, 0x50, 0x59, 0x0C,
	0x87, 0xA2, 0x38, 0x84, 
};

static uint8_t iv_ctr_3[16] = {
	0x00, 0xFA, 0xAC, 0x24,
	0xC1, 0x58, 0x5E, 0xF1,
	0x5A, 0x43, 0xD8, 0x75,
	0x00, 0x00, 0x00, 0x01, 
};

static uint8_t pt_ctr_3[32] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F, 
};

static uint8_t tv_ctr_ct_3[32] = {
	0xF0, 0x5E, 0x23, 0x1B,
	0x38, 0x94, 0x61, 0x2C,
	0x49, 0xEE, 0x00, 0x0B,
	0x80, 0x4E, 0xB2, 0xA9,
	0xB8, 0x30, 0x6B, 0x50,
	0x8F, 0x83, 0x9D, 0x6A,
	0x55, 0x30, 0x83, 0x1D,
	0x93, 0x44, 0xAF, 0x1C, 
};

static uint8_t key_ctr_4[32] = {
	0xFF, 0x7A, 0x61, 0x7C,
	0xE6, 0x91, 0x48, 0xE4,
	0xF1, 0x72, 0x6E, 0x2F,
	0x43, 0x58, 0x1D, 0xE2,
	0xAA, 0x62, 0xD9, 0xF8,
	0x05, 0x53, 0x2E, 0xDF,
	0xF1, 0xEE, 0xD6, 0x87,
	0xFB, 0x54, 0x15, 0x3D, 
};

static uint8_t iv_ctr_4[16] = {
	0x00, 0x1C, 0xC5, 0xB7,
	0x51, 0xA5, 0x1D, 0x70,
	0xA1, 0xC1, 0x11, 0x48,
	0x00, 0x00, 0x00, 0x01, 
};

static uint8_t pt_ctr_4[36] = {
	0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 
};

static uint8_t tv_ctr_ct_4[36] = {
	0xEB, 0x6C, 0x52, 0x82,
	0x1D, 0x0B, 0xBB, 0xF7,
	0xCE, 0x75, 0x94, 0x46,
	0x2A, 0xCA, 0x4F, 0xAA,
	0xB4, 0x07, 0xDF, 0x86,
	0x65, 0x69, 0xFD, 0x07,
	0xF4, 0x8C, 0xC0, 0xB5,
	0x83, 0xD6, 0x07, 0x1F,
	0x1E, 0xC0, 0xE6, 0xB8, 
};

static uint8_t key_ctr_5[32] = {
	0xFF, 0x7A, 0x61, 0x7C,
	0xE6, 0x91, 0x48, 0xE4,
	0xF1, 0x72, 0x6E, 0x2F,
	0x43, 0x58, 0x1D, 0xE2,
	0xAA, 0x62, 0xD9, 0xF8,
	0x05, 0x53, 0x2E, 0xDF,
	0xF1, 0xEE, 0xD6, 0x87,
	0xFB, 0x54, 0x15, 0x3D, 
};

static uint8_t iv_ctr_5[16] = {
	0x00, 0x1C, 0xC5, 0xB7,
	0x51, 0xA5, 0x1D, 0x70,
	0xA1, 0xC1, 0x11, 0x48,
	0x00, 0x00, 0x00, 0x01, 
};

static uint8_t pt_ctr_5[0] = {};

static uint8_t tv_ctr_ct_5[0] = {};

static uint8_t key_gcm_1[32] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
};
static uint8_t iv_gcm_1[16] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 
};
static uint8_t pt_gcm_1[0] = {};
static uint8_t tv_gcm_ct_1[0] = {};
static uint8_t aad_gcm_1[0] = {};
static uint8_t tv_gcm_tag_1[16] = {
	0x53, 0x0F, 0x8A, 0xFB,
	0xC7, 0x45, 0x36, 0xB9,
	0xA9, 0x63, 0xB4, 0xF1,
	0xC4, 0xCB, 0x73, 0x8B, 
};

static uint8_t key_gcm_2[32] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
};
static uint8_t iv_gcm_2[16] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 
};
static uint8_t pt_gcm_2[16] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 
};
static uint8_t tv_gcm_ct_2[16] = {
	0xCE, 0xA7, 0x40, 0x3D,
	0x4D, 0x60, 0x6B, 0x6E,
	0x07, 0x4E, 0xC5, 0xD3,
	0xBA, 0xF3, 0x9D, 0x18, 
};
static uint8_t aad_gcm_2[0] = {};
static uint8_t tv_gcm_tag_2[16] = {
	0xD0, 0xD1, 0xC8, 0xA7,
	0x99, 0x99, 0x6B, 0xF0,
	0x26, 0x5B, 0x98, 0xB5,
	0xD4, 0x8A, 0xB9, 0x19, 
};

static uint8_t key_gcm_3[32] = {
	0xFE, 0xFF, 0xE9, 0x92,
	0x86, 0x65, 0x73, 0x1C,
	0x6D, 0x6A, 0x8F, 0x94,
	0x67, 0x30, 0x83, 0x08,
	0xFE, 0xFF, 0xE9, 0x92,
	0x86, 0x65, 0x73, 0x1C,
	0x6D, 0x6A, 0x8F, 0x94,
	0x67, 0x30, 0x83, 0x08, 
};
static uint8_t iv_gcm_3[16] = {
	0xCA, 0xFE, 0xBA, 0xBE,
	0xFA, 0xCE, 0xDB, 0xAD,
	0xDE, 0xCA, 0xF8, 0x88, 
	0x00, 0x00, 0x00, 0x00, 
};
static uint8_t pt_gcm_3[64] = {
	0xD9, 0x31, 0x32, 0x25,
	0xF8, 0x84, 0x06, 0xE5,
	0xA5, 0x59, 0x09, 0xC5,
	0xAF, 0xF5, 0x26, 0x9A,
	0x86, 0xA7, 0xA9, 0x53,
	0x15, 0x34, 0xF7, 0xDA,
	0x2E, 0x4C, 0x30, 0x3D,
	0x8A, 0x31, 0x8A, 0x72,
	0x1C, 0x3C, 0x0C, 0x95,
	0x95, 0x68, 0x09, 0x53,
	0x2F, 0xCF, 0x0E, 0x24,
	0x49, 0xA6, 0xB5, 0x25,
	0xB1, 0x6A, 0xED, 0xF5,
	0xAA, 0x0D, 0xE6, 0x57,
	0xBA, 0x63, 0x7B, 0x39,
	0x1A, 0xAF, 0xD2, 0x55, 
};
static uint8_t tv_gcm_ct_3[64] = {
	0x52, 0x2D, 0xC1, 0xF0,
	0x99, 0x56, 0x7D, 0x07,
	0xF4, 0x7F, 0x37, 0xA3,
	0x2A, 0x84, 0x42, 0x7D,
	0x64, 0x3A, 0x8C, 0xDC,
	0xBF, 0xE5, 0xC0, 0xC9,
	0x75, 0x98, 0xA2, 0xBD,
	0x25, 0x55, 0xD1, 0xAA,
	0x8C, 0xB0, 0x8E, 0x48,
	0x59, 0x0D, 0xBB, 0x3D,
	0xA7, 0xB0, 0x8B, 0x10,
	0x56, 0x82, 0x88, 0x38,
	0xC5, 0xF6, 0x1E, 0x63,
	0x93, 0xBA, 0x7A, 0x0A,
	0xBC, 0xC9, 0xF6, 0x62,
	0x89, 0x80, 0x15, 0xAD,
};
static uint8_t aad_gcm_3[0] = {};
static uint8_t tv_gcm_tag_3[16] = {
	0xB0, 0x94, 0xDA, 0xC5,
	0xD9, 0x34, 0x71, 0xBD,
	0xEC, 0x1A, 0x50, 0x22,
	0x70, 0xE3, 0xCC, 0x6C, 
};

static uint8_t key_gcm_4[32] = {
	0xFE, 0xFF, 0xE9, 0x92,
	0x86, 0x65, 0x73, 0x1C,
	0x6D, 0x6A, 0x8F, 0x94,
	0x67, 0x30, 0x83, 0x08,
	0xFE, 0xFF, 0xE9, 0x92,
	0x86, 0x65, 0x73, 0x1C,
	0x6D, 0x6A, 0x8F, 0x94,
	0x67, 0x30, 0x83, 0x08, 
};
static uint8_t iv_gcm_4[16] = {
	0xCA, 0xFE, 0xBA, 0xBE,
	0xFA, 0xCE, 0xDB, 0xAD,
	0xDE, 0xCA, 0xF8, 0x88, 
	0x00, 0x00, 0x00, 0x00,
};
static uint8_t pt_gcm_4[60] = {
	0xD9, 0x31, 0x32, 0x25,
	0xF8, 0x84, 0x06, 0xE5,
	0xA5, 0x59, 0x09, 0xC5,
	0xAF, 0xF5, 0x26, 0x9A,
	0x86, 0xA7, 0xA9, 0x53,
	0x15, 0x34, 0xF7, 0xDA,
	0x2E, 0x4C, 0x30, 0x3D,
	0x8A, 0x31, 0x8A, 0x72,
	0x1C, 0x3C, 0x0C, 0x95,
	0x95, 0x68, 0x09, 0x53,
	0x2F, 0xCF, 0x0E, 0x24,
	0x49, 0xA6, 0xB5, 0x25,
	0xB1, 0x6A, 0xED, 0xF5,
	0xAA, 0x0D, 0xE6, 0x57,
	0xBA, 0x63, 0x7B, 0x39, 
};
static uint8_t tv_gcm_ct_4[60] = {
	0x52, 0x2D, 0xC1, 0xF0,
	0x99, 0x56, 0x7D, 0x07,
	0xF4, 0x7F, 0x37, 0xA3,
	0x2A, 0x84, 0x42, 0x7D,
	0x64, 0x3A, 0x8C, 0xDC,
	0xBF, 0xE5, 0xC0, 0xC9,
	0x75, 0x98, 0xA2, 0xBD,
	0x25, 0x55, 0xD1, 0xAA,
	0x8C, 0xB0, 0x8E, 0x48,
	0x59, 0x0D, 0xBB, 0x3D,
	0xA7, 0xB0, 0x8B, 0x10,
	0x56, 0x82, 0x88, 0x38,
	0xC5, 0xF6, 0x1E, 0x63,
	0x93, 0xBA, 0x7A, 0x0A,
	0xBC, 0xC9, 0xF6, 0x62, 
};
static uint8_t aad_gcm_4[20] = {
	0xFE, 0xED, 0xFA, 0xCE,
	0xDE, 0xAD, 0xBE, 0xEF,
	0xFE, 0xED, 0xFA, 0xCE,
	0xDE, 0xAD, 0xBE, 0xEF,
	0xAB, 0xAD, 0xDA, 0xD2, 
};
static uint8_t tv_gcm_tag_4[16] = {
	0x76, 0xFC, 0x6E, 0xCE,
	0x0F, 0x4E, 0x17, 0x68,
	0xCD, 0xDF, 0x88, 0x53,
	0xBB, 0x2D, 0x55, 0x1B, 
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

	if (!ctr_test(1, 1, 1, iv_ctr_1, key_ctr_1, pt_ctr_1, 16, tv_ctr_ct_1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(2, 2, 2, iv_ctr_2, key_ctr_2, pt_ctr_2, 0, tv_ctr_ct_2)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(3, 3, 3, iv_ctr_3, key_ctr_3, pt_ctr_3, 32, tv_ctr_ct_3)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(4, 4, 4, iv_ctr_4, key_ctr_4, pt_ctr_4, 36, tv_ctr_ct_4)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!ctr_test(5, 5, 5, iv_ctr_5, key_ctr_5, pt_ctr_5, 0, tv_ctr_ct_5)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(1, 1, 1, 1, iv_gcm_1, key_gcm_1, aad_gcm_1, 0, pt_gcm_1,
				0, tv_gcm_ct_1, tv_gcm_tag_1)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(2, 2, 2, 2, iv_gcm_2, key_gcm_2, aad_gcm_2, 0, pt_gcm_2,
				16, tv_gcm_ct_2, tv_gcm_tag_2)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(3, 3, 3, 3, iv_gcm_3, key_gcm_3, aad_gcm_3, 0, pt_gcm_3,
				64, tv_gcm_ct_3, tv_gcm_tag_3)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	if (!gcm_test(4, 4, 4, 4, iv_gcm_4, key_gcm_4, aad_gcm_4, 20, pt_gcm_4,
				60, tv_gcm_ct_4, tv_gcm_tag_4)) {
		FURI_LOG_I(APPLICATION_NAME, "Error, terminating...");
		return 0;
	}

	FURI_LOG_I(APPLICATION_NAME, "Terminating...");

	return 0;
}
