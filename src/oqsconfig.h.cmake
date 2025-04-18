// SPDX-License-Identifier: MIT

#cmakedefine OQS_VERSION_TEXT "@OQS_VERSION_TEXT@"
#cmakedefine OQS_COMPILE_BUILD_TARGET "@OQS_COMPILE_BUILD_TARGET@"
#cmakedefine OQS_DIST_BUILD 1
#cmakedefine OQS_DIST_X86_64_BUILD 1
#cmakedefine OQS_DIST_X86_BUILD 1
#cmakedefine OQS_DIST_ARM64v8_BUILD 1
#cmakedefine OQS_DIST_ARM32v7_BUILD 1
#cmakedefine OQS_DIST_PPC64LE_BUILD 1
#cmakedefine OQS_DEBUG_BUILD 1
#cmakedefine ARCH_X86_64 1
#cmakedefine ARCH_ARM64v8 1
#cmakedefine ARCH_ARM32v7 1

#cmakedefine OQS_USE_OPENSSL 1
#cmakedefine OQS_USE_AES_OPENSSL 1
#cmakedefine OQS_USE_SHA2_OPENSSL 1
#cmakedefine OQS_USE_SHA3_OPENSSL 1

#cmakedefine OQS_USE_PTHREADS_IN_TESTS 1

#cmakedefine OQS_USE_ADX_INSTRUCTIONS 1
#cmakedefine OQS_USE_AES_INSTRUCTIONS 1
#cmakedefine OQS_USE_AVX_INSTRUCTIONS 1
#cmakedefine OQS_USE_AVX2_INSTRUCTIONS 1
#cmakedefine OQS_USE_AVX512_INSTRUCTIONS 1
#cmakedefine OQS_USE_BMI1_INSTRUCTIONS 1
#cmakedefine OQS_USE_BMI2_INSTRUCTIONS 1
#cmakedefine OQS_USE_PCLMULQDQ_INSTRUCTIONS 1
#cmakedefine OQS_USE_VPCLMULQDQ_INSTRUCTIONS 1
#cmakedefine OQS_USE_POPCNT_INSTRUCTIONS 1
#cmakedefine OQS_USE_SSE_INSTRUCTIONS 1
#cmakedefine OQS_USE_SSE2_INSTRUCTIONS 1
#cmakedefine OQS_USE_SSE3_INSTRUCTIONS 1

#cmakedefine OQS_USE_ARM_AES_INSTRUCTIONS 1
#cmakedefine OQS_USE_ARM_SHA2_INSTRUCTIONS 1
#cmakedefine OQS_USE_ARM_SHA3_INSTRUCTIONS 1
#cmakedefine OQS_USE_ARM_NEON_INSTRUCTIONS 1

#cmakedefine OQS_ENABLE_TEST_CONSTANT_TIME 1

#cmakedefine OQS_ENABLE_SHA3_xkcp_low_avx2 1

#cmakedefine OQS_ENABLE_KEM_BIKE 1
#cmakedefine OQS_ENABLE_KEM_bike_l1 1
#cmakedefine OQS_ENABLE_KEM_bike_l3 1

#cmakedefine OQS_ENABLE_KEM_FRODOKEM 1
#cmakedefine OQS_ENABLE_KEM_frodokem_640_aes 1
#cmakedefine OQS_ENABLE_KEM_frodokem_640_shake 1
#cmakedefine OQS_ENABLE_KEM_frodokem_976_aes 1
#cmakedefine OQS_ENABLE_KEM_frodokem_976_shake 1
#cmakedefine OQS_ENABLE_KEM_frodokem_1344_aes 1
#cmakedefine OQS_ENABLE_KEM_frodokem_1344_shake 1

#cmakedefine OQS_ENABLE_KEM_SIDH 1
#cmakedefine OQS_ENABLE_KEM_sidh_p434 1
#cmakedefine OQS_ENABLE_KEM_sidh_p434_compressed 1
#cmakedefine OQS_ENABLE_KEM_sidh_p503 1
#cmakedefine OQS_ENABLE_KEM_sidh_p503_compressed 1
#cmakedefine OQS_ENABLE_KEM_sidh_p610 1
#cmakedefine OQS_ENABLE_KEM_sidh_p610_compressed 1
#cmakedefine OQS_ENABLE_KEM_sidh_p751 1
#cmakedefine OQS_ENABLE_KEM_sidh_p751_compressed 1

#cmakedefine OQS_ENABLE_KEM_SIKE 1
#cmakedefine OQS_ENABLE_KEM_sike_p434 1
#cmakedefine OQS_ENABLE_KEM_sike_p434_compressed 1
#cmakedefine OQS_ENABLE_KEM_sike_p503 1
#cmakedefine OQS_ENABLE_KEM_sike_p503_compressed 1
#cmakedefine OQS_ENABLE_KEM_sike_p610 1
#cmakedefine OQS_ENABLE_KEM_sike_p610_compressed 1
#cmakedefine OQS_ENABLE_KEM_sike_p751 1
#cmakedefine OQS_ENABLE_KEM_sike_p751_compressed 1

#cmakedefine OQS_ENABLE_SIG_PICNIC 1
#cmakedefine OQS_ENABLE_SIG_picnic_L1_UR 1
#cmakedefine OQS_ENABLE_SIG_picnic_L1_FS 1
#cmakedefine OQS_ENABLE_SIG_picnic_L1_full 1
#cmakedefine OQS_ENABLE_SIG_picnic_L3_UR 1
#cmakedefine OQS_ENABLE_SIG_picnic_L3_FS 1
#cmakedefine OQS_ENABLE_SIG_picnic_L3_full 1
#cmakedefine OQS_ENABLE_SIG_picnic_L5_UR 1
#cmakedefine OQS_ENABLE_SIG_picnic_L5_FS 1
#cmakedefine OQS_ENABLE_SIG_picnic_L5_full 1
#cmakedefine OQS_ENABLE_SIG_picnic3_L1 1
#cmakedefine OQS_ENABLE_SIG_picnic3_L3 1
#cmakedefine OQS_ENABLE_SIG_picnic3_L5 1

///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ADD_ALG_ENABLE_DEFINES_START

#cmakedefine OQS_ENABLE_KEM_CLASSIC_MCELIECE 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_348864 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_348864_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_348864f 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_348864f_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_460896 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_460896_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_460896f 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_460896f_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6688128 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6688128_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6688128f 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6688128f_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6960119 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6960119_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6960119f 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_6960119f_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_8192128 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_8192128_avx 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_8192128f 1
#cmakedefine OQS_ENABLE_KEM_classic_mceliece_8192128f_avx 1

#cmakedefine OQS_ENABLE_KEM_HQC 1
#cmakedefine OQS_ENABLE_KEM_hqc_128 1
#cmakedefine OQS_ENABLE_KEM_hqc_128_avx2 1
#cmakedefine OQS_ENABLE_KEM_hqc_192 1
#cmakedefine OQS_ENABLE_KEM_hqc_192_avx2 1
#cmakedefine OQS_ENABLE_KEM_hqc_256 1
#cmakedefine OQS_ENABLE_KEM_hqc_256_avx2 1

#cmakedefine OQS_ENABLE_KEM_KYBER 1
#cmakedefine OQS_ENABLE_KEM_kyber_512 1
#cmakedefine OQS_ENABLE_KEM_kyber_512_avx2 1
#cmakedefine OQS_ENABLE_KEM_kyber_768 1
#cmakedefine OQS_ENABLE_KEM_kyber_768_avx2 1
#cmakedefine OQS_ENABLE_KEM_kyber_1024 1
#cmakedefine OQS_ENABLE_KEM_kyber_1024_avx2 1
#cmakedefine OQS_ENABLE_KEM_kyber_512_90s 1
#cmakedefine OQS_ENABLE_KEM_kyber_512_90s_avx2 1
#cmakedefine OQS_ENABLE_KEM_kyber_768_90s 1
#cmakedefine OQS_ENABLE_KEM_kyber_768_90s_avx2 1
#cmakedefine OQS_ENABLE_KEM_kyber_1024_90s 1
#cmakedefine OQS_ENABLE_KEM_kyber_1024_90s_avx2 1

#cmakedefine OQS_ENABLE_KEM_NTRU 1
#cmakedefine OQS_ENABLE_KEM_ntru_hps2048509 1
#cmakedefine OQS_ENABLE_KEM_ntru_hps2048509_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntru_hps2048677 1
#cmakedefine OQS_ENABLE_KEM_ntru_hps2048677_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntru_hps4096821 1
#cmakedefine OQS_ENABLE_KEM_ntru_hps4096821_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntru_hrss701 1
#cmakedefine OQS_ENABLE_KEM_ntru_hrss701_avx2 1

#cmakedefine OQS_ENABLE_KEM_NTRUPRIME 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_ntrulpr653 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_ntrulpr653_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_ntrulpr761 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_ntrulpr761_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_ntrulpr857 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_ntrulpr857_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_sntrup653 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_sntrup653_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_sntrup761 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_sntrup761_avx2 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_sntrup857 1
#cmakedefine OQS_ENABLE_KEM_ntruprime_sntrup857_avx2 1

#cmakedefine OQS_ENABLE_KEM_SABER 1
#cmakedefine OQS_ENABLE_KEM_saber_lightsaber 1
#cmakedefine OQS_ENABLE_KEM_saber_lightsaber_avx2 1
#cmakedefine OQS_ENABLE_KEM_saber_saber 1
#cmakedefine OQS_ENABLE_KEM_saber_saber_avx2 1
#cmakedefine OQS_ENABLE_KEM_saber_firesaber 1
#cmakedefine OQS_ENABLE_KEM_saber_firesaber_avx2 1

#cmakedefine OQS_ENABLE_SIG_DILITHIUM 1
#cmakedefine OQS_ENABLE_SIG_dilithium_2 1
#cmakedefine OQS_ENABLE_SIG_dilithium_2_avx2 1
#cmakedefine OQS_ENABLE_SIG_dilithium_3 1
#cmakedefine OQS_ENABLE_SIG_dilithium_3_avx2 1
#cmakedefine OQS_ENABLE_SIG_dilithium_5 1
#cmakedefine OQS_ENABLE_SIG_dilithium_5_avx2 1
#cmakedefine OQS_ENABLE_SIG_dilithium_2_aes 1
#cmakedefine OQS_ENABLE_SIG_dilithium_2_aes_avx2 1
#cmakedefine OQS_ENABLE_SIG_dilithium_3_aes 1
#cmakedefine OQS_ENABLE_SIG_dilithium_3_aes_avx2 1
#cmakedefine OQS_ENABLE_SIG_dilithium_5_aes 1
#cmakedefine OQS_ENABLE_SIG_dilithium_5_aes_avx2 1

#cmakedefine OQS_ENABLE_SIG_FALCON 1
#cmakedefine OQS_ENABLE_SIG_falcon_512 1
#cmakedefine OQS_ENABLE_SIG_falcon_512_avx2 1
#cmakedefine OQS_ENABLE_SIG_falcon_1024 1
#cmakedefine OQS_ENABLE_SIG_falcon_1024_avx2 1

#cmakedefine OQS_ENABLE_SIG_RAINBOW 1
#cmakedefine OQS_ENABLE_SIG_rainbow_I_classic 1
#cmakedefine OQS_ENABLE_SIG_rainbow_I_circumzenithal 1
#cmakedefine OQS_ENABLE_SIG_rainbow_I_compressed 1
#cmakedefine OQS_ENABLE_SIG_rainbow_III_classic 1
#cmakedefine OQS_ENABLE_SIG_rainbow_III_circumzenithal 1
#cmakedefine OQS_ENABLE_SIG_rainbow_III_compressed 1
#cmakedefine OQS_ENABLE_SIG_rainbow_V_classic 1
#cmakedefine OQS_ENABLE_SIG_rainbow_V_circumzenithal 1
#cmakedefine OQS_ENABLE_SIG_rainbow_V_compressed 1

#cmakedefine OQS_ENABLE_SIG_SPHINCS 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128f_robust_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128f_simple_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128s_robust_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_128s_simple_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192f_robust_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192f_simple_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192s_robust_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_192s_simple_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256f_robust_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256f_simple_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256s_robust_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_haraka_256s_simple_aesni 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128f_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128f_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128s_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_128s_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192f_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192f_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192s_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_192s_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256f_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256f_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256s_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_sha256_256s_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128f_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128f_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128s_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_128s_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192f_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192f_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192s_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_192s_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256f_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256f_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256f_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256f_simple_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256s_robust 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256s_robust_avx2 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256s_simple 1
#cmakedefine OQS_ENABLE_SIG_sphincs_shake256_256s_simple_avx2 1
///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ADD_ALG_ENABLE_DEFINES_END
