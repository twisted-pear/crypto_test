# Tests for Flipper Zero's advanced crypto functions

This plugin runs several tests on the new functions I added to the Flipper
Zero's crypto engine.

The modified firmware can be found here:
https://github.com/twisted-pear/flipperzero-crypto-firmware/tree/crypto_enhancements

The test vectors for CTR mode were generated using openssl thusly:

```
printf "<input as escaped hex>" | openssl enc -aes-256-ctr -e -K '<key as hex string>' -iv '<iv and counter starting at 1 as hex string>' | xxd -ps -c 16
```

Example:

```
printf "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"| openssl enc -aes-256-ctr -e -K '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' -iv 'c0fed00dc0fed00dc0fed00d00000001' | xxd -ps -c 16
```

The test vectors for GCM mode were generated using Markus Kosmal's AES-GCM
code, which can be found here: https://github.com/mko-x/SharedAES-GCM
