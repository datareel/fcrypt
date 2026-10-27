cJSON 1.7.18, https://github.com/DaveGamble/cJSON (MIT license, see LICENSE)

Vendored unchanged from the v1.7.18 release tarball
https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz
(sha256 3aa806844a03442c00769b83e99970be70fbef03735ff898f4811dd03b9f5ee5).

  cJSON.c  sha256 75c51de8fa40ac9d7a99319c6330719bd692eb81c0a869265f3d4c682533f9b9
  cJSON.h  sha256 0578cc29132912edbc88f83207a8fc76e5db3db0605497e909a9384ef3cc474b
  LICENSE  sha256 a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c

Used by src/fckeymgmt.cpp, which includes cJSON.c so no build file
changes are needed. It parses the JSON record input of the Encrypted
Password Database; allocations go through hooks that wipe the memory
before it is freed.
