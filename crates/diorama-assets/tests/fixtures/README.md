Independent structural fixtures, not a production asset lock. The JSON manifests
declare the eight runtime executables and seven images in the diorama inventory,
including `image-diorama`. Their sizes and digests are placeholders; no corresponding
production payloads are supplied.

`abc.bin` is the standard SHA-256 `abc` vector (FIPS 180-4). Encoded verification
tests replace the bundled records' size and digest with that vector. Those bytes
are neither ELF nor gzip nor zstd: encoded matching must not imply content validation.
