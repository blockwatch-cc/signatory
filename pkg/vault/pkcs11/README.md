# PKCS#11 vault

## Configuration

| Name        | Type         | Env                 | Description                                              |
| ----------- | ------------ | --------------------|--------------------------------------------------------- |
| path        | string       | PKCS11_LIBRARY_PATH | Path of the HSM wrapper dynamic library to load.         |
| slot        | string       | PKCS11_SLOT         | Optional HSM slot number as hexadecimal string to identify the device.      |                                               |
| label       | string       | PKCS11_LABEL        | Optional HSM slot label to identify the device. (use either slot or label). |
| pin         | string       | PKCS11_PIN          | User PIN to unlock the HSM token in the selected slot.                      |


### Example

```yaml
vaults:
  softhsm:
    driver: pkcs11
    config:
      # See backend specific documentation
      path: /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
      slot: 0x7bae4f1f
      pin: 98765432
      label: test
```

## Dependencies and Compiling

This vault uses the popular PKCS#11 Golang library [github.com/miekg/pkcs11](https://github.com/miekg/pkcs11) and
requires version 3 for all ket types to work. Unfortunately the Go (mod) toolchain cannot work
with branches, so we reference the library at a recent Git commit `721e3fc6d90`. To update run

```sh
go get -u github.com/miekg/pkcs11@{git-sha1}
```

This Go library loads a PKCS#11 HSM's dynamic C library and wraps all calls using CGO. For this 
reason it is necessary to build `signatory` with `CGO_ENABLED=1` (default in Go, but disabled by 
the Signatory Makefile). Another caveat about the Go toolchain is that CGO may not be able to
find C headers or sources when run in vendor mode. For this reason compile with

```sh
go build -mod=mod ./cmd/signatory
```

On OSX (12.2) this produces a deprecation warning 

```
warning: 'kIOMasterPortDefault' is deprecated: first deprecated in macOS 12.0
```

but its still safe to assume OSX will not immediatly break compatibility. The source is
USB support from [github.com/karalabe/hid](https://github.com/karalabe/hid).


## Supported key types and signature schemes

- [x] `ed25519` (tz1) Edwards
- [x] `secp256k1` (tz2) ECDSA
- [x] `p256` (tz3) ECDSA


## Using SoftHSM2

To test functionality its possible to use a software emulation of a HSM provided by OpenSC.


1. On OSX, first install

```sh
brew install softhsm opensc
```

2. Then initialize your first token (tokens are Smart Cards a.k.a HSM's in OpenSC terminology).

```sh
softhsm2-util --init-token --slot 0 --label "test" --so-pin 1234 --pin 98765432
```

3. Setup environment variables (or add to `signatory.yaml`)

```sh
export PKCS11_LIBRARY_PATH="/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"
export PKCS11_PIN=98765432
export PKCS11_LABEL="test"
```

4. Generate Keypairs

```sh
# tz1 - ed25519
pkcs11-tool --module "$PKCS11_LIBRARY_PATH" --login --pin "$PKCS11_PIN" --keypairgen --mechanism EC-EDWARDS-KEY-PAIR-GEN --key-type EC:edwards25519 --usage-sign --label ed-key --id 0

# tz2 - secp256k1
pkcs11-tool --module "$PKCS11_LIBRARY_PATH" --login --pin "$PKCS11_PIN" --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp256k1 --usage-sign --label secp-key --id 1

# tz3 - p256
pkcs11-tool --module "$PKCS11_LIBRARY_PATH" --login --pin "$PKCS11_PIN" --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:prime256v1 --usage-sign --label p256-key --id 2
```

5. Test signing works

```sh
pkcs11-tool --module "$PKCS11_LIBRARY_PATH" --login --pin "$PKCS11_PIN" --sign --mechanism ECDSA -i README.md
```

6. PKCS#11 Cheatsheet
```sh
# list available slots
pkcs11-tool --module "$PKCS11_LIBRARY_PATH" -L

# list available objects (e.g. private keys)
pkcs11-tool --module "$PKCS11_LIBRARY_PATH" -O
```