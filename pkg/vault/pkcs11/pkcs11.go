package pkcs11

import (
    "bytes"
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "encoding/asn1"
    "encoding/hex"
    "fmt"
    "math/big"
    "os"
    "strconv"

    "github.com/ecadlabs/signatory/pkg/config"
    "github.com/ecadlabs/signatory/pkg/cryptoutils"
    "github.com/ecadlabs/signatory/pkg/errors"
    "github.com/ecadlabs/signatory/pkg/tezos"
    "github.com/ecadlabs/signatory/pkg/utils"
    "github.com/ecadlabs/signatory/pkg/vault"
    "github.com/miekg/pkcs11"
    log "github.com/sirupsen/logrus"
    "gopkg.in/yaml.v3"
)

const (
    envLibraryPath = "PKCS11_LIBRARY_PATH"
    envPin         = "PKCS11_PIN"
    envSlot        = "PKCS11_SLOT"
    envLabel       = "PKCS11_LABEL"
)

var (
    // ed25519KeyParams   = mustMarshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1159, 15, 1})
    ed25519KeyParams   = mustMarshal("edwards25519")
    secp256k1KeyParams = mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
    prime256KeyParams  = mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
)

// ASN.1 marshal some value and panic on error
func mustMarshal(val interface{}) []byte {
    if b, err := asn1.Marshal(val); err != nil {
        panic(err)
    } else {
        return b
    }
}

// Config contains PKCS11 backend configuration
type Config struct {
    Path  string `yaml:"path"`
    Slot  uint32 `yaml:"slot"`
    Label string `yaml:"label"`
    Pin   string `yaml:"pin"`
}

func (c *Config) id() string {
    return fmt.Sprintf("pkcs11:token=%s;slot-id=%08x", c.Label, c.Slot)
}

type hsmKey struct {
    id    uint8
    label string
    pub   crypto.PublicKey
    curve elliptic.Curve
}

func (h *hsmKey) PublicKey() crypto.PublicKey { return h.pub }
func (h *hsmKey) ID() string                  { return fmt.Sprintf("%x", h.id) }

// HSM struct containing information required to interrogate a YubiHSM
type HSM struct {
    session pkcs11.SessionHandle
    context *pkcs11.Ctx
    keys    []*hsmKey
    conf    Config
}

// Name returns backend name
func (h *HSM) Name() string {
    info, err := h.context.GetInfo()
    if err != nil {
        return ""
    }
    return "PKCS#11:" + info.ManufacturerID
}

// VaultName returns vault name
func (h *HSM) VaultName() string {
    return h.conf.id()
}

type pkcs11StoredKeysIterator struct {
    keys []*hsmKey
    idx  int
}

func (i *pkcs11StoredKeysIterator) Next() (key vault.StoredKey, err error) {
    if i.idx == len(i.keys) {
        return nil, vault.ErrDone
    }
    key = i.keys[i.idx]
    i.idx++
    return
}

// ListPublicKeys list all public key from connected PCKS#11 HSM
func (h *HSM) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
    return &pkcs11StoredKeysIterator{
        keys: h.keys,
        idx:  0,
    }
}

func parsePublicKey(attrs []*pkcs11.Attribute) (crypto.PublicKey, error) {
    if len(attrs) != 2 {
        return nil, fmt.Errorf("invalid key attribute length %d", len(attrs))
    }

    var buf []byte
    extra, err := asn1.Unmarshal(attrs[1].Value, &buf)
    if err != nil {
        return nil, fmt.Errorf("elliptic curve point is invalid ASN.1: %v", err)
    }
    if len(extra) > 0 {
        return nil, fmt.Errorf("unexpected data found when parsing elliptic curve point")
    }

    switch {
    case bytes.Compare(attrs[0].Value, ed25519KeyParams) == 0:
        return ed25519.PublicKey(buf), nil

    case bytes.Compare(attrs[0].Value, secp256k1KeyParams) == 0:
        x, y := elliptic.Unmarshal(cryptoutils.S256(), buf)
        return &ecdsa.PublicKey{
            Curve: cryptoutils.S256(),
            X:     x,
            Y:     y,
        }, nil

    case bytes.Compare(attrs[0].Value, prime256KeyParams) == 0:
        x, y := elliptic.Unmarshal(elliptic.P256(), buf)
        return &ecdsa.PublicKey{
            Curve: elliptic.P256(),
            X:     x,
            Y:     y,
        }, nil

    default:
        return nil, fmt.Errorf("unsupported key type %s", hex.EncodeToString(attrs[0].Value))
    }
}

func listPublicKeys(ctx context.Context, p *pkcs11.Ctx, session pkcs11.SessionHandle) ([]*hsmKey, error) {
    err := p.FindObjectsInit(session, []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
    })
    if err != nil {
        return nil, fmt.Errorf("init pubkey scan: %v", err)
    }
    handles, _, err := p.FindObjects(session, 256)
    if err != nil {
        return nil, fmt.Errorf("scanning pubkeys: %v", err)

    }
    if err := p.FindObjectsFinal(session); err != nil {
        return nil, fmt.Errorf("finalizing pubkey scan: %v", err)
    }

    keys := make([]*hsmKey, 0)
    for i, v := range handles {
        attrs, err := p.GetAttributeValue(session, v, []*pkcs11.Attribute{
            pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
            pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
            pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
            pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
        })
        if err != nil {
            return nil, fmt.Errorf("reading attributes for pubkey %d: %v", i, err)
        }

        pk, err := parsePublicKey(attrs[2:])
        if err != nil {
            return nil, fmt.Errorf("parsing pubkey %d (%x): %v", i, attrs[0].Value[0], err)
        }

        addr, _ := tezos.EncodePublicKeyHash(pk)
        log.Debugf("(PKCS#11): Found key #%d id=%x label=%q addr=%q",
            i,
            uint8(attrs[0].Value[0]),
            string(attrs[1].Value),
            addr,
        )

        var curve elliptic.Curve
        if k, ok := pk.(*ecdsa.PublicKey); ok {
            curve = k.Curve
        }

        keys = append(keys, &hsmKey{
            id:    uint8(attrs[0].Value[0]),
            label: string(attrs[1].Value),
            pub:   pk,
            curve: curve,
        })
    }
    return keys, nil
}

// GetPublicKey returns a public key by given ID
func (h *HSM) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
    id, err := strconv.ParseUint(keyID, 16, 8)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): %v", h.conf.id(), err)
    }

    publicKeyTemplate := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
        pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{uint8(id)}),
    }

    err = h.context.FindObjectsInit(h.session, publicKeyTemplate)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find pubkey: %v", h.conf.id(), err)
    }
    handles, _, err := h.context.FindObjects(h.session, 1)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find pubkey: %v", h.conf.id(), err)
    }
    if err := h.context.FindObjectsFinal(h.session); err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find pubkey: %v", h.conf.id(), err)
    }

    attrs, err := h.context.GetAttributeValue(h.session, handles[0], []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
        pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
        pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
        pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
    })
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): reading pubkey attributes: %v", h.conf.id(), err)
    }

    pk, err := parsePublicKey(attrs[2:])
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): parsing pubkey %x: %v", h.conf.id(), attrs[0].Value[0], err)
    }

    var curve elliptic.Curve
    if k, ok := pk.(*ecdsa.PublicKey); ok {
        curve = k.Curve
    }

    return &hsmKey{
        id:    uint8(attrs[0].Value[0]),
        label: string(attrs[1].Value),
        pub:   pk,
        curve: curve,
    }, nil
}

func (h *HSM) signECDSA(digest []byte, key *hsmKey) (*cryptoutils.ECDSASignature, error) {
    err := h.context.FindObjectsInit(h.session, []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
        pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{key.id}),
    })
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find privkey %x %q: %v", h.conf.id(), key.id, key.label, err)
    }
    handles, _, err := h.context.FindObjects(h.session, 1)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find privkey %x %q: %v", h.conf.id(), key.id, key.label, err)
    }
    if err = h.context.FindObjectsFinal(h.session); err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find privkey %x %q: %v", h.conf.id(), key.id, key.label, err)
    }

    if err = h.context.SignInit(
        h.session,
        []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
        handles[0],
    ); err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): init sign for ECDSA key %x %q: %v", h.conf.id(), key.id, key.label, err)
    }

    raw, err := h.context.Sign(h.session, digest)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): sign with ECDSA key %x %q: %v", h.conf.id(), key.id, key.label, err)
    }

    if len(raw) != 64 {
        return nil, fmt.Errorf("(PKCS#11/%s): invalid ECDSA signature length: %d", h.conf.id(), len(raw))
    }

    return &cryptoutils.ECDSASignature{
        Curve: key.curve,
        R:     new(big.Int).SetBytes(raw[:32]),
        S:     new(big.Int).SetBytes(raw[32:]),
    }, nil
}

func (h *HSM) signED25519(digest []byte, key *hsmKey) (cryptoutils.ED25519Signature, error) {
    err := h.context.FindObjectsInit(h.session, []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
        pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{key.id}),
    })
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find privatekey %x %q: %v", h.conf.id(), key.id, key.label, err)
    }
    handles, _, err := h.context.FindObjects(h.session, 1)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find privatekey %x %q: %v", h.conf.id(), key.id, key.label, err)
    }
    if err = h.context.FindObjectsFinal(h.session); err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): find privatekey %x %q: %v", h.conf.id(), key.id, key.label, err)
    }

    if err = h.context.SignInit(
        h.session,
        []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EDDSA, nil)},
        handles[0],
    ); err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): init sign with Edwards key %x %q: %v", h.conf.id(), key.id, key.label, err)
    }

    raw, err := h.context.Sign(h.session, digest)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11/%s): sign with Edwards key %x %q: %v", h.conf.id(), key.id, key.label, err)
    }

    if len(raw) != ed25519.SignatureSize {
        return nil, fmt.Errorf("(PKCS#11/%s): invalid ED25519 signature length: %d", h.conf.id(), len(raw))
    }

    return cryptoutils.ED25519Signature(raw), nil
}

// Sign performs signing operation
func (h *HSM) Sign(ctx context.Context, digest []byte, k vault.StoredKey) (sig cryptoutils.Signature, err error) {
    key, ok := k.(*hsmKey)
    if !ok {
        return nil, fmt.Errorf("(PKCS#11/%s): not a PKCS#11 key: %T", h.conf.id(), k)
    }

    switch key.pub.(type) {
    case *ecdsa.PublicKey:
        return h.signECDSA(digest, key)
    case ed25519.PublicKey:
        return h.signED25519(digest, key)
    }

    return nil, fmt.Errorf("(PKCS#11/%s): unexpected key type: %T", h.conf.id(), key.pub)
}

// Ready implements vault.ReadinessChecker
func (h *HSM) Ready(ctx context.Context) (bool, error) {
    // ensure HSM is unlocked and usable
    // - session must be valid and readable
    // - slot must be initialized and contain a token (smartcard)
    info, err := h.context.GetSessionInfo(h.session)
    if err != nil {
        return false, fmt.Errorf("(PKCS#11/%s): %v", h.conf.id(), err)
    }
    switch info.State {
    case pkcs11.CKS_RO_USER_FUNCTIONS, pkcs11.CKS_RW_USER_FUNCTIONS:
        // ok
    default:
        return false, fmt.Errorf("(PKCS#11/%s): invalid session state %d", h.conf.id(), info.State)
    }

    if info.DeviceError > 0 {
        return false, fmt.Errorf("(PKCS#11/%s): device error %d", h.conf.id(), info.DeviceError)
    }

    if _, err := h.context.GetTokenInfo(uint(h.conf.Slot)); err != nil {
        return false, fmt.Errorf("(PKCS#11/%s): reading slot: %v", h.conf.id(), err)
    }

    return true, nil
}

// Import of private keys is not implemented. Some HSMs support this feature, but its
// deemed too insecure as sensitive private key material used to be outside the HSM.
func (h *HSM) Import(_ context.Context, _ cryptoutils.PrivateKey, _ utils.Options) (vault.StoredKey, error) {
    return nil, fmt.Errorf("(PKCS#11/%s): key import not supported", h.conf.id())
}

// New creates new YubiHSM backend
func New(ctx context.Context, config *Config) (*HSM, error) {
    c := *config
    if c.Path == "" {
        c.Path = os.Getenv(envLibraryPath)
    }

    if d, err := os.Stat(c.Path); err != nil {
        if os.IsNotExist(err) {
            return nil, fmt.Errorf("(PKCS#11): library %q not found", c.Path)
        }
    } else {
        if d.Mode().IsDir() {
            return nil, fmt.Errorf("(PKCS#11): library %q is a directory", c.Path)
        }
    }

    if c.Pin == "" {
        c.Pin = os.Getenv(envPin)
    }

    if c.Slot == 0 {
        slot := os.Getenv(envSlot)
        v, err := strconv.ParseUint(slot, 16, 32)
        if err != nil {
            return nil, fmt.Errorf("(PKCS#11): reading slot %q from env: %v", slot, err)
        }
        c.Slot = uint32(v)
    }

    if c.Label == "" {
        c.Label = os.Getenv(envLabel)
    }

    p := pkcs11.New(c.Path)
    if err := p.Initialize(); err != nil {
        return nil, fmt.Errorf("(PKCS#11): opening device: %v", err)
    }

    slots, err := p.GetSlotList(true)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11): listing slots: %v", err)
    }

    if c.Label != "" {
        var (
            found     bool
            tokenInfo pkcs11.TokenInfo
        )
        for i, v := range slots {
            tokenInfo, err = p.GetTokenInfo(v)
            if err != nil {
                return nil, fmt.Errorf("(PKCS#11): reading token slot %d (%08x) info: %v", i, v, err)
            }

            if tokenInfo.Label == c.Label {
                c.Slot = uint32(v)
                found = true
                break
            }
        }
        if !found {
            return nil, fmt.Errorf("(PKCS#11): token slot %08x not found on device", c.Slot)
        }
        log.Debugf("(PKCS#11): Using slot %08x label=%s manufacturer=%s", c.Slot, c.Label, tokenInfo.ManufacturerID)
    } else {
        // fallback to slot id
        var found bool
        for _, v := range slots {
            if uint32(v) == c.Slot {
                found = true
                break
            }
        }

        if !found {
            return nil, fmt.Errorf("(PKCS#11): slot %08x not found on device", c.Slot)
        }

        tokenInfo, err := p.GetTokenInfo(uint(c.Slot))
        if err != nil {
            return nil, fmt.Errorf("(PKCS#11): reading token slot %08x info: %v", c.Slot, err)
        }
        log.Debugf("(PKCS#11): Using slot %08x label=%s manufacturer=%s", c.Slot, tokenInfo.Label, tokenInfo.ManufacturerID)
    }

    // a read-only session is sufficient for signing
    session, err := p.OpenSession(uint(c.Slot), pkcs11.CKF_SERIAL_SESSION)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11): opening session: %v", err)
    }

    if err := p.Login(session, pkcs11.CKU_USER, c.Pin); err != nil {
        return nil, fmt.Errorf("(PKCS#11): unlocking device: %v", err)
    }

    // load all keys
    keys, err := listPublicKeys(ctx, p, session)
    if err != nil {
        return nil, fmt.Errorf("(PKCS#11): %v", err)
    }

    return &HSM{
        session: session,
        context: p,
        keys:    keys,
        conf:    c,
    }, nil
}

func init() {
    vault.RegisterVault("pkcs11", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
        var conf Config
        if node == nil || node.Kind == 0 {
            return nil, errors.New("(PKCS11): config is missing")
        }
        if err := node.Decode(&conf); err != nil {
            return nil, err
        }

        if err := config.Validator().Struct(&conf); err != nil {
            return nil, err
        }

        return New(ctx, &conf)
    })
}

var _ vault.Importer = &HSM{}
