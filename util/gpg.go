package util

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

// A parsedMPI is used to store the contents of a big integer, along with the
// bit length that was specified in the original input. This allows the MPI to
// be reserialized exactly.
type parsedMPI struct {
	bytes     []byte
	bitLength uint16
}

func hashToHashID(h crypto.Hash) uint8 {
	v, ok := s2k.HashToHashId(h)
	if !ok {
		panic("tried to convert unknown hash")
	}
	return v
}

func fromBig(n *big.Int) parsedMPI {
	return parsedMPI{
		bytes:     n.Bytes(),
		bitLength: uint16(n.BitLen()),
	}
}

// NewRSAPublicKey returns a PublicKey that wraps the given rsa.PublicKey.
func newCryptoSignerRSAPublicKey(creationTime time.Time, pub *rsa.PublicKey) *packet.PublicKey {
	pk := &packet.PublicKey{
		CreationTime: creationTime,
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		PublicKey:    pub,
		n:            fromBig(pub.N),
		e:            fromBig(big.NewInt(int64(pub.E))),
	}

	pk.setFingerPrintAndKeyId()
	return pk
}

func newCryptoSignerRSAPrivateKey(currentTime time.Time, priv *crypto.Signer) *packet.PrivateKey {
	pk := new(packet.PrivateKey)
	pk.PublicKey = *NewRSAPublicKey(currentTime, &priv.PublicKey)
	pk.PrivateKey = priv
	return pk
}

// NewEntityFromRSABits returns an Entity that uses the provided keypair
// it is given.
func NewEntityFromRSASigner(uid *packet.UserId, signingPriv *crypto.Signer, config *packet.Config) (*openpgp.Entity, error) {
	currentTime := config.Now()

	// default bits from openpgp
	bits := 2048
	if config != nil && config.RSABits != 0 {
		bits = config.RSABits
	}

	signingPriv, err := rsa.GenerateKey(config.Random(), bits)
	if err != nil {
		return nil, err
	}
	encryptingPriv, err := rsa.GenerateKey(config.Random(), bits)
	if err != nil {
		return nil, err
	}

	e := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(currentTime, signingPriv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(currentTime, &signingPriv),
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryID := true
	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryID,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}
	err = e.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, e.PrimaryKey, e.PrivateKey, config)
	if err != nil {
		return nil, err
	}

	// If the user passes in a DefaultHash via packet.Config,
	// set the PreferredHash for the SelfSignature.
	if config != nil && config.DefaultHash != 0 {
		e.Identities[uid.Id].SelfSignature.PreferredHash = []uint8{hashToHashID(config.DefaultHash)}
	}

	// Likewise for DefaultCipher.
	if config != nil && config.DefaultCipher != 0 {
		e.Identities[uid.Id].SelfSignature.PreferredSymmetric = []uint8{uint8(config.DefaultCipher)}
	}

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(currentTime, &encryptingPriv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(currentTime, encryptingPriv),
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
		},
	}
	e.Subkeys[0].PublicKey.IsSubkey = true
	e.Subkeys[0].PrivateKey.IsSubkey = true
	err = e.Subkeys[0].Sig.SignKey(e.Subkeys[0].PublicKey, e.PrivateKey, config)
	if err != nil {
		return nil, err
	}
	return e, nil
}
