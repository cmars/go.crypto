// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"github.com/cmars/go.crypto/openpgp/armor"
	"encoding/hex"
	"testing"
	"time"
)

var pubKeyTests = []struct {
	hexData        string
	hexFingerprint string
	creationTime   time.Time
	pubKeyAlgo     PublicKeyAlgorithm
	keyId          uint64
	keyIdString    string
	keyIdShort     string
}{
	{rsaPkDataHex, rsaFingerprintHex, time.Unix(0x4d3c5c10, 0), PubKeyAlgoRSA, 0xa34d7e18c20c31bb, "A34D7E18C20C31BB", "C20C31BB"},
	{dsaPkDataHex, dsaFingerprintHex, time.Unix(0x4d432f89, 0), PubKeyAlgoDSA, 0x8e8fbe54062f19ed, "8E8FBE54062F19ED", "062F19ED"},
	{ecdsaPkDataHex, ecdsaFingerprintHex, time.Unix(0x5071c294, 0), PubKeyAlgoECDSA, 0x43fe956c542ca00b, "43FE956C542CA00B", "542CA00B"},
}

func TestPublicKeyRead(t *testing.T) {
	for i, test := range pubKeyTests {
		packet, err := Read(readerFromHex(test.hexData))
		if err != nil {
			t.Errorf("#%d: Read error: %s", i, err)
			continue
		}
		pk, ok := packet.(*PublicKey)
		if !ok {
			t.Errorf("#%d: failed to parse, got: %#v", i, packet)
			continue
		}
		if pk.PubKeyAlgo != test.pubKeyAlgo {
			t.Errorf("#%d: bad public key algorithm got:%x want:%x", i, pk.PubKeyAlgo, test.pubKeyAlgo)
		}
		if !pk.CreationTime.Equal(test.creationTime) {
			t.Errorf("#%d: bad creation time got:%v want:%v", i, pk.CreationTime, test.creationTime)
		}
		expectedFingerprint, _ := hex.DecodeString(test.hexFingerprint)
		if !bytes.Equal(expectedFingerprint, pk.Fingerprint[:]) {
			t.Errorf("#%d: bad fingerprint got:%x want:%x", i, pk.Fingerprint[:], expectedFingerprint)
		}
		if pk.KeyId != test.keyId {
			t.Errorf("#%d: bad keyid got:%x want:%x", i, pk.KeyId, test.keyId)
		}
		if g, e := pk.KeyIdString(), test.keyIdString; g != e {
			t.Errorf("#%d: bad KeyIdString got:%q want:%q", i, g, e)
		}
		if g, e := pk.KeyIdShortString(), test.keyIdShort; g != e {
			t.Errorf("#%d: bad KeyIdShortString got:%q want:%q", i, g, e)
		}
	}
}

func TestPublicKeySerialize(t *testing.T) {
	for i, test := range pubKeyTests {
		packet, err := Read(readerFromHex(test.hexData))
		if err != nil {
			t.Errorf("#%d: Read error: %s", i, err)
			continue
		}
		pk, ok := packet.(*PublicKey)
		if !ok {
			t.Errorf("#%d: failed to parse, got: %#v", i, packet)
			continue
		}
		serializeBuf := bytes.NewBuffer(nil)
		err = pk.Serialize(serializeBuf)
		if err != nil {
			t.Errorf("#%d: failed to serialize: %s", i, err)
			continue
		}

		packet, err = Read(serializeBuf)
		if err != nil {
			t.Errorf("#%d: Read error (from serialized data): %s", i, err)
			continue
		}
		pk, ok = packet.(*PublicKey)
		if !ok {
			t.Errorf("#%d: failed to parse serialized data, got: %#v", i, packet)
			continue
		}
	}
}

func TestEcc384Serialize(t *testing.T) {
	armorBlock, err := armor.Decode(bytes.NewBufferString(ecc384PubArmor))
	if err != nil {
		t.Fatalf("armor Decode failed: %v", err)
	}
	r := armorBlock.Body
	w := bytes.NewBuffer(nil)
	for i := 0; i < 2; i++ {
		// Public key
		p, err := Read(r)
		if err != nil {
			t.Error(err)
		}
		pubkey := p.(*PublicKey)
		if !bytes.Equal(pubkey.ec.oid, []byte{0x2b, 0x81, 0x04, 0x00, 0x22}) {
			t.Errorf("Unexpected pubkey OID: %x", pubkey.ec.oid)
		}
		if !bytes.Equal(pubkey.ec.p.bytes[:5], []byte{0x04, 0xf6, 0xb8, 0xc5, 0xac}) {
			t.Errorf("Unexpected pubkey P[:5]: %x", pubkey.ec.p.bytes)
		}
		if pubkey.KeyId != 0x098033880F54719F {
			t.Errorf("Unexpected pubkey ID: %x", pubkey.KeyId)
		}
		err = pubkey.Serialize(w)
		if err != nil {
			t.Error(err)
		}
		// User ID
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		uid := p.(*UserId)
		if uid.Id != "ec_dsa_dh_384 <openpgp@brainhub.org>" {
			t.Error("Unexpected UID:", uid.Id)
		}
		err = uid.Serialize(w)
		if err != nil {
			t.Error(err)
		}
		// User ID Sig
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		uidSig := p.(*Signature)
		err = pubkey.VerifyUserIdSignature(uid.Id, uidSig)
		if err != nil {
			t.Error(err, ": UID")
		}
		err = uidSig.Serialize(w)
		if err != nil {
			t.Error(err)
		}
		// Subkey
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		subkey := p.(*PublicKey)
		if !bytes.Equal(subkey.ec.oid, []byte{0x2b, 0x81, 0x04, 0x00, 0x22}) {
			t.Errorf("Unexpected subkey OID: %x", subkey.ec.oid)
		}
		if !bytes.Equal(subkey.ec.p.bytes[:5], []byte{0x04, 0x2f, 0xaa, 0x84, 0x02}) {
			t.Errorf("Unexpected subkey P[:5]: %x", subkey.ec.p.bytes)
		}
		if subkey.ecdh.KdfHash != 0x09 {
			t.Error("Expected KDF hash function SHA384 (0x09), got", subkey.ecdh.KdfHash)
		}
		if subkey.ecdh.KdfAlgo != 0x09 {
			t.Error("Expected KDF symmetric alg AES256 (0x09), got", subkey.ecdh.KdfAlgo)
		}
		if subkey.KeyId != 0xAA8B938F9A201946 {
			t.Errorf("Unexpected subkey ID: %x", subkey.KeyId)
		}
		err = subkey.Serialize(w)
		if err != nil {
			t.Error(err)
		}
		// Subkey Sig
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		subkeySig := p.(*Signature)
		err = pubkey.VerifyKeySignature(subkey, subkeySig)
		if err != nil {
			t.Error(err)
		}
		err = subkeySig.Serialize(w)
		if err != nil {
			t.Error(err)
		}
		// Now read back what we've written again
		r = bytes.NewBuffer(w.Bytes())
		w = bytes.NewBuffer(nil)
	}
}

const rsaFingerprintHex = "5fb74b1d03b1e3cb31bc2f8aa34d7e18c20c31bb"

const rsaPkDataHex = "988d044d3c5c10010400b1d13382944bd5aba23a4312968b5095d14f947f600eb478e14a6fcb16b0e0cac764884909c020bc495cfcc39a935387c661507bdb236a0612fb582cac3af9b29cc2c8c70090616c41b662f4da4c1201e195472eb7f4ae1ccbcbf9940fe21d985e379a5563dde5b9a23d35f1cfaa5790da3b79db26f23695107bfaca8e7b5bcd0011010001"

const dsaFingerprintHex = "eece4c094db002103714c63c8e8fbe54062f19ed"

const dsaPkDataHex = "9901a2044d432f89110400cd581334f0d7a1e1bdc8b9d6d8c0baf68793632735d2bb0903224cbaa1dfbf35a60ee7a13b92643421e1eb41aa8d79bea19a115a677f6b8ba3c7818ce53a6c2a24a1608bd8b8d6e55c5090cbde09dd26e356267465ae25e69ec8bdd57c7bbb2623e4d73336f73a0a9098f7f16da2e25252130fd694c0e8070c55a812a423ae7f00a0ebf50e70c2f19c3520a551bd4b08d30f23530d3d03ff7d0bf4a53a64a09dc5e6e6e35854b7d70c882b0c60293401958b1bd9e40abec3ea05ba87cf64899299d4bd6aa7f459c201d3fbbd6c82004bdc5e8a9eb8082d12054cc90fa9d4ec251a843236a588bf49552441817436c4f43326966fe85447d4e6d0acf8fa1ef0f014730770603ad7634c3088dc52501c237328417c31c89ed70400b2f1a98b0bf42f11fefc430704bebbaa41d9f355600c3facee1e490f64208e0e094ea55e3a598a219a58500bf78ac677b670a14f4e47e9cf8eab4f368cc1ddcaa18cc59309d4cc62dd4f680e73e6cc3e1ce87a84d0925efbcb26c575c093fc42eecf45135fabf6403a25c2016e1774c0484e440a18319072c617cc97ac0a3bb0"

const ecdsaFingerprintHex = "9892270b38b8980b05c8d56d43fe956c542ca00b"

const ecdsaPkDataHex = "9893045071c29413052b8104002304230401f4867769cedfa52c325018896245443968e52e51d0c2df8d939949cb5b330f2921711fbee1c9b9dddb95d15cb0255e99badeddda7cc23d9ddcaacbc290969b9f24019375d61c2e4e3b36953a28d8b2bc95f78c3f1d592fb24499be348656a7b17e3963187b4361afe497bc5f9f81213f04069f8e1fb9e6a6290ae295ca1a92b894396cb4"

// Source: https://sites.google.com/site/brainhub/pgpecckeys#TOC-ECC-NIST-P-384-key
const ecc384PubArmor = `
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PGP Command Line v10.2.0 (Linux)

mQBvBE1TBZITBSuBBAAiAwME9rjFrO1bhO+fSiCdsuSp37cNKMuMEOzVdnSp+lpn
OJlCti1eUTZ99Me/0/jlAP7s8H7SZaYhqOu75T6UfseMZ366FDvRUzwrNQ4cKfgj
E+HhEI66Bjvh5ksQ5pUOeZwttCRlY19kc2FfZGhfMzg0IDxvcGVucGdwQGJyYWlu
aHViLm9yZz6JAMsEEBMJAFMFAk1TBZIwFIAAAAAAIAAHcHJlZmVycmVkLWVtYWls
LWVuY29kaW5nQHBncC5jb21wZ3BtaW1lBAsJCAcCGQEFGwMAAAACFgIFHgEAAAAE
FQkKCAAKCRAJgDOID1Rxn8orAYCqNzUJaL1fEVr9jOe8exA4IhUtv/BtCvzag1Mp
UQkFuYy0abogj6q4fHQSt5nntjMBf1g2TqSA6KGj8lOgxfIsRG6L6an85iEBNu4w
gRq71JE53ii1vfjcNtBq50hXnp/1A7kAcwRNUwWSEgUrgQQAIgMDBC+qhAJKILZz
XEiX76W/tBv4W37v6rXKDLn/yOoEpGrLJVNKV3aU+eJTQKSrUiOp3R7aUwyKouZx
jbENfmclWMdzb+CTaepXOaKjVUvxbUH6pQVi8RxtObvV3/trmp7JGAMBCQmJAIQE
GBMJAAwFAk1TBZIFGwwAAAAACgkQCYAziA9UcZ+AlwGA7uem2PzuQe5PkonfF/m8
+dlV3KJcWDuUM286Ky1Jhtxc9Be40tyG90Gp4abSNsDjAX0cdldUWKDPuTroorJ0
/MZc7s16ke7INla6EyGZafBpRbSMVr0EFSw6BVPF8vS9Emc=
=I76R
-----END PGP PUBLIC KEY BLOCK-----
`
