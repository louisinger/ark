package bitcointree

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

type Closure interface {
	Leaf() (*txscript.TapLeaf, error)
	Decode(script []byte) (bool, error)
}

type CSVSigClosure struct {
	Pubkey  *secp256k1.PublicKey
	Seconds uint
}

type MultisigClosure struct {
	Pubkey    *secp256k1.PublicKey
	AspPubkey *secp256k1.PublicKey
}

type CSVMultisigClosure struct {
	Pubkey    *secp256k1.PublicKey
	AspPubkey *secp256k1.PublicKey
	Seconds   uint
}

type RefundClosure struct {
	Sender    *secp256k1.PublicKey
	Receiver  *secp256k1.PublicKey
	AspPubkey *secp256k1.PublicKey
}

type PreimageMultisigClosure struct {
	PreimageHash string
	Pubkey       *secp256k1.PublicKey
	AspPubkey    *secp256k1.PublicKey
}

type CSVPreimageClosure struct {
	PreimageHash string
	Pubkey       *secp256k1.PublicKey
	Seconds      uint
}

func DecodeClosure(script []byte) (Closure, error) {
	var closure Closure

	closure = &RefundClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &CSVMultisigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &PreimageMultisigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &CSVPreimageClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &CSVSigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	closure = &MultisigClosure{}
	if valid, err := closure.Decode(script); err == nil && valid {
		return closure, nil
	}

	return nil, fmt.Errorf("invalid closure script")
}

func (f *CSVPreimageClosure) Leaf() (*txscript.TapLeaf, error) {
	userKeyBytes := schnorr.SerializePubKey(f.Pubkey)

	h, err := hex.DecodeString(f.PreimageHash)
	if err != nil {
		return nil, err
	}

	preimageScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddInt64(32).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(h).
		AddOp(txscript.OP_EQUALVERIFY).
		Script()
	if err != nil {
		return nil, err
	}

	csvScript, err := encodeCsvScript(f.Seconds)
	if err != nil {
		return nil, err
	}

	checksigScript, err := txscript.NewScriptBuilder().
		AddData(userKeyBytes).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		return nil, err
	}

	script := append(preimageScript, csvScript...)
	script = append(script, checksigScript...)

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (f *CSVPreimageClosure) Decode(script []byte) (bool, error) {
	hash160Index := bytes.Index(
		script, []byte{txscript.OP_HASH160},
	)

	if hash160Index == -1 || hash160Index == 0 {
		return false, nil
	}

	preimageHash := script[hash160Index+1 : hash160Index+33]
	if len(preimageHash) != 32 {
		return false, nil
	}

	csvIndex := bytes.Index(
		script, []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP},
	)
	if csvIndex == -1 || csvIndex == 0 {
		return false, nil
	}

	sequence := script[hash160Index+33 : csvIndex]

	seconds, err := common.BIP68Decode(sequence)
	if err != nil {
		return false, err
	}

	checksigScript := script[csvIndex+2:]
	valid, pubkey, err := decodeChecksigScript(checksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	f.Pubkey = pubkey
	f.PreimageHash = hex.EncodeToString(preimageHash)
	f.Seconds = seconds

	rebuilt, err := f.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil
	}

	return true, nil
}

func (f *PreimageMultisigClosure) Leaf() (*txscript.TapLeaf, error) {
	aspKeyBytes := schnorr.SerializePubKey(f.AspPubkey)
	userKeyBytes := schnorr.SerializePubKey(f.Pubkey)

	h, err := hex.DecodeString(f.PreimageHash)
	if err != nil {
		return nil, err
	}

	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddInt64(32).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(h).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(userKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData(aspKeyBytes).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		return nil, err
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (f *PreimageMultisigClosure) Decode(script []byte) (bool, error) {
	hash160Index := bytes.Index(
		script, []byte{txscript.OP_HASH160},
	)
	if hash160Index == -1 || hash160Index == 0 {
		return false, nil
	}

	preimageHash := script[hash160Index+2 : hash160Index+22]
	if len(preimageHash) != 20 {
		return false, nil
	}

	checksigScript := script[hash160Index+22 : hash160Index+22+33]
	valid, pubkey, err := decodeChecksigScript(checksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	secondChecksigScript := script[hash160Index+22+33:]
	valid, aspPubkey, err := decodeChecksigScript(secondChecksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		logrus.Errorf("invalid checksig script %s", hex.EncodeToString(secondChecksigScript))
		return false, nil
	}

	f.Pubkey = pubkey
	f.AspPubkey = aspPubkey
	f.PreimageHash = hex.EncodeToString(preimageHash)

	rebuilt, err := f.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		logrus.Errorf("invalid rebuilt script")
		logrus.Info(hex.EncodeToString(rebuilt.Script))
		logrus.Info(hex.EncodeToString(script))
		return false, nil
	}

	return true, nil
}

func (f *CSVMultisigClosure) Leaf() (*txscript.TapLeaf, error) {
	aspKeyBytes := schnorr.SerializePubKey(f.AspPubkey)
	userKeyBytes := schnorr.SerializePubKey(f.Pubkey)

	csvScript, err := encodeCsvScript(f.Seconds)
	if err != nil {
		return nil, err
	}

	script, err := txscript.NewScriptBuilder().
		AddData(userKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData(aspKeyBytes).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		return nil, err
	}

	script = append(csvScript, script...)

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (f *CSVMultisigClosure) Decode(script []byte) (bool, error) {
	csvIndex := bytes.Index(
		script, []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP},
	)
	if csvIndex == -1 || csvIndex == 0 {
		return false, nil
	}

	sequence := script[1:csvIndex]

	seconds, err := common.BIP68Decode(sequence)
	if err != nil {
		return false, err
	}

	checksigScript := script[csvIndex+2 : csvIndex+2+33]
	valid, pubkey, err := decodeChecksigScript(checksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	secondChecksigScript := script[csvIndex+2+33:]
	valid, aspPubkey, err := decodeChecksigScript(secondChecksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	f.Pubkey = pubkey
	f.AspPubkey = aspPubkey
	f.Seconds = seconds

	rebuilt, err := f.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil
	}

	return true, nil
}

func (f *RefundClosure) Leaf() (*txscript.TapLeaf, error) {
	aspKeyBytes := schnorr.SerializePubKey(f.AspPubkey)
	receiverKeyBytes := schnorr.SerializePubKey(f.Receiver)
	senderKeyBytes := schnorr.SerializePubKey(f.Sender)

	script, err := txscript.NewScriptBuilder().
		AddData(senderKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData(receiverKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData(aspKeyBytes).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, err
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (f *RefundClosure) Decode(script []byte) (bool, error) {
	valid, senderPubKey, err := decodeChecksigScript(script[:33])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	valid, receiverPubKey, err := decodeChecksigScript(script[33:66])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	valid, aspPubKey, err := decodeChecksigScript(script[66:])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	f.Sender = senderPubKey
	f.Receiver = receiverPubKey
	f.AspPubkey = aspPubKey

	rebuilt, err := f.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil
	}

	return true, nil
}

func (f *MultisigClosure) Leaf() (*txscript.TapLeaf, error) {
	aspKeyBytes := schnorr.SerializePubKey(f.AspPubkey)
	userKeyBytes := schnorr.SerializePubKey(f.Pubkey)

	script, err := txscript.NewScriptBuilder().AddData(aspKeyBytes).
		AddOp(txscript.OP_CHECKSIGVERIFY).AddData(userKeyBytes).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, err
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (f *MultisigClosure) Decode(script []byte) (bool, error) {
	valid, aspPubKey, err := decodeChecksigScript(script)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	valid, pubkey, err := decodeChecksigScript(script[33:])
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	f.Pubkey = pubkey
	f.AspPubkey = aspPubKey

	rebuilt, err := f.Leaf()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt.Script, script) {
		return false, nil
	}

	return true, nil
}

func (d *CSVSigClosure) Leaf() (*txscript.TapLeaf, error) {
	script, err := encodeCsvWithChecksigScript(d.Pubkey, d.Seconds)
	if err != nil {
		return nil, err
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)
	return &tapLeaf, nil
}

func (d *CSVSigClosure) Decode(script []byte) (bool, error) {
	csvIndex := bytes.Index(
		script, []byte{txscript.OP_CHECKSEQUENCEVERIFY, txscript.OP_DROP},
	)
	if csvIndex == -1 || csvIndex == 0 {
		return false, nil
	}

	sequence := script[1:csvIndex]

	seconds, err := common.BIP68Decode(sequence)
	if err != nil {
		return false, err
	}

	checksigScript := script[csvIndex+2:]
	valid, pubkey, err := decodeChecksigScript(checksigScript)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, nil
	}

	rebuilt, err := encodeCsvWithChecksigScript(pubkey, seconds)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(rebuilt, script) {
		return false, nil
	}

	d.Pubkey = pubkey
	d.Seconds = seconds

	return valid, nil
}

func decodeChecksigScript(script []byte) (bool, *secp256k1.PublicKey, error) {
	data32Index := bytes.Index(script, []byte{txscript.OP_DATA_32})
	if data32Index == -1 {
		return false, nil, nil
	}

	key := script[data32Index+1 : data32Index+33]
	if len(key) != 32 {
		return false, nil, nil
	}

	pubkey, err := schnorr.ParsePubKey(key)
	if err != nil {
		return false, nil, err
	}

	return true, pubkey, nil
}

// checkSequenceVerifyScript without checksig
func encodeCsvScript(seconds uint) ([]byte, error) {
	sequence, err := common.BIP68Encode(seconds)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().AddData(sequence).AddOps([]byte{
		txscript.OP_CHECKSEQUENCEVERIFY,
		txscript.OP_DROP,
	}).Script()
}

// checkSequenceVerifyScript + checksig
func encodeCsvWithChecksigScript(
	pubkey *secp256k1.PublicKey, seconds uint,
) ([]byte, error) {
	script, err := encodeChecksigScript(pubkey)
	if err != nil {
		return nil, err
	}

	csvScript, err := encodeCsvScript(seconds)
	if err != nil {
		return nil, err
	}

	return append(csvScript, script...), nil
}

func encodeChecksigScript(pubkey *secp256k1.PublicKey) ([]byte, error) {
	key := schnorr.SerializePubKey(pubkey)
	return txscript.NewScriptBuilder().AddData(key).
		AddOp(txscript.OP_CHECKSIG).Script()
}
