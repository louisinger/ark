package bitcointree

import (
	"encoding/hex"
	"fmt"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type VtxoScript common.VtxoScript[bitcoinTapTree]

func ParseVtxoScript(desc string) (VtxoScript, error) {
	v := &DefaultVtxoScript{}
	err := v.FromDescriptor(desc)
	if err != nil {
		v := &ReversibleVtxoScript{}
		err = v.FromDescriptor(desc)
		if err != nil {
			v := &HTLCVtxoScript{}
			err = v.FromDescriptor(desc)
			if err != nil {
				return nil, fmt.Errorf("invalid vtxo descriptor: %s", desc)
			}
			return v, nil
		}
		return v, nil
	}
	return v, nil
}

/*
* DefaultVtxoScript is the default implementation of VTXO with 2 closures
* - Owner and ASP (forfeit)
*	- Owner after t (unilateral exit)
 */
type DefaultVtxoScript struct {
	Owner     *secp256k1.PublicKey
	Asp       *secp256k1.PublicKey
	ExitDelay uint
}

func (v *DefaultVtxoScript) ToDescriptor() string {
	owner := hex.EncodeToString(schnorr.SerializePubKey(v.Owner))

	return fmt.Sprintf(
		descriptor.DefaultVtxoDescriptorTemplate,
		hex.EncodeToString(UnspendableKey().SerializeCompressed()),
		owner,
		hex.EncodeToString(schnorr.SerializePubKey(v.Asp)),
		v.ExitDelay,
		owner,
	)
}

func (v *DefaultVtxoScript) FromDescriptor(desc string) error {
	owner, asp, exitDelay, err := descriptor.ParseDefaultVtxoDescriptor(desc)
	if err != nil {
		return err
	}

	v.Owner = owner
	v.Asp = asp
	v.ExitDelay = exitDelay
	return nil
}

func (v *DefaultVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	redeemClosure := &CSVSigClosure{
		Pubkey:  v.Owner,
		Seconds: v.ExitDelay,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	forfeitClosure := &MultisigClosure{
		Pubkey:    v.Owner,
		AspPubkey: v.Asp,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	tapTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf,
	)

	root := tapTree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	return taprootKey, bitcoinTapTree{tapTree}, nil
}

/*
* ReversibleVtxoScript allows sender of the VTXO to revert the transaction
* unilateral exit is in favor of the sender
* - Owner and ASP (forfeit owner)
* - Sender and ASP (forfeit sender)
*	- Sender after t (unilateral exit)
 */
type ReversibleVtxoScript struct {
	Asp       *secp256k1.PublicKey
	Sender    *secp256k1.PublicKey
	Owner     *secp256k1.PublicKey
	ExitDelay uint
}

func (v *ReversibleVtxoScript) ToDescriptor() string {
	owner := hex.EncodeToString(schnorr.SerializePubKey(v.Owner))
	sender := hex.EncodeToString(schnorr.SerializePubKey(v.Sender))
	asp := hex.EncodeToString(schnorr.SerializePubKey(v.Asp))

	return fmt.Sprintf(
		descriptor.ReversibleVtxoScriptTemplate,
		hex.EncodeToString(UnspendableKey().SerializeCompressed()),
		sender,
		asp,
		v.ExitDelay,
		sender,
		owner,
		asp,
	)
}

func (v *ReversibleVtxoScript) FromDescriptor(desc string) error {
	owner, sender, asp, exitDelay, err := descriptor.ParseReversibleVtxoDescriptor(desc)
	if err != nil {
		return err
	}

	v.Owner = owner
	v.Sender = sender
	v.Asp = asp
	v.ExitDelay = exitDelay
	return nil
}

func (v *ReversibleVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	redeemClosure := &CSVSigClosure{
		Pubkey:  v.Sender,
		Seconds: v.ExitDelay,
	}

	redeemLeaf, err := redeemClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	forfeitClosure := &MultisigClosure{
		Pubkey:    v.Owner,
		AspPubkey: v.Asp,
	}

	forfeitLeaf, err := forfeitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	reverseForfeitClosure := &MultisigClosure{
		Pubkey:    v.Sender,
		AspPubkey: v.Asp,
	}

	reverseForfeitLeaf, err := reverseForfeitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	tapTree := txscript.AssembleTaprootScriptTree(
		*redeemLeaf, *forfeitLeaf, *reverseForfeitLeaf,
	)

	root := tapTree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	return taprootKey, bitcoinTapTree{tapTree}, nil
}

/*
* HTLCVtxoScript allows owner of the VTXO to atomically swap with LN funds, it contains 6 branches
* - Receiver and ASP and preimage (forfeit receiver / claim with preimage)
* - Receiver and ASP and Sender (refund)
* - Sender and ASP after T_Reclaim (reclaim / cancel the swap)
* - Sender after T_Reclaim' (reclaim without ASP) - with T_Reclaim' > T_Reclaim
* - Receiver and ASP after T_Refund (refund)
* - Receiver and preimage after T_Redeem (exit path for the receiver)
 */
type HTLCVtxoScript struct {
	Sender                  *secp256k1.PublicKey // sender of vtxos, receive LN funds
	Receiver                *secp256k1.PublicKey // receive vtxo, send LN funds
	Asp                     *secp256k1.PublicKey
	PreimageHash            string
	SenderReclaimDelay      uint
	SenderReclaimAloneDelay uint
	ReceiverRefundDelay     uint
	ReceiverExitDelay       uint
}

func (v *HTLCVtxoScript) ToDescriptor() string {
	sender := hex.EncodeToString(schnorr.SerializePubKey(v.Sender))
	receiver := hex.EncodeToString(schnorr.SerializePubKey(v.Receiver))
	asp := hex.EncodeToString(schnorr.SerializePubKey(v.Asp))

	return fmt.Sprintf(
		descriptor.HTLCVtxoScriptTemplate,
		hex.EncodeToString(UnspendableKey().SerializeCompressed()),
		sender,
		receiver,
		asp,
		v.SenderReclaimDelay,
		sender,
		asp,
		v.SenderReclaimAloneDelay,
		sender,
		v.ReceiverRefundDelay,
		receiver,
		asp,
		v.PreimageHash,
		receiver,
		asp,
		v.PreimageHash,
		v.ReceiverExitDelay,
		receiver,
	)
}

func (v *HTLCVtxoScript) FromDescriptor(desc string) error {
	sender, receiver, asp, reclaimDelay, reclaimAloneDelay, refundDelay, exitDelay, preimageHash, err := descriptor.ParseHTLCVtxoDescriptor(desc)
	if err != nil {
		return err
	}

	v.Sender = sender
	v.Receiver = receiver
	v.Asp = asp
	v.SenderReclaimDelay = reclaimDelay
	v.SenderReclaimAloneDelay = reclaimAloneDelay
	v.ReceiverRefundDelay = refundDelay
	v.ReceiverExitDelay = exitDelay
	v.PreimageHash = preimageHash

	return nil
}

func (v *HTLCVtxoScript) TapTree() (*secp256k1.PublicKey, bitcoinTapTree, error) {
	refundClosure := &RefundClosure{
		Sender:    v.Sender,
		Receiver:  v.Receiver,
		AspPubkey: v.Asp,
	}

	refundLeaf, err := refundClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	reclaimWithASPClosure := &CSVMultisigClosure{
		Pubkey:    v.Sender,
		AspPubkey: v.Asp,
		Seconds:   v.SenderReclaimDelay,
	}

	reclaimWithASPLeaf, err := reclaimWithASPClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	reclaimAloneClosure := &CSVSigClosure{
		Pubkey:  v.Sender,
		Seconds: v.SenderReclaimAloneDelay,
	}

	reclaimAloneLeaf, err := reclaimAloneClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	receiverRefundClosure := &CSVMultisigClosure{
		Pubkey:    v.Receiver,
		AspPubkey: v.Asp,
		Seconds:   v.ReceiverRefundDelay,
	}

	receiverRefundLeaf, err := receiverRefundClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	claimClosure := &PreimageMultisigClosure{
		PreimageHash: v.PreimageHash,
		Pubkey:       v.Receiver,
		AspPubkey:    v.Asp,
	}

	claimLeaf, err := claimClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	receiverExitClosure := &CSVPreimageClosure{
		PreimageHash: v.PreimageHash,
		Pubkey:       v.Receiver,
		Seconds:      v.ReceiverExitDelay,
	}

	receiverExitLeaf, err := receiverExitClosure.Leaf()
	if err != nil {
		return nil, bitcoinTapTree{}, err
	}

	tapTree := txscript.AssembleTaprootScriptTree(
		*refundLeaf, *reclaimWithASPLeaf, *reclaimAloneLeaf, *receiverRefundLeaf, *claimLeaf, *receiverExitLeaf,
	)

	root := tapTree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(
		UnspendableKey(),
		root[:],
	)

	return taprootKey, bitcoinTapTree{tapTree}, nil
}

// bitcoinTapTree is a wrapper around txscript.IndexedTapScriptTree to implement the common.TaprootTree interface
type bitcoinTapTree struct {
	*txscript.IndexedTapScriptTree
}

func (b bitcoinTapTree) GetRoot() chainhash.Hash {
	return b.RootNode.TapHash()
}

func (b bitcoinTapTree) GetTaprootMerkleProof(leafhash chainhash.Hash) (*common.TaprootMerkleProof, error) {
	index, ok := b.LeafProofIndex[leafhash]
	if !ok {
		return nil, fmt.Errorf("leaf %s not found in tree", leafhash.String())
	}
	proof := b.LeafMerkleProofs[index]

	controlBlock := proof.ToControlBlock(UnspendableKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	return &common.TaprootMerkleProof{
		ControlBlock: controlBlockBytes,
		Script:       proof.Script,
	}, nil
}

func (b bitcoinTapTree) GetLeaves() []chainhash.Hash {
	leafHashes := make([]chainhash.Hash, 0)
	for hash := range b.LeafProofIndex {
		leafHashes = append(leafHashes, hash)
	}
	return leafHashes
}
