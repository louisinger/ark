package descriptor

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// tr(unspendable, { and(pk(user), pk(asp)), and(older(timeout), pk(user)) })
const DefaultVtxoDescriptorTemplate = "tr(%s,{ and(pk(%s), pk(%s)), and(older(%d), pk(%s)) })"

// tr(unspendable, { { and(pk(sender), pk(asp)), and(older(timeout), pk(sender)) }, and(pk(receiver), pk(asp)) })
const ReversibleVtxoScriptTemplate = "tr(%s,{ { and(pk(%s), pk(%s)), and(older(%d), pk(%s)) }, and(pk(%s), pk(%s)) })"

// tr(unspendable,
//
//	{
//			{
//					{
//							and(and(pk(sender), pk(receiver)), pk(asp)), // REFUND
//							and(older(reclaim_timeout), and(pk(sender), pk(asp))) // RECLAIM with asp
//					},
//					{
//							and(older(reclaim_alone_timeout), pk(sender)), // RECLAIM without asp
//							and(older(refund), and(pk(receiver), pk(asp))) // REFUND without sender
//					}
//			},
//			{
//					and(hash160(preimage_hash), and(pk(receiver), pk(asp))), // CLAIM (forfeit)
//					and(hash160(preimage_hash), and(older(exit_timeout), pk(receiver))) // CLAIM (unilateral exit)
//			}
//	}
//
// )
const HTLCVtxoScriptTemplate = `
tr(
	%s,
	{
			{
					{
							and(and(pk(%s), pk(%s)), pk(%s)),
							and(older(%d), and(pk(%s), pk(%s)))
					},
					{
							and(older(%d), pk(%s)),
							and(older(%d), and(pk(%s), pk(%s)))
					}
			},
			{
					and(hash160(%s), and(pk(%s), pk(%s))),
					and(hash160(%s), and(older(%d), pk(%s)))
			}
	}
)
`

func ParseHTLCVtxoDescriptor(
	descriptor string,
) (
	sender, receiver, asp *secp256k1.PublicKey,
	reclaimTimeout, reclaimAloneTimeout, refundTimeout, exitTimeout uint,
	preimageHash string, err error,
) {
	desc, err := ParseTaprootDescriptor(descriptor)
	if err != nil {
		return
	}

	if len(desc.ScriptTree) != 6 {
		return
	}

	sender, receiver, asp, err = parseRefund(desc.ScriptTree[0])
	if err != nil {
		return
	}

	senderFromReclaim, aspFromReclaim, timeoutFromReclaim, err := parseReclaimWithASP(desc.ScriptTree[1])
	if err != nil {
		return
	}

	reclaimTimeout = timeoutFromReclaim

	if !sender.IsEqual(senderFromReclaim) || !asp.IsEqual(aspFromReclaim) {
		err = fmt.Errorf("invalid vHTLC descriptor, public key mismatch (reclaim)")
		return
	}

	senderFromReclaimAlone, timeoutFromReclaimAlone, err := parseReclaimWithoutASP(desc.ScriptTree[2])
	if err != nil {
		return
	}

	reclaimAloneTimeout = timeoutFromReclaimAlone

	if !sender.IsEqual(senderFromReclaimAlone) {
		err = fmt.Errorf("invalid vHTLC descriptor, public key mismatch (reclaim alone)")
		return
	}

	receiverFromRefund, aspFromRefund, timeoutFromRefund, err := parseRefundWithoutSender(desc.ScriptTree[3])
	if err != nil {
		return
	}

	refundTimeout = timeoutFromRefund

	if !receiver.IsEqual(receiverFromRefund) || !asp.IsEqual(aspFromRefund) {
		err = fmt.Errorf("invalid vHTLC descriptor, public key mismatch (refund)")
		return
	}

	receiverFromClaim, aspFromClaim, preimageHashFromClaim, err := parseClaim(desc.ScriptTree[4])
	if err != nil {
		return
	}

	preimageHash = preimageHashFromClaim

	if !receiver.IsEqual(receiverFromClaim) || !asp.IsEqual(aspFromClaim) {
		err = fmt.Errorf("invalid vHTLC descriptor, public key mismatch (claim)")
		return
	}

	receiverFromUnilateralExit, exitTimeoutFromClaim, preimageHashFromUnilateralExit, err := parseClaimUnilateralExit(desc.ScriptTree[5])
	if err != nil {
		return
	}

	exitTimeout = exitTimeoutFromClaim

	if preimageHashFromUnilateralExit != preimageHash {
		err = fmt.Errorf("invalid vHTLC descriptor, preimage hash mismatch")
		return
	}

	if !receiver.IsEqual(receiverFromUnilateralExit) {
		err = fmt.Errorf("invalid vHTLC descriptor, public key mismatch (unilateral exit)")
		return
	}

	return
}

func ParseReversibleVtxoDescriptor(
	descriptor string,
) (user, sender, asp *secp256k1.PublicKey, timeout uint, err error) {
	desc, err := ParseTaprootDescriptor(descriptor)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	if len(desc.ScriptTree) != 3 {
		return nil, nil, nil, 0, errors.New("not a reversible vtxo script descriptor")
	}

	for _, leaf := range desc.ScriptTree {
		if andLeaf, ok := leaf.(*And); ok {
			if first, ok := andLeaf.First.(*PK); ok {
				if second, ok := andLeaf.Second.(*PK); ok {
					keyBytes, err := hex.DecodeString(first.Key.Hex)
					if err != nil {
						return nil, nil, nil, 0, err
					}
					if sender == nil {
						sender, err = schnorr.ParsePubKey(keyBytes)
						if err != nil {
							return nil, nil, nil, 0, err
						}
					} else {
						user, err = schnorr.ParsePubKey(keyBytes)
						if err != nil {
							return nil, nil, nil, 0, err
						}
					}

					if asp == nil {
						keyBytes, err = hex.DecodeString(second.Key.Hex)
						if err != nil {
							return nil, nil, nil, 0, err
						}

						asp, err = schnorr.ParsePubKey(keyBytes)
						if err != nil {
							return nil, nil, nil, 0, err
						}
					}
				}
			}

			if first, ok := andLeaf.First.(*Older); ok {
				if second, ok := andLeaf.Second.(*PK); ok {
					timeout = first.Timeout
					keyBytes, err := hex.DecodeString(second.Key.Hex)
					if err != nil {
						return nil, nil, nil, 0, err
					}

					sender, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, nil, 0, err
					}
				}
			}
		}
	}

	if user == nil {
		return nil, nil, nil, 0, errors.New("descriptor is invalid")
	}

	if asp == nil {
		return nil, nil, nil, 0, errors.New("descriptor is invalid")
	}

	if timeout == 0 {
		return nil, nil, nil, 0, errors.New("descriptor is invalid")
	}

	if sender == nil {
		return nil, nil, nil, 0, errors.New("descriptor is invalid")
	}

	return
}

func ParseDefaultVtxoDescriptor(
	descriptor string,
) (user, asp *secp256k1.PublicKey, timeout uint, err error) {
	desc, err := ParseTaprootDescriptor(descriptor)
	if err != nil {
		return nil, nil, 0, err
	}

	if len(desc.ScriptTree) != 2 {
		return nil, nil, 0, errors.New("not a default vtxo script descriptor")
	}

	for _, leaf := range desc.ScriptTree {
		if andLeaf, ok := leaf.(*And); ok {
			if first, ok := andLeaf.First.(*PK); ok {
				if second, ok := andLeaf.Second.(*PK); ok {
					keyBytes, err := hex.DecodeString(first.Key.Hex)
					if err != nil {
						return nil, nil, 0, err
					}

					user, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, 0, err
					}

					keyBytes, err = hex.DecodeString(second.Key.Hex)
					if err != nil {
						return nil, nil, 0, err
					}

					asp, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, 0, err
					}
				}
			}

			if first, ok := andLeaf.First.(*Older); ok {
				if second, ok := andLeaf.Second.(*PK); ok {
					timeout = first.Timeout
					keyBytes, err := hex.DecodeString(second.Key.Hex)
					if err != nil {
						return nil, nil, 0, err
					}

					user, err = schnorr.ParsePubKey(keyBytes)
					if err != nil {
						return nil, nil, 0, err
					}
				}
			}
		}
	}

	if user == nil {
		return nil, nil, 0, errors.New("boarding descriptor is invalid")
	}

	if asp == nil {
		return nil, nil, 0, errors.New("boarding descriptor is invalid")
	}

	if timeout == 0 {
		return nil, nil, 0, errors.New("boarding descriptor is invalid")
	}

	return
}

// HTLC parse utility functions

// and(and(pk(sender), pk(receiver)), pk(asp))
func parseRefund(expr Expression) (
	sender, receiver, asp *secp256k1.PublicKey, err error,
) {
	refund, ok := expr.(*And)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript")
		return
	}

	firtRefundChild, ok := refund.First.(*And)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected and()")
		return
	}

	firstKey, ok := firtRefundChild.First.(*PK)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected pk()")
		return
	}

	senderPubKeyBytes, err := hex.DecodeString(firstKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	sender, err = schnorr.ParsePubKey(senderPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	secondKey, ok := firtRefundChild.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected pk()")
		return
	}

	receiverPubKeyBytes, err := hex.DecodeString(secondKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	receiver, err = schnorr.ParsePubKey(receiverPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	secondRefundChild, ok := refund.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected pk()")
		return
	}

	aspPubKeyBytes, err := hex.DecodeString(secondRefundChild.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	asp, err = schnorr.ParsePubKey(aspPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	return
}

// and(older(reclaim_timeout), and(pk(sender), pk(asp))) // RECLAIM with asp
func parseReclaimWithASP(expr Expression) (
	sender, asp *secp256k1.PublicKey, timeout uint, err error,
) {
	reclaim, ok := expr.(*And)
	if !ok {
		err = fmt.Errorf("invalid reclaim tapscript")
		return
	}

	older, ok := reclaim.First.(*Older)
	if !ok {
		err = fmt.Errorf("invalid reclaim tapscript, expected older()")
		return
	}

	timeout = older.Timeout

	and, ok := reclaim.Second.(*And)
	if !ok {
		err = fmt.Errorf("invalid reclaim tapscript, expected and()")
		return
	}

	firstKey, ok := and.First.(*PK)
	if !ok {
		err = fmt.Errorf("invalid reclaim tapscript, expected pk()")
		return
	}

	senderPubKeyBytes, err := hex.DecodeString(firstKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid reclaim tapscript, %v", err)
		return
	}

	sender, err = schnorr.ParsePubKey(senderPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid reclaim tapscript, %v", err)
		return
	}

	secondKey, ok := and.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid reclaim tapscript, expected pk()")
		return
	}

	aspPubKeyBytes, err := hex.DecodeString(secondKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid reclaim tapscript, %v", err)
		return
	}

	asp, err = schnorr.ParsePubKey(aspPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid reclaim tapscript, %v", err)
		return
	}

	return
}

// and(older(reclaim_alone_timeout), pk(sender)), // RECLAIM without asp
func parseReclaimWithoutASP(expr Expression) (
	sender *secp256k1.PublicKey, timeout uint, err error,
) {
	reclaim, ok := expr.(*And)
	if !ok {
		err = fmt.Errorf("invalid reclaim alone tapscript")
		return
	}

	older, ok := reclaim.First.(*Older)
	if !ok {
		err = fmt.Errorf("invalid reclaim alone tapscript, expected older()")
		return
	}

	timeout = older.Timeout

	pk, ok := reclaim.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid reclaim alone tapscript, expected pk()")
		return
	}

	senderPubKeyBytes, err := hex.DecodeString(pk.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid reclaim alone tapscript, %v", err)
		return
	}

	sender, err = schnorr.ParsePubKey(senderPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid reclaim alone tapscript, %v", err)
		return
	}

	return
}

// and(older(refund), and(pk(receiver), pk(asp))) // REFUND
func parseRefundWithoutSender(expr Expression) (
	receiver, asp *secp256k1.PublicKey, timeout uint, err error,
) {
	refund, ok := expr.(*And)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript")
		return
	}

	older, ok := refund.First.(*Older)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected older()")
		return
	}

	timeout = older.Timeout

	and, ok := refund.Second.(*And)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected and()")
		return
	}

	firstKey, ok := and.First.(*PK)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected pk()")
		return
	}

	receiverPubKeyBytes, err := hex.DecodeString(firstKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	receiver, err = schnorr.ParsePubKey(receiverPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	secondKey, ok := and.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid refund tapscript, expected pk()")
		return
	}

	aspPubKeyBytes, err := hex.DecodeString(secondKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	asp, err = schnorr.ParsePubKey(aspPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid refund tapscript, %v", err)
		return
	}

	return
}

// and(hash160(preimage_hash), and(pk(receiver), pk(asp))), // CLAIM (forfeit)
func parseClaim(expr Expression) (
	receiver, asp *secp256k1.PublicKey, preimageHash string, err error,
) {
	claim, ok := expr.(*And)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript")
		return
	}

	hash160, ok := claim.First.(*Hash160)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected hash160()")
		return
	}

	preimageHash = hash160.Hash

	and, ok := claim.Second.(*And)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected and()")
		return
	}

	firstKey, ok := and.First.(*PK)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected pk()")
		return
	}

	receiverPubKeyBytes, err := hex.DecodeString(firstKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid claim tapscript, %v", err)
		return
	}

	receiver, err = schnorr.ParsePubKey(receiverPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid claim tapscript, %v", err)
		return
	}

	secondKey, ok := and.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected pk()")
		return
	}

	aspPubKeyBytes, err := hex.DecodeString(secondKey.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid claim tapscript, %v", err)
		return
	}

	asp, err = schnorr.ParsePubKey(aspPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid claim tapscript, %v", err)
		return
	}

	return
}

// and(hash160(preimage_hash), and(older(exit_timeout), pk(receiver))) // CLAIM (unilateral exit)
func parseClaimUnilateralExit(expr Expression) (
	receiver *secp256k1.PublicKey, exitTimeout uint, preimageHash string, err error,
) {
	claim, ok := expr.(*And)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript")
		return
	}

	hash160, ok := claim.First.(*Hash160)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected hash160()")
		return
	}

	preimageHash = hash160.Hash

	and, ok := claim.Second.(*And)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected and()")
		return
	}

	older, ok := and.First.(*Older)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected older()")
		return
	}

	exitTimeout = older.Timeout

	pk, ok := and.Second.(*PK)
	if !ok {
		err = fmt.Errorf("invalid claim tapscript, expected pk()")
		return
	}

	receiverPubKeyBytes, err := hex.DecodeString(pk.Key.Hex)
	if err != nil {
		err = fmt.Errorf("invalid claim tapscript, %v", err)
		return
	}

	receiver, err = schnorr.ParsePubKey(receiverPubKeyBytes)
	if err != nil {
		err = fmt.Errorf("invalid claim tapscript, %v", err)
		return
	}

	return
}
