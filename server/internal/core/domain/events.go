package domain

import "github.com/ark-network/ark/common/tree"

type RoundEvent interface {
	isEvent()
}

func (r RoundStarted) isEvent()             {}
func (r RoundFinalizationStarted) isEvent() {}
func (r RoundFinalized) isEvent()           {}
func (r RoundFailed) isEvent()              {}
func (r PaymentsRegistered) isEvent()       {}

type RoundStarted struct {
	Id        string
	Timestamp int64
}

type RoundFinalizationStarted struct {
	Id                 string
	CongestionTree     tree.CongestionTree
	Connectors         []string
	ConnectorAddress   string
	UnsignedForfeitTxs []string
	PoolTx             string
}

type RoundFinalized struct {
	Id         string
	Txid       string
	ForfeitTxs []string
	Timestamp  int64
}

type RoundFailed struct {
	Id        string
	Err       string
	Timestamp int64
}

type PaymentsRegistered struct {
	Id       string
	Payments []Payment
}
