// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package queries

import (
	"database/sql"
)

type Payment struct {
	ID      string
	RoundID string
}

type PaymentReceiverVw struct {
	PaymentID      sql.NullString
	Pubkey         sql.NullString
	Amount         sql.NullInt64
	OnchainAddress sql.NullString
}

type PaymentVtxoVw struct {
	Txid      sql.NullString
	Vout      sql.NullInt64
	Pubkey    sql.NullString
	Amount    sql.NullInt64
	PoolTx    sql.NullString
	SpentBy   sql.NullString
	Spent     sql.NullBool
	Redeemed  sql.NullBool
	Swept     sql.NullBool
	ExpireAt  sql.NullInt64
	PaymentID sql.NullString
	RedeemTx  sql.NullString
}

type Receiver struct {
	PaymentID      string
	Pubkey         string
	Amount         int64
	OnchainAddress string
}

type Round struct {
	ID                string
	StartingTimestamp int64
	EndingTimestamp   int64
	Ended             bool
	Failed            bool
	StageCode         int64
	Txid              string
	UnsignedTx        string
	ConnectorAddress  string
	DustAmount        int64
	Version           int64
	Swept             bool
}

type RoundPaymentVw struct {
	ID      sql.NullString
	RoundID sql.NullString
}

type RoundTxVw struct {
	ID         sql.NullInt64
	Tx         sql.NullString
	RoundID    sql.NullString
	Type       sql.NullString
	Position   sql.NullInt64
	Txid       sql.NullString
	TreeLevel  sql.NullInt64
	ParentTxid sql.NullString
	IsLeaf     sql.NullBool
}

type Tx struct {
	ID         int64
	Tx         string
	RoundID    string
	Type       string
	Position   int64
	Txid       sql.NullString
	TreeLevel  sql.NullInt64
	ParentTxid sql.NullString
	IsLeaf     sql.NullBool
}

type UncondForfeitTx struct {
	ID       int64
	Tx       string
	VtxoTxid string
	VtxoVout int64
	Position int64
}

type UncondForfeitTxVw struct {
	ID       sql.NullInt64
	Tx       sql.NullString
	VtxoTxid sql.NullString
	VtxoVout sql.NullInt64
	Position sql.NullInt64
}

type Vtxo struct {
	Txid      string
	Vout      int64
	Pubkey    string
	Amount    int64
	PoolTx    string
	SpentBy   string
	Spent     bool
	Redeemed  bool
	Swept     bool
	ExpireAt  int64
	PaymentID sql.NullString
	RedeemTx  sql.NullString
}