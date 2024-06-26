package appconfig

import (
	"fmt"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/internal/core/application"
	"github.com/ark-network/ark/internal/core/ports"
	"github.com/ark-network/ark/internal/infrastructure/db"
	oceanwallet "github.com/ark-network/ark/internal/infrastructure/ocean-wallet"
	scheduler "github.com/ark-network/ark/internal/infrastructure/scheduler/gocron"
	txbuilder "github.com/ark-network/ark/internal/infrastructure/tx-builder/covenant"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/network"
)

const minAllowedSequence = 512

var (
	supportedDbs = supportedType{
		"badger": {},
	}
	supportedSchedulers = supportedType{
		"gocron": {},
	}
	supportedTxBuilders = supportedType{
		"covenant": {},
	}
	supportedScanners = supportedType{
		"ocean": {},
	}
)

type Config struct {
	DbType                string
	DbDir                 string
	RoundInterval         int64
	Network               common.Network
	SchedulerType         string
	TxBuilderType         string
	BlockchainScannerType string
	WalletAddr            string
	MinRelayFee           uint64
	RoundLifetime         int64
	UnilateralExitDelay   int64

	repo      ports.RepoManager
	svc       application.Service
	wallet    ports.WalletService
	txBuilder ports.TxBuilder
	scanner   ports.BlockchainScanner
	scheduler ports.SchedulerService
}

func (c *Config) Validate() error {
	if !supportedDbs.supports(c.DbType) {
		return fmt.Errorf("db type not supported, please select one of: %s", supportedDbs)
	}
	if !supportedSchedulers.supports(c.SchedulerType) {
		return fmt.Errorf("scheduler type not supported, please select one of: %s", supportedSchedulers)
	}
	if !supportedTxBuilders.supports(c.TxBuilderType) {
		return fmt.Errorf("tx builder type not supported, please select one of: %s", supportedTxBuilders)
	}
	if !supportedScanners.supports(c.BlockchainScannerType) {
		return fmt.Errorf("blockchain scanner type not supported, please select one of: %s", supportedScanners)
	}
	if c.RoundInterval < 2 {
		return fmt.Errorf("invalid round interval, must be at least 2 seconds")
	}
	if c.Network.Name != "liquid" && c.Network.Name != "testnet" && c.Network.Name != "regtest" {
		return fmt.Errorf("invalid network, must be liquid, testnet or regtest")
	}
	if len(c.WalletAddr) <= 0 {
		return fmt.Errorf("missing onchain wallet address")
	}
	if c.MinRelayFee < 30 {
		return fmt.Errorf("invalid min relay fee, must be at least 30 sats")
	}
	// round life time must be a multiple of 512
	if c.RoundLifetime < minAllowedSequence {
		return fmt.Errorf(
			"invalid round lifetime, must be a at least %d", minAllowedSequence,
		)
	}

	if c.UnilateralExitDelay < minAllowedSequence {
		return fmt.Errorf(
			"invalid unilateral exit delay, must at least %d", minAllowedSequence,
		)
	}

	if c.RoundLifetime%minAllowedSequence != 0 {
		c.RoundLifetime -= c.RoundLifetime % minAllowedSequence
		log.Infof(
			"round lifetime must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.RoundLifetime,
		)
	}

	if c.UnilateralExitDelay%minAllowedSequence != 0 {
		c.UnilateralExitDelay -= c.UnilateralExitDelay % minAllowedSequence
		log.Infof(
			"unilateral exit delay must be a multiple of %d, rounded to %d",
			minAllowedSequence, c.UnilateralExitDelay,
		)
	}

	if err := c.repoManager(); err != nil {
		return err
	}
	if err := c.walletService(); err != nil {
		return fmt.Errorf("failed to connect to wallet: %s", err)
	}
	if err := c.txBuilderService(); err != nil {
		return err
	}
	if err := c.scannerService(); err != nil {
		return err
	}
	if err := c.schedulerService(); err != nil {
		return err
	}
	if err := c.appService(); err != nil {
		return err
	}
	return nil
}

func (c *Config) AppService() application.Service {
	return c.svc
}

func (c *Config) repoManager() error {
	var svc ports.RepoManager
	var err error
	switch c.DbType {
	case "badger":
		logger := log.New()
		svc, err = db.NewService(db.ServiceConfig{
			EventStoreType: c.DbType,
			RoundStoreType: c.DbType,
			VtxoStoreType:  c.DbType,

			EventStoreConfig: []interface{}{c.DbDir, logger},
			RoundStoreConfig: []interface{}{c.DbDir, logger},
			VtxoStoreConfig:  []interface{}{c.DbDir, logger},
		})
	default:
		return fmt.Errorf("unknown db type")
	}
	if err != nil {
		return err
	}

	c.repo = svc
	return nil
}

func (c *Config) walletService() error {
	svc, err := oceanwallet.NewService(c.WalletAddr)
	if err != nil {
		return err
	}

	c.wallet = svc
	return nil
}

func (c *Config) txBuilderService() error {
	var svc ports.TxBuilder
	var err error
	net := c.mainChain()

	switch c.TxBuilderType {
	case "covenant":
		svc = txbuilder.NewTxBuilder(
			c.wallet, net, c.RoundLifetime, c.UnilateralExitDelay,
		)
	default:
		err = fmt.Errorf("unknown tx builder type")
	}
	if err != nil {
		return err
	}

	c.txBuilder = svc
	return nil
}

func (c *Config) scannerService() error {
	var svc ports.BlockchainScanner
	var err error
	switch c.BlockchainScannerType {
	case "ocean":
		svc = c.wallet
	default:
		err = fmt.Errorf("unknown blockchain scanner type")
	}
	if err != nil {
		return err
	}

	c.scanner = svc
	return nil
}

func (c *Config) schedulerService() error {
	var svc ports.SchedulerService
	var err error
	switch c.SchedulerType {
	case "gocron":
		svc = scheduler.NewScheduler()
	default:
		err = fmt.Errorf("unknown scheduler type")
	}
	if err != nil {
		return err
	}

	c.scheduler = svc
	return nil
}

func (c *Config) appService() error {
	net := c.mainChain()
	svc, err := application.NewService(
		c.Network, net,
		c.RoundInterval, c.RoundLifetime, c.UnilateralExitDelay, c.MinRelayFee,
		c.wallet, c.repo, c.txBuilder, c.scanner, c.scheduler,
	)
	if err != nil {
		return err
	}

	c.svc = svc
	return nil
}

func (c *Config) mainChain() network.Network {
	switch c.Network.Name {
	case "testnet":
		return network.Testnet
	case "regtest":
		return network.Regtest
	default:
		return network.Liquid
	}
}

type supportedType map[string]struct{}

func (t supportedType) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t supportedType) supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}
