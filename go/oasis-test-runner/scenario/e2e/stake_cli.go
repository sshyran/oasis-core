package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/stake"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	// Init balance in the genesis block.
	initBalance = 100_000_000_000

	// Test transfer amount.
	transferAmount = 1000

	// Test burn amount.
	burnAmount = 2000

	// Test escrow amount.
	escrowAmount = 3000

	// Test reclaim escrow shares.
	reclaimEscrowShares = 1234

	// Transaction fee amount.
	feeAmount = 10

	// Transaction fee gas.
	feeGas = 10000

	// Source address in the genesis block.
	srcAddress = "4ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35"

	// Test transfer destination address.
	transferAddress = "5ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35"

	// Test escrow address.
	escrowAddress = "6ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35"
)

var (
	// StakeCLI is the staking scenario.
	StakeCLI scenario.Scenario = &stakeCLIImpl{
		runtimeImpl: *newRuntimeImpl("stake-cli", "", nil),
	}
)

type stakeCLIImpl struct {
	runtimeImpl
}

func (s *stakeCLIImpl) Clone() scenario.Scenario {
	return &stakeCLIImpl{
		runtimeImpl: *s.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (s *stakeCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := s.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// We will mock epochs for reclaiming the escrow.
	f.Network.EpochtimeMock = true

	// Enable some features in the staking system that we'll test.
	f.Network.StakingGenesis = "tests/fixture-data/stake-cli/staking-genesis.json"

	return f, nil
}

func (s *stakeCLIImpl) Run(childEnv *env.Env) error {
	if err := s.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()
	s.logger.Info("waiting for nodes to register")
	if err := s.net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("waiting for nodes to register: %w", err)
	}
	s.logger.Info("nodes registered")

	cli := cli.New(childEnv, s.net, s.logger)

	// General token info.
	if err := s.getInfo(childEnv); err != nil {
		return err
	}

	// Account list.
	accounts, err := s.listAccounts(childEnv)
	if err != nil {
		return err
	}
	// In the genesis block, only one account should have a balance.
	if len(accounts) < 1 {
		return fmt.Errorf("scenario/e2e/stake: initial stake list wrong number of accounts: %d, expected at least: %d. Accounts: %s", len(accounts), 1, accounts)
	}

	// Ensure the source account is in the list.
	var src signature.PublicKey
	if err = src.UnmarshalHex(srcAddress); err != nil {
		return err
	}
	var found bool
	for _, a := range accounts {
		if bytes.Equal(a[:], src[:]) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("scenario/e2e/stake: src account not found: %s", src.String())
	}
	// Define a new destination account.
	var dst signature.PublicKey
	if err = dst.UnmarshalHex(transferAddress); err != nil {
		return err
	}
	// Define escrow account.
	var escrow signature.PublicKey
	if err = escrow.UnmarshalHex(escrowAddress); err != nil {
		return err
	}

	// Run the tests
	// Transfer
	if err = s.testTransfer(childEnv, cli, src, dst); err != nil {
		return fmt.Errorf("scenario/e2e/stake: error while running Transfer test: %w", err)
	}

	// Burn
	if err = s.testBurn(childEnv, cli, src); err != nil {
		return fmt.Errorf("scenario/e2e/stake: error while running Burn test: %w", err)
	}

	// Escrow
	if err = s.testEscrow(childEnv, cli, src, escrow); err != nil {
		return fmt.Errorf("scenario/e2e/stake: error while running Escrow test: %w", err)
	}

	// ReclaimEscrow
	if err = s.testReclaimEscrow(childEnv, cli, src, escrow); err != nil {
		return fmt.Errorf("scenario/e2e/stake: error while running ReclaimEscrow test: %w", err)
	}

	// AmendCommissionSchedule
	if err = s.testAmendCommissionSchedule(childEnv, cli, src); err != nil {
		return fmt.Errorf("scenario/e2e/stake: error while running AmendCommissionSchedule: %w", err)
	}

	// Stop the network.
	s.logger.Info("stopping the network")
	s.net.Stop()

	return nil
}

// testTransfer tests transfer of transferAmount tokens from src to dst.
func (s *stakeCLIImpl) testTransfer(childEnv *env.Env, cli *cli.Helpers, src signature.PublicKey, dst signature.PublicKey) error {
	transferTxPath := filepath.Join(childEnv.Dir(), "stake_transfer.json")
	if err := s.genTransferTx(childEnv, transferAmount, 0, dst, transferTxPath); err != nil {
		return err
	}
	if err := s.showTx(childEnv, transferTxPath); err != nil {
		return err
	}
	if err := s.checkBalance(childEnv, src, initBalance); err != nil {
		return err
	}
	if err := s.checkBalance(childEnv, dst, 0); err != nil {
		return err
	}

	if err := cli.Consensus.SubmitTx(transferTxPath); err != nil {
		return err
	}

	if err := s.checkBalance(childEnv, src, initBalance-transferAmount-feeAmount); err != nil {
		return err
	}
	if err := s.checkBalance(childEnv, dst, transferAmount); err != nil {
		return err
	}
	accounts, err := s.listAccounts(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 2 {
		return fmt.Errorf("scenario/e2e/stake: post-transfer stake list wrong number of accounts: %d, expected at least: %d. Accounts: %s", len(accounts), 2, accounts)
	}

	return nil
}

// testBurn tests burning of burnAmount tokens owned by src.
func (s *stakeCLIImpl) testBurn(childEnv *env.Env, cli *cli.Helpers, src signature.PublicKey) error {
	burnTxPath := filepath.Join(childEnv.Dir(), "stake_burn.json")
	if err := s.genBurnTx(childEnv, burnAmount, 1, burnTxPath); err != nil {
		return err
	}
	if err := s.showTx(childEnv, burnTxPath); err != nil {
		return err
	}

	if err := cli.Consensus.SubmitTx(burnTxPath); err != nil {
		return err
	}

	if err := s.checkBalance(childEnv, src, initBalance-transferAmount-burnAmount-2*feeAmount); err != nil {
		return err
	}
	accounts, err := s.listAccounts(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 2 {
		return fmt.Errorf("scenario/e2e/stake: post-burn stake list wrong number of accounts: %d, expected at least: %d", len(accounts), 2)
	}

	return nil
}

// testEscrow tests escrowing escrowAmount tokens from src to dst.
func (s *stakeCLIImpl) testEscrow(childEnv *env.Env, cli *cli.Helpers, src signature.PublicKey, escrow signature.PublicKey) error {
	escrowTxPath := filepath.Join(childEnv.Dir(), "stake_escrow.json")
	if err := s.genEscrowTx(childEnv, escrowAmount, 2, escrow, escrowTxPath); err != nil {
		return err
	}
	if err := s.showTx(childEnv, escrowTxPath); err != nil {
		return err
	}

	if err := cli.Consensus.SubmitTx(escrowTxPath); err != nil {
		return err
	}

	if err := s.checkBalance(childEnv, src, initBalance-transferAmount-burnAmount-escrowAmount-3*feeAmount); err != nil {
		return err
	}
	if err := s.checkEscrowBalance(childEnv, escrow, escrowAmount); err != nil {
		return err
	}
	accounts, err := s.listAccounts(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 3 {
		return fmt.Errorf("scenario/e2e/stake: post-escrow stake list wrong number of accounts: %d, expected at least: %d", len(accounts), 3)
	}

	return nil
}

// testReclaimEscrow test reclaiming reclaimEscrowShares shares from an escrow account.
func (s *stakeCLIImpl) testReclaimEscrow(childEnv *env.Env, cli *cli.Helpers, src signature.PublicKey, escrow signature.PublicKey) error {
	reclaimEscrowTxPath := filepath.Join(childEnv.Dir(), "stake_reclaim_escrow.json")
	if err := s.genReclaimEscrowTx(childEnv, reclaimEscrowShares, 3, escrow, reclaimEscrowTxPath); err != nil {
		return err
	}
	if err := s.showTx(childEnv, reclaimEscrowTxPath); err != nil {
		return err
	}

	if err := cli.Consensus.SubmitTx(reclaimEscrowTxPath); err != nil {
		return err

	}
	// Advance epochs to trigger reclaim processing.
	if err := s.net.Controller().SetEpoch(context.Background(), 1); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}

	// Since we are the only ones who put tokens into the escrow account and there was no slashing,
	// we can expect the reclaimed escrow amount to equal the number of reclaimed escrow shares.
	var reclaimEscrowAmount int64 = reclaimEscrowShares
	if err := s.checkBalance(childEnv, src, initBalance-transferAmount-burnAmount-escrowAmount+reclaimEscrowAmount-4*feeAmount); err != nil {
		return err
	}
	if err := s.checkEscrowBalance(childEnv, escrow, escrowAmount-reclaimEscrowAmount); err != nil {
		return err
	}
	accounts, err := s.listAccounts(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 3 {
		return fmt.Errorf("scenario/e2e/stake: post-reclaim-escrow stake list wrong number of accounts: %d, expected: %d", len(accounts), 3)
	}

	return nil
}

func mustInitQuantity(i int64) (q quantity.Quantity) {
	if err := q.FromInt64(i); err != nil {
		panic(fmt.Sprintf("FromInt64: %+v", err))
	}
	return
}

func (s *stakeCLIImpl) testAmendCommissionSchedule(childEnv *env.Env, cli *cli.Helpers, src signature.PublicKey) error {
	amendCommissionScheduleTxPath := filepath.Join(childEnv.Dir(), "amend_commission_schedule.json")
	if err := s.genAmendCommissionScheduleTx(childEnv, 4, &api.CommissionSchedule{
		Rates: []api.CommissionRateStep{
			{
				Start: 40,
				Rate:  mustInitQuantity(50_000),
			},
		},
		Bounds: []api.CommissionRateBoundStep{
			{
				Start:   40,
				RateMin: mustInitQuantity(0),
				RateMax: mustInitQuantity(100_000),
			},
		},
	}, amendCommissionScheduleTxPath); err != nil {
		return err
	}
	if err := s.showTx(childEnv, amendCommissionScheduleTxPath); err != nil {
		return err
	}

	if err := cli.Consensus.SubmitTx(amendCommissionScheduleTxPath); err != nil {
		return err
	}

	// todo: check that it was applied

	return nil
}

func (s *stakeCLIImpl) getInfo(childEnv *env.Env) error {
	s.logger.Info("querying common token info")
	args := []string{
		"stake", "info",
		"--" + grpc.CfgAddress, "unix:" + s.runtimeImpl.net.Validators()[0].SocketPath(),
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "info", s.runtimeImpl.net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("scenario/e2e/stake: failed to query common token info: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *stakeCLIImpl) listAccounts(childEnv *env.Env) ([]signature.PublicKey, error) {
	s.logger.Info("listing all accounts")
	args := []string{
		"stake", "list",
		"--" + grpc.CfgAddress, "unix:" + s.runtimeImpl.net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "list", s.runtimeImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/stake: failed to list accounts: error: %w output: %s", err, out.String())
	}
	accountsStr := strings.Split(out.String(), "\n")

	var accounts []signature.PublicKey
	for _, accStr := range accountsStr {
		// Ignore last newline.
		if accStr == "" {
			continue
		}

		var acc signature.PublicKey
		if err = acc.UnmarshalText([]byte(accStr)); err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}

	return accounts, nil
}

func (s *stakeCLIImpl) getAccountInfo(childEnv *env.Env, src signature.PublicKey) (*api.Account, error) {
	s.logger.Info("checking account balance", stake.CfgAccountAddr, src.String())
	args := []string{
		"stake", "account", "info",
		"--" + stake.CfgAccountAddr, src.String(),
		"--" + grpc.CfgAddress, "unix:" + s.runtimeImpl.net.Validators()[0].SocketPath(),
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "info", s.runtimeImpl.net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("scenario/e2e/stake: failed to check account info: error: %w output: %s", err, out.String())
	}

	var acct api.Account
	if err = json.Unmarshal(out.Bytes(), &acct); err != nil {
		return nil, err
	}

	return &acct, nil
}

func (s *stakeCLIImpl) checkBalance(childEnv *env.Env, src signature.PublicKey, expected int64) error {
	ai, err := s.getAccountInfo(childEnv, src)
	if err != nil {
		return err
	}

	var q quantity.Quantity
	if err = q.FromBigInt(big.NewInt(expected)); err != nil {
		return err
	}
	if ai.General.Balance.Cmp(&q) != 0 {
		return fmt.Errorf("checkBalance: wrong general balance of account. Expected %s got %s", q, ai.General.Balance)
	}

	return nil
}

func (s *stakeCLIImpl) checkEscrowBalance(childEnv *env.Env, src signature.PublicKey, expected int64) error {
	ai, err := s.getAccountInfo(childEnv, src)
	if err != nil {
		return err
	}

	var q quantity.Quantity
	if err = q.FromBigInt(big.NewInt(expected)); err != nil {
		return err
	}
	if ai.Escrow.Active.Balance.Cmp(&q) != 0 {
		return fmt.Errorf("checkEscrowBalance: wrong escrow balance of account. Expected %s got %s", q, ai.Escrow.Active.Balance)
	}

	return nil
}

func (s *stakeCLIImpl) showTx(childEnv *env.Env, txPath string) error {
	s.logger.Info("pretty printing generated transaction")

	args := []string{
		"consensus", "show_tx",
		"--" + consensus.CfgTxFile, txPath,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgGenesisFile, s.runtimeImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "show_tx", s.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("showTx: failed to show tx: error: %w, output: %s", err, out.String())
	}
	return nil
}

func (s *stakeCLIImpl) genTransferTx(childEnv *env.Env, amount int, nonce int, dst signature.PublicKey, txPath string) error {
	s.logger.Info("generating stake transfer tx", stake.CfgTransferDestination, dst)

	args := []string{
		"stake", "account", "gen_transfer",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgTransferDestination, dst.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, s.runtimeImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "gen_transfer", s.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genTransferTx: failed to generate transfer tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *stakeCLIImpl) genBurnTx(childEnv *env.Env, amount int, nonce int, txPath string) error {
	s.logger.Info("generating stake burn tx")

	args := []string{
		"stake", "account", "gen_burn",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, s.runtimeImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "gen_burn", s.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genBurnTx: failed to generate burn tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *stakeCLIImpl) genEscrowTx(childEnv *env.Env, amount int, nonce int, escrow signature.PublicKey, txPath string) error {
	s.logger.Info("generating stake escrow tx", "stake.CfgEscrowAccount", escrow)

	args := []string{
		"stake", "account", "gen_escrow",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgEscrowAccount, escrow.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, s.runtimeImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "gen_escrow", s.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genEscrowTx: failed to generate escrow tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *stakeCLIImpl) genReclaimEscrowTx(childEnv *env.Env, shares int, nonce int, escrow signature.PublicKey, txPath string) error {
	s.logger.Info("generating stake reclaim escrow tx", stake.CfgEscrowAccount, escrow)

	args := []string{
		"stake", "account", "gen_reclaim_escrow",
		"--" + stake.CfgShares, strconv.Itoa(shares),
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgEscrowAccount, escrow.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, s.runtimeImpl.net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "gen_reclaim_escrow", s.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genReclaimEscrowTx: failed to generate reclaim escrow tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (s *stakeCLIImpl) genAmendCommissionScheduleTx(childEnv *env.Env, nonce int, cs *api.CommissionSchedule, txPath string) error {
	s.logger.Info("generating stake amend commission schedule tx", "commission_schedule", cs)

	args := []string{
		"stake", "account", "gen_amend_commission_schedule",
		"--" + consensus.CfgTxNonce, strconv.Itoa(nonce),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, s.runtimeImpl.net.GenesisPath(),
	}
	for _, step := range cs.Rates {
		args = append(args, "--"+stake.CfgCommissionScheduleRates, fmt.Sprintf("%d/%d", step.Start, step.Rate.ToBigInt()))
	}
	for _, step := range cs.Bounds {
		args = append(args, "--"+stake.CfgCommissionScheduleBounds, fmt.Sprintf("%d/%d/%d", step.Start, step.RateMin.ToBigInt(), step.RateMax.ToBigInt()))
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, s.logger, "gen_amend_commission_schedule", s.runtimeImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genAmendCommissionScheduleTx: failed to generate amend commission schedule tx: error: %w output: %s", err, out.String())
	}
	return nil
}
