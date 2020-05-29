// Package tests is a collection of staking token backend implementation tests.
package tests

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	tendermintTests "github.com/oasislabs/oasis-core/go/consensus/tendermint/tests"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/staking/tests/debug"
)

const recvTimeout = 5 * time.Second

// stakingTestsState holds the current state of staking tests.
type stakingTestsState struct {
	totalSupply *quantity.Quantity
	commonPool  *quantity.Quantity

	srcAccountGeneralBalance      quantity.Quantity
	srcAccountNonce               uint64
	srcAccountEscrowActiveBalance quantity.Quantity
	srcAccountEscrowActiveShares  quantity.Quantity

	destAccountGeneralBalance quantity.Quantity
}

func (s *stakingTestsState) update(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "update: TotalSupply")
	s.totalSupply = totalSupply

	commonPool, err := backend.CommonPool(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "update: CommonPool")
	s.commonPool = commonPool

	srcAccount, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "update: src: AccountInfo")
	s.srcAccountGeneralBalance = srcAccount.General.Balance
	s.srcAccountNonce = srcAccount.General.Nonce
	s.srcAccountEscrowActiveBalance = srcAccount.Escrow.Active.Balance
	s.srcAccountEscrowActiveShares = srcAccount.Escrow.Active.TotalShares

	destAccount, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: DestID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "update: dest: AccountInfo")
	s.destAccountGeneralBalance = destAccount.General.Balance
}

func newStakingTestsState(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) (state *stakingTestsState) {
	state = &stakingTestsState{}
	state.update(t, backend, consensus)
	return
}

var (
	debugGenesisState = debug.DebugGenesisState

	qtyOne = debug.QtyFromInt(1)

	srcSigner = debug.DebugStateSrcSigner
	SrcID     = debug.DebugStateSrcID
	DestID    = debug.DebugStateDestID
)

// StakingImplementationTests exercises the basic functionality of a
// staking token backend.
func StakingImplementationTests(
	t *testing.T,
	backend api.Backend,
	consensus consensusAPI.Backend,
	identity *identity.Identity,
	entity *entity.Entity,
	entitySigner signature.Signer,
	runtimeID common.Namespace,
) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, *stakingTestsState, api.Backend, consensusAPI.Backend)
	}{
		{"Thresholds", testThresholds},
		{"LastBlockFees", testLastBlockFees},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
		{"EscrowSelf", testSelfEscrow},
	} {
		state := newStakingTestsState(t, backend, consensus)
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, state, backend, consensus) })
	}

	// Separate test as it requires some arguments that others don't.
	t.Run("SlashDoubleSigning", func(t *testing.T) {
		state := newStakingTestsState(t, backend, consensus)
		testSlashDoubleSigning(t, state, backend, consensus, identity, entity, entitySigner, runtimeID)
	})
}

// StakingClientImplementationTests exercises the basic functionality of a
// staking token client backend.
func StakingClientImplementationTests(t *testing.T, backend api.Backend, consensus consensusAPI.Backend) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, *stakingTestsState, api.Backend, consensusAPI.Backend)
	}{
		{"Thresholds", testThresholds},
		{"LastBlockFees", testLastBlockFees},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
		{"EscrowSelf", testSelfEscrow},
	} {
		state := newStakingTestsState(t, backend, consensus)
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, state, backend, consensus) })
	}
}

func testThresholds(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	for _, kind := range []api.ThresholdKind{
		api.KindNodeValidator,
		api.KindNodeCompute,
		api.KindNodeStorage,
		api.KindNodeKeyManager,
		api.KindRuntimeCompute,
		api.KindRuntimeKeyManager,
	} {
		qty, err := backend.Threshold(context.Background(), &api.ThresholdQuery{Kind: kind, Height: consensusAPI.HeightLatest})
		require.NoError(err, "Threshold")
		require.NotNil(qty, "Threshold != nil")
		require.Equal(debugGenesisState.Parameters.Thresholds[kind], *qty, "Threshold - value")
	}
}

func testLastBlockFees(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	lastBlockFees, err := backend.LastBlockFees(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "LastBlockFees")
	require.True(lastBlockFees.IsZero(), "LastBlockFees - initial value")
}

func testTransfer(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	dstAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: DestID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: AccountInfo")

	srcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - before")

	ch, sub, err := backend.WatchTransfers(context.Background())
	require.NoError(err, "WatchTransfers")
	defer sub.Close()

	xfer := &api.Transfer{
		To:     DestID,
		Tokens: debug.QtyFromInt(math.MaxUint8),
	}
	tx := api.NewTransferTx(srcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "Transfer")

	var gotCommon bool
	var gotFeeAcc bool
	var gotTransfer bool

TransferWaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.From.Equal(api.CommonPoolAddress) || ev.To.Equal(api.CommonPoolAddress) {
				gotCommon = true
				continue
			}
			if ev.From.Equal(api.FeeAccumulatorAddress) || ev.To.Equal(api.FeeAccumulatorAddress) {
				gotFeeAcc = true
				continue
			}

			if !gotTransfer {
				require.Equal(SrcID, ev.From, "Event: from")
				require.Equal(DestID, ev.To, "Event: to")
				require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")

				// Make sure that GetEvents also returns the transfer event.
				evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
				require.NoError(grr, "GetEvents")
				for _, evt := range evts {
					if evt.TransferEvent != nil {
						if evt.TransferEvent.From.Equal(ev.From) && evt.TransferEvent.To.Equal(ev.To) && evt.TransferEvent.Tokens.Cmp(&ev.Tokens) == 0 {
							gotTransfer = true
							require.True(!evt.TxHash.IsEmpty(), "GetEvents should return valid txn hash")
							break
						}
					}
				}
				require.True(gotTransfer, "GetEvents should return transfer event")
			}

			if (gotCommon || gotFeeAcc) && gotTransfer {
				break TransferWaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive transfer event")
		}
	}

	require.True(gotCommon || gotFeeAcc, "WatchTransfers should also return transfers related to the common pool and/or the fee accumulator")

	_ = srcAcc.General.Balance.Sub(&xfer.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	_ = dstAcc.General.Balance.Add(&xfer.Tokens)
	newDstAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: DestID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dest: AccountInfo - after")
	require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dest: general balance - after")
	require.EqualValues(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dest: nonce - after")

	// Transfers that exceed available balance should fail.
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Tokens = newSrcAcc.General.Balance

	tx = api.NewTransferTx(newSrcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.Error(err, "Transfer - more than available balance")
}

func testSelfTransfer(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	srcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - before")

	ch, sub, err := backend.WatchTransfers(context.Background())
	require.NoError(err, "WatchTransfers")
	defer sub.Close()

	xfer := &api.Transfer{
		To:     SrcID,
		Tokens: debug.QtyFromInt(math.MaxUint8),
	}
	tx := api.NewTransferTx(srcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "Transfer")

	var gotCommon bool
	var gotFeeAcc bool
	var gotTransfer bool

TransferWaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.From.Equal(api.CommonPoolAddress) || ev.To.Equal(api.CommonPoolAddress) {
				gotCommon = true
				continue
			}
			if ev.From.Equal(api.FeeAccumulatorAddress) || ev.To.Equal(api.FeeAccumulatorAddress) {
				gotFeeAcc = true
				continue
			}

			if !gotTransfer {
				require.Equal(SrcID, ev.From, "Event: from")
				require.Equal(SrcID, ev.To, "Event: to")
				require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")
				gotTransfer = true
			}

			if (gotCommon || gotFeeAcc) && gotTransfer {
				break TransferWaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive transfer event")
		}
	}

	require.True(gotCommon || gotFeeAcc, "WatchTransfers should also return transfers related to the common pool and/or the fee accumulator")

	newSrcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	// Self transfers that are more than the balance should fail.
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Tokens = newSrcAcc.General.Balance

	tx = api.NewTransferTx(newSrcAcc.General.Nonce, nil, xfer)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.Error(err, "Transfer - more than available balance")
}

func testBurn(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "TotalSupply - before")

	srcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo")

	ch, sub, err := backend.WatchBurns(context.Background())
	require.NoError(err, "WatchBurns")
	defer sub.Close()

	burn := &api.Burn{
		Tokens: debug.QtyFromInt(math.MaxUint32),
	}
	tx := api.NewBurnTx(srcAcc.General.Nonce, nil, burn)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "Burn")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(burn.Tokens, ev.Tokens, "Event: tokens")

		// Make sure that GetEvents also returns the burn event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.BurnEvent != nil {
				if evt.BurnEvent.Owner.Equal(ev.Owner) && evt.BurnEvent.Tokens.Cmp(&ev.Tokens) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return burn event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive burn event")
	}

	_ = totalSupply.Sub(&burn.Tokens)
	newTotalSupply, err := backend.TotalSupply(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "TotalSupply - after")
	require.Equal(totalSupply, newTotalSupply, "totalSupply is reduced by burn")

	_ = srcAcc.General.Balance.Sub(&burn.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.EqualValues(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testEscrowEx(t, state, backend, consensus, SrcID, srcSigner, DestID)
}

func testSelfEscrow(t *testing.T, state *stakingTestsState, backend api.Backend, consensus consensusAPI.Backend) {
	testEscrowEx(t, state, backend, consensus, SrcID, srcSigner, SrcID)
}

func testEscrowEx( // nolint: gocyclo
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	srcID signature.PublicKey,
	srcSigner signature.Signer,
	dstID signature.PublicKey,
) {
	require := require.New(t)

	srcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - before")
	require.False(srcAcc.General.Balance.IsZero(), "src: general balance != 0")
	require.Equal(state.srcAccountEscrowActiveBalance, srcAcc.Escrow.Active.Balance, "src: active escrow balance")
	require.Equal(state.srcAccountEscrowActiveShares, srcAcc.Escrow.Active.TotalShares, "src: active escrow total shares")
	require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0")
	require.True(srcAcc.Escrow.Debonding.TotalShares.IsZero(), "src: debonding escrow total shares == 0")

	dstAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: dstID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: AccountInfo - before")
	if !srcID.Equal(dstID) {
		require.True(dstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0")
		require.True(dstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0")
	}
	require.True(dstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0")
	require.True(dstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0")

	ch, sub, err := backend.WatchEscrows(context.Background())
	require.NoError(err, "WatchEscrows")
	defer sub.Close()

	totalEscrowed := dstAcc.Escrow.Active.Balance.Clone()

	// Escrow.
	escrow := &api.Escrow{
		Account: dstID,
		Tokens:  debug.QtyFromInt(math.MaxUint32),
	}
	tx := api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Tokens))

	select {
	case rawEv := <-ch:
		ev := rawEv.Add
		require.NotNil(ev)
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(dstID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")

		// Make sure that GetEvents also returns the add escrow event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.EscrowEvent != nil && evt.EscrowEvent.Add != nil {
				if evt.EscrowEvent.Add.Owner.Equal(ev.Owner) && evt.EscrowEvent.Add.Escrow.Equal(ev.Escrow) && evt.EscrowEvent.Add.Tokens.Cmp(&ev.Tokens) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return add escrow event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	currentTotalShares := dstAcc.Escrow.Active.TotalShares.Clone()
	_ = dstAcc.Escrow.Active.Deposit(currentTotalShares, &srcAcc.General.Balance, &escrow.Tokens)

	newSrcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	if !srcID.Equal(dstID) {
		require.Equal(state.srcAccountEscrowActiveBalance, newSrcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	newDstAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: dstID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: AccountInfo - after")
	if !srcID.Equal(dstID) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after")
	require.Equal(dstAcc.Escrow.Active.TotalShares, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Escrow some more.
	escrow = &api.Escrow{
		Account: dstID,
		Tokens:  debug.QtyFromInt(math.MaxUint32),
	}
	tx = api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Tokens))

	select {
	case rawEv := <-ch:
		ev := rawEv.Add
		require.NotNil(ev)
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(dstID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")

		// Make sure that GetEvents also returns the add escrow event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.EscrowEvent != nil && evt.EscrowEvent.Add != nil {
				if evt.EscrowEvent.Add.Owner.Equal(ev.Owner) && evt.EscrowEvent.Add.Escrow.Equal(ev.Escrow) && evt.EscrowEvent.Add.Tokens.Cmp(&ev.Tokens) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return add escrow event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	currentTotalShares = dstAcc.Escrow.Active.TotalShares.Clone()
	_ = dstAcc.Escrow.Active.Deposit(currentTotalShares, &srcAcc.General.Balance, &escrow.Tokens)

	newSrcAcc, err = backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - after 2nd")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after 2nd")
	if !srcID.Equal(dstID) {
		require.Equal(state.srcAccountEscrowActiveBalance, newSrcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after 2nd")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after 2nd")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after 2nd")

	newDstAcc, err = backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: dstID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: AccountInfo - after 2nd")
	if !srcID.Equal(dstID) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after 2nd")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after 2nd")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after 2nd")
	require.Equal(dstAcc.Escrow.Active.TotalShares, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after 2nd")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Reclaim escrow (subject to debonding).
	debs, err := backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - before")
	require.Len(debs, 0, "no debonding delegations before reclaiming escrow")

	reclaim := &api.ReclaimEscrow{
		Account: dstID,
		Shares:  dstAcc.Escrow.Active.TotalShares,
	}
	tx = api.NewReclaimEscrowTx(srcAcc.General.Nonce, nil, reclaim)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "ReclaimEscrow")

	// Query debonding delegations.
	debs, err = backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - after (in debonding)")
	require.Len(debs, 1, "one debonding delegation after reclaiming escrow")
	require.Len(debs[dstID], 1, "one debonding delegation after reclaiming escrow")

	// Advance epoch to trigger debonding.
	timeSource := consensus.EpochTime().(epochtime.SetableBackend)
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for debonding period to pass.
	select {
	case rawEv := <-ch:
		ev := rawEv.Reclaim
		require.NotNil(ev)
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(dstID, ev.Escrow, "Event: escrow")
		require.Equal(totalEscrowed, &ev.Tokens, "Event: tokens")

		// Make sure that GetEvents also returns the reclaim escrow event.
		evts, grr := backend.GetEvents(context.Background(), consensusAPI.HeightLatest)
		require.NoError(grr, "GetEvents")
		var gotIt bool
		for _, evt := range evts {
			if evt.EscrowEvent != nil && evt.EscrowEvent.Reclaim != nil {
				if evt.EscrowEvent.Reclaim.Owner.Equal(ev.Owner) && evt.EscrowEvent.Reclaim.Escrow.Equal(ev.Escrow) && evt.EscrowEvent.Reclaim.Tokens.Cmp(&ev.Tokens) == 0 {
					gotIt = true
					break
				}
			}
		}
		require.EqualValues(true, gotIt, "GetEvents should return reclaim escrow event")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive reclaim escrow event")
	}

	_ = srcAcc.General.Balance.Add(totalEscrowed)
	newSrcAcc, err = backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "src: AccountInfo - after debond")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after debond")
	if !srcID.Equal(dstID) {
		require.Equal(state.srcAccountEscrowActiveBalance, srcAcc.Escrow.Active.Balance, "src: active escrow balance unchanged - after debond")
		require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after debond")
	}
	require.Equal(tx.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after debond")

	newDstAcc, err = backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: dstID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "dst: AccountInfo - after debond")
	if !srcID.Equal(dstID) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after debond")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after debond")
	}
	require.True(newDstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after debond")

	debs, err = backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations - after (debonding completed)")
	require.Len(debs, 0, "no debonding delegations after debonding has completed")

	// Reclaim escrow (without enough shares).
	reclaim = &api.ReclaimEscrow{
		Account: dstID,
		Shares:  reclaim.Shares,
	}
	tx = api.NewReclaimEscrowTx(newSrcAcc.General.Nonce, nil, reclaim)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.Error(err, "ReclaimEscrow")

	debs, err = backend.DebondingDelegations(context.Background(), &api.OwnerQuery{Owner: srcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "DebondingDelegations")
	require.Len(debs, 0, "no debonding delegations after failed reclaim")

	// Escrow less than the minimum amount.
	escrow = &api.Escrow{
		Account: dstID,
		Tokens:  debug.QtyFromInt(1), // Minimum is 10.
	}
	tx = api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.Error(err, "AddEscrow")
}

func testSlashDoubleSigning(
	t *testing.T,
	state *stakingTestsState,
	backend api.Backend,
	consensus consensusAPI.Backend,
	ident *identity.Identity,
	ent *entity.Entity,
	entSigner signature.Signer,
	runtimeID common.Namespace,
) {
	require := require.New(t)

	// Delegate some stake to the validator so we can check if slashing works.
	srcAcc, err := backend.AccountInfo(context.Background(), &api.OwnerQuery{Owner: SrcID, Height: consensusAPI.HeightLatest})
	require.NoError(err, "AccountInfo")

	escrowCh, escrowSub, err := backend.WatchEscrows(context.Background())
	require.NoError(err, "WatchEscrows")
	defer escrowSub.Close()

	escrow := &api.Escrow{
		Account: ent.ID,
		Tokens:  debug.QtyFromInt(math.MaxUint32),
	}
	tx := api.NewAddEscrowTx(srcAcc.General.Nonce, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, srcSigner, tx)
	require.NoError(err, "AddEscrow")

	select {
	case rawEv := <-escrowCh:
		ev := rawEv.Add
		require.NotNil(ev)
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(ent.ID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	// Subscribe to roothash blocks.
	blocksCh, blocksSub, err := consensus.RootHash().WatchBlocks(runtimeID)
	require.NoError(err, "WatchBlocks")
	defer blocksSub.Close()

	// Subscribe to slash events.
	slashCh, slashSub, err := backend.WatchEscrows(context.Background())
	require.NoError(err, "WatchEscrows")
	defer slashSub.Close()

	// Broadcast evidence. This is Tendermint-specific, if we ever have more than one
	// consensus backend, we need to change this part.
	err = consensus.SubmitEvidence(context.Background(), tendermintTests.MakeDoubleSignEvidence(t, ident))
	require.NoError(err, "SubmitEvidence")

	// Wait for the node to get slashed.
WaitLoop:
	for {
		select {
		case ev := <-slashCh:
			if e := ev.Take; e != nil {
				require.Equal(ent.ID, e.Owner, "TakeEscrowEvent - owner must be entity")
				// All tokens must be slashed as defined in debugGenesisState.
				require.Equal(escrow.Tokens, e.Tokens, "TakeEscrowEvent - all tokens slashed")
				break WaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive slash event")
		}
	}

	// Make sure the node is frozen.
	nodeStatus, err := consensus.Registry().GetNodeStatus(context.Background(), &registry.IDQuery{ID: ident.NodeSigner.Public(), Height: consensusAPI.HeightLatest})
	require.NoError(err, "GetNodeStatus")
	require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
	require.True(nodeStatus.IsFrozen(), "IsFrozen() should return true")

	// Make sure node cannot be unfrozen.
	tx = registry.NewUnfreezeNodeTx(0, nil, &registry.UnfreezeNode{
		NodeID: ident.NodeSigner.Public(),
	})
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, entSigner, tx)
	require.Error(err, "UnfreezeNode should fail")

	// Wait for roothash block as re-scheduling must have taken place due to slashing.
	select {
	case blk := <-blocksCh:
		require.Equal(block.EpochTransition, blk.Block.Header.HeaderType)
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive roothash block")
	}

	// Advance epoch to make the freeze period expire.
	timeSource := consensus.EpochTime().(epochtime.SetableBackend)
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Unfreeze node (now it should work).
	tx = registry.NewUnfreezeNodeTx(0, nil, &registry.UnfreezeNode{
		NodeID: ident.NodeSigner.Public(),
	})
	err = consensusAPI.SignAndSubmitTx(context.Background(), consensus, entSigner, tx)
	require.NoError(err, "UnfreezeNode")

	// Advance epoch to restore committees.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Make sure the node is no longer frozen.
	nodeStatus, err = consensus.Registry().GetNodeStatus(context.Background(), &registry.IDQuery{ID: ident.NodeSigner.Public(), Height: consensusAPI.HeightLatest})
	require.NoError(err, "GetNodeStatus")
	require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
	require.False(nodeStatus.IsFrozen(), "IsFrozen() should return false")
}
