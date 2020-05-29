package staking

import (
	"context"

	"github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	abciAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var _ abci.TransactionAuthHandler = (*stakingApplication)(nil)

// Implements abci.TransactionAuthHandler.
func (app *stakingApplication) GetSignerNonce(ctx context.Context, req *api.GetSignerNonceRequest) (uint64, error) {
	q, err := app.QueryFactory().(*QueryFactory).QueryAt(ctx, req.Height)
	if err != nil {
		return 0, err
	}

	addr := staking.NewFromPublicKey(req.ID)
	acct, err := q.AccountInfo(ctx, addr)
	if err != nil {
		return 0, err
	}
	return acct.General.Nonce, nil
}

// Implements abci.TransactionAuthHandler.
func (app *stakingApplication) AuthenticateTx(ctx *abciAPI.Context, tx *transaction.Transaction) error {
	return stakingState.AuthenticateAndPayFees(ctx, ctx.TxSigner(), tx.Nonce, tx.Fee)
}
