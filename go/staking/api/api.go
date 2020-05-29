// Package api implements the staking backend API.
package api

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

const (
	// ModuleName is a unique module name for the staking module.
	ModuleName = "staking"

	// LogEventGeneralAdjustment is a log event value that signals adjustment
	// of an account's general balance due to a roothash message.
	LogEventGeneralAdjustment = "staking/general_adjustment"
)

var (
	// CommonPoolAddress signifies the common pool in staking events.
	// The address is invalid to prevent it being accidentally used in the actual ledger.
	CommonPoolAddress = NewFromPublicKey(
		signature.NewBlacklistedKey("1abe11edc001ffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

	// FeeAccumulatorAddress signifies the staking fee accumulator in staking events.
	// The address is invalid to prevent it being accidentally used in the actual ledger.
	FeeAccumulatorAddress = NewFromPublicKey(
		signature.NewBlacklistedKey("1abe11edfeeaccffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

	// ErrInvalidArgument is the error returned on malformed arguments.
	ErrInvalidArgument = errors.New(ModuleName, 1, "staking: invalid argument")

	// ErrInvalidSignature is the error returned on invalid signature.
	ErrInvalidSignature = errors.New(ModuleName, 2, "staking: invalid signature")

	// ErrInsufficientBalance is the error returned when an operation
	// fails due to insufficient balance.
	ErrInsufficientBalance = errors.New(ModuleName, 3, "staking: insufficient balance")

	// ErrInsufficientStake is the error returned when an operation fails
	// due to insufficient stake.
	ErrInsufficientStake = errors.New(ModuleName, 4, "staking: insufficient stake")

	// ErrForbidden is the error returned when an operation is forbiden by
	// policy.
	ErrForbidden = errors.New(ModuleName, 5, "staking: forbidden by policy")

	// ErrInvalidThreshold is the error returned when an invalid threshold kind
	// is specified in a query.
	ErrInvalidThreshold = errors.New(ModuleName, 6, "staking: invalid threshold")

	// MethodTransfer is the method name for transfers.
	MethodTransfer = transaction.NewMethodName(ModuleName, "Transfer", Transfer{})
	// MethodBurn is the method name for burns.
	MethodBurn = transaction.NewMethodName(ModuleName, "Burn", Burn{})
	// MethodAddEscrow is the method name for escrows.
	MethodAddEscrow = transaction.NewMethodName(ModuleName, "AddEscrow", Escrow{})
	// MethodReclaimEscrow is the method name for escrow reclamations.
	MethodReclaimEscrow = transaction.NewMethodName(ModuleName, "ReclaimEscrow", ReclaimEscrow{})
	// MethodAmendCommissionSchedule is the method name for amending commission schedules.
	MethodAmendCommissionSchedule = transaction.NewMethodName(ModuleName, "AmendCommissionSchedule", AmendCommissionSchedule{})

	// Methods is the list of all methods supported by the staking backend.
	Methods = []transaction.MethodName{
		MethodTransfer,
		MethodBurn,
		MethodAddEscrow,
		MethodReclaimEscrow,
		MethodAmendCommissionSchedule,
	}
)

// Backend is a staking token implementation.
type Backend interface {
	// TotalSupply returns the total number of tokens.
	TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error)

	// CommonPool returns the common pool balance.
	CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error)

	// LastBlockFees returns the collected fees for previous block.
	LastBlockFees(ctx context.Context, height int64) (*quantity.Quantity, error)

	// Threshold returns the specific staking threshold by kind.
	Threshold(ctx context.Context, query *ThresholdQuery) (*quantity.Quantity, error)

	// Accounts returns the addresses of all accounts with a non-zero general or
	// escrow balance.
	Accounts(ctx context.Context, height int64) ([]Address, error)

	// AccountInfo returns the account descriptor for the given account.
	AccountInfo(ctx context.Context, query *OwnerQuery) (*Account, error)

	// Delegations returns the list of delegations for the given owner
	// (delegator).
	Delegations(ctx context.Context, query *OwnerQuery) (map[Address]*Delegation, error)

	// DebondingDelegations returns the list of debonding delegations for
	// the given owner (delegator).
	DebondingDelegations(ctx context.Context, query *OwnerQuery) (map[Address][]*DebondingDelegation, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// Paremeters returns the staking consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

	// WatchTransfers returns a channel that produces a stream of TranserEvent
	// on all balance transfers.
	WatchTransfers(ctx context.Context) (<-chan *TransferEvent, pubsub.ClosableSubscription, error)

	// WatchBurns returns a channel of BurnEvent on token destruction.
	WatchBurns(ctx context.Context) (<-chan *BurnEvent, pubsub.ClosableSubscription, error)

	// WatchEscrows returns a channel that produces a stream of EscrowEvent
	// when entities add to their escrow balance, get tokens deducted from
	// their escrow balance, and have their escrow balance released into their
	// general balance.
	WatchEscrows(ctx context.Context) (<-chan *EscrowEvent, pubsub.ClosableSubscription, error)

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]Event, error)

	// Cleanup cleans up the backend.
	Cleanup()
}

// ThresholdQuery is a treshold query.
type ThresholdQuery struct {
	Height int64         `json:"height"`
	Kind   ThresholdKind `json:"kind"`
}

// OwnerQuery is an owner query.
type OwnerQuery struct {
	Height int64   `json:"height"`
	Owner  Address `json:"owner"`
}

// TransferEvent is the event emitted when a balance is transfered, either by
// a call to Transfer or Withdraw.
type TransferEvent struct {
	From   Address           `json:"from"`
	To     Address           `json:"to"`
	Tokens quantity.Quantity `json:"tokens"`
}

// BurnEvent is the event emitted when tokens are destroyed via a call to Burn.
type BurnEvent struct {
	Owner  Address           `json:"owner"`
	Tokens quantity.Quantity `json:"tokens"`
}

// EscrowEvent is an escrow event.
type EscrowEvent struct {
	Add     *AddEscrowEvent     `json:"add,omitempty"`
	Take    *TakeEscrowEvent    `json:"take,omitempty"`
	Reclaim *ReclaimEscrowEvent `json:"reclaim,omitempty"`
}

// Event signifies a staking event, returned via GetEvents.
type Event struct {
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	TransferEvent *TransferEvent `json:"transfer,omitempty"`
	BurnEvent     *BurnEvent     `json:"burn,omitempty"`
	EscrowEvent   *EscrowEvent   `json:"escrow,omitempty"`
}

// AddEscrowEvent is the event emitted when a balance is transfered into
// an escrow balance.
type AddEscrowEvent struct {
	Owner  Address           `json:"owner"`
	Escrow Address           `json:"escrow"`
	Tokens quantity.Quantity `json:"tokens"`
}

// TakeEscrowEvent is the event emitted when balance is deducted from an
// escrow balance (stake is slashed).
type TakeEscrowEvent struct {
	Owner  Address           `json:"owner"`
	Tokens quantity.Quantity `json:"tokens"`
}

// ReclaimEscrowEvent is the event emitted when tokens are reclaimed from an
// escrow balance back into the entity's general balance.
type ReclaimEscrowEvent struct {
	Owner  Address           `json:"owner"`
	Escrow Address           `json:"escrow"`
	Tokens quantity.Quantity `json:"tokens"`
}

// Transfer is a token transfer.
type Transfer struct {
	To     Address           `json:"xfer_to"`
	Tokens quantity.Quantity `json:"xfer_tokens"`
}

// NewTransferTx creates a new transfer transaction.
func NewTransferTx(nonce uint64, fee *transaction.Fee, xfer *Transfer) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodTransfer, xfer)
}

// Burn is a token burn (destruction).
type Burn struct {
	Tokens quantity.Quantity `json:"burn_tokens"`
}

// NewBurnTx creates a new burn transaction.
func NewBurnTx(nonce uint64, fee *transaction.Fee, burn *Burn) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodBurn, burn)
}

// Escrow is a token escrow.
type Escrow struct {
	Account Address           `json:"escrow_account"`
	Tokens  quantity.Quantity `json:"escrow_tokens"`
}

// NewAddEscrowTx creates a new add escrow transaction.
func NewAddEscrowTx(nonce uint64, fee *transaction.Fee, escrow *Escrow) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAddEscrow, escrow)
}

// ReclaimEscrow is a token escrow reclimation.
type ReclaimEscrow struct {
	Account Address           `json:"escrow_account"`
	Shares  quantity.Quantity `json:"reclaim_shares"`
}

// NewReclaimEscrowTx creates a new reclaim escrow transaction.
func NewReclaimEscrowTx(nonce uint64, fee *transaction.Fee, reclaim *ReclaimEscrow) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodReclaimEscrow, reclaim)
}

// AmendCommissionSchedule is an amendment to a commission schedule.
type AmendCommissionSchedule struct {
	Amendment CommissionSchedule `json:"amendment"`
}

// NewAmendCommissionScheduleTx creates a new amend commission schedule transaction.
func NewAmendCommissionScheduleTx(nonce uint64, fee *transaction.Fee, amend *AmendCommissionSchedule) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodAmendCommissionSchedule, amend)
}

// SharePool is a combined balance of several entries, the relative sizes
// of which are tracked through shares.
type SharePool struct {
	Balance     quantity.Quantity `json:"balance,omitempty"`
	TotalShares quantity.Quantity `json:"total_shares,omitempty"`
}

// sharesForTokens computes the amount of shares for the given amount of tokens.
func (p *SharePool) sharesForTokens(amount *quantity.Quantity) (*quantity.Quantity, error) {
	if p.TotalShares.IsZero() {
		// No existing shares, exchange rate is 1:1.
		return amount.Clone(), nil
	}
	if p.Balance.IsZero() {
		// This can happen if the pool has no balance due to
		// losing everything through slashing. In this case there is no
		// way to create more shares.
		return nil, ErrInvalidArgument
	}

	// Exchange rate is based on issued shares and the total balance as:
	//
	//     shares = amount * total_shares / balance
	//
	q := amount.Clone()
	// Multiply first.
	if err := q.Mul(&p.TotalShares); err != nil {
		return nil, err
	}
	if err := q.Quo(&p.Balance); err != nil {
		return nil, err
	}

	return q, nil
}

// Deposit moves tokens into the combined balance, raising the shares.
// If an error occurs, the pool and affected accounts are left in an invalid state.
func (p *SharePool) Deposit(shareDst, tokenSrc, tokenAmount *quantity.Quantity) error {
	shares, err := p.sharesForTokens(tokenAmount)
	if err != nil {
		return err
	}

	if err = quantity.Move(&p.Balance, tokenSrc, tokenAmount); err != nil {
		return err
	}

	if err = p.TotalShares.Add(shares); err != nil {
		return err
	}

	if err = shareDst.Add(shares); err != nil {
		return err
	}

	return nil
}

// tokensForShares computes the amount of tokens for the given amount of shares.
func (p *SharePool) tokensForShares(amount *quantity.Quantity) (*quantity.Quantity, error) {
	if amount.IsZero() || p.Balance.IsZero() || p.TotalShares.IsZero() {
		// No existing shares or no balance means no tokens.
		return quantity.NewQuantity(), nil
	}

	// Exchange rate is based on issued shares and the total balance as:
	//
	//     tokens = shares * balance / total_shares
	//
	q := amount.Clone()
	// Multiply first.
	if err := q.Mul(&p.Balance); err != nil {
		return nil, err
	}
	if err := q.Quo(&p.TotalShares); err != nil {
		return nil, err
	}

	return q, nil
}

// Withdraw moves tokens out of the combined balance, reducing the shares.
// If an error occurs, the pool and affected accounts are left in an invalid state.
func (p *SharePool) Withdraw(tokenDst, shareSrc, shareAmount *quantity.Quantity) error {
	tokens, err := p.tokensForShares(shareAmount)
	if err != nil {
		return err
	}

	if err = shareSrc.Sub(shareAmount); err != nil {
		return err
	}

	if err = p.TotalShares.Sub(shareAmount); err != nil {
		return err
	}

	if err = quantity.Move(tokenDst, &p.Balance, tokens); err != nil {
		return err
	}

	return nil
}

// ThresholdKind is the kind of staking threshold.
type ThresholdKind int

const (
	KindEntity            ThresholdKind = 0
	KindNodeValidator     ThresholdKind = 1
	KindNodeCompute       ThresholdKind = 2
	KindNodeStorage       ThresholdKind = 3
	KindNodeKeyManager    ThresholdKind = 4
	KindRuntimeCompute    ThresholdKind = 5
	KindRuntimeKeyManager ThresholdKind = 6

	KindMax = KindRuntimeKeyManager
)

// String returns the string representation of a ThresholdKind.
func (k ThresholdKind) String() string {
	switch k {
	case KindEntity:
		return "entity"
	case KindNodeValidator:
		return "validator node"
	case KindNodeCompute:
		return "compute node"
	case KindNodeStorage:
		return "storage node"
	case KindNodeKeyManager:
		return "key manager node"
	case KindRuntimeCompute:
		return "compute runtime"
	case KindRuntimeKeyManager:
		return "key manager runtime"
	default:
		return "[unknown threshold kind]"
	}
}

// StakeClaim is a unique stake claim identifier.
type StakeClaim string

// StakeAccumulator is a per-escrow-account stake accumulator.
type StakeAccumulator struct {
	// Claims are the stake claims that must be satisfied at any given point. Adding a new claim is
	// only possible if all of the existing claims plus the new claim is satisfied.
	Claims map[StakeClaim][]ThresholdKind `json:"claims,omitempty"`
}

// AddClaimUnchecked adds a new claim without checking its validity.
func (sa *StakeAccumulator) AddClaimUnchecked(claim StakeClaim, thresholds []ThresholdKind) {
	if sa.Claims == nil {
		sa.Claims = make(map[StakeClaim][]ThresholdKind)
	}

	sa.Claims[claim] = thresholds
}

// RemoveClaim removes a given stake claim.
//
// It is an error if the stake claim does not exist.
func (sa *StakeAccumulator) RemoveClaim(claim StakeClaim) error {
	if sa.Claims == nil || sa.Claims[claim] == nil {
		return fmt.Errorf("staking: claim does not exist: %s", claim)
	}

	delete(sa.Claims, claim)
	return nil
}

// TotalClaims computes the total amount of stake claims in the accumulator.
func (sa *StakeAccumulator) TotalClaims(thresholds map[ThresholdKind]quantity.Quantity, exclude *StakeClaim) (*quantity.Quantity, error) {
	if sa == nil || sa.Claims == nil {
		return quantity.NewQuantity(), nil
	}

	var total quantity.Quantity
	for id, claim := range sa.Claims {
		if exclude != nil && id == *exclude {
			continue
		}

		for _, kind := range claim {
			q := thresholds[kind]
			if err := total.Add(&q); err != nil {
				return nil, fmt.Errorf("staking: failed to accumulate threshold: %w", err)
			}
		}
	}
	return &total, nil
}

// GeneralAccount is a general-purpose account.
type GeneralAccount struct {
	Balance quantity.Quantity `json:"balance,omitempty"`
	Nonce   uint64            `json:"nonce,omitempty"`
}

// EscrowAccount is an escrow account the balance of which is subject to
// special delegation provisions and a debonding period.
type EscrowAccount struct {
	Active             SharePool          `json:"active,omitempty"`
	Debonding          SharePool          `json:"debonding,omitempty"`
	CommissionSchedule CommissionSchedule `json:"commission_schedule,omitempty"`
	StakeAccumulator   StakeAccumulator   `json:"stake_accumulator,omitempty"`
}

// CheckStakeClaims checks whether the escrow account balance satisfies all the stake claims.
func (e *EscrowAccount) CheckStakeClaims(tm map[ThresholdKind]quantity.Quantity) error {
	totalClaims, err := e.StakeAccumulator.TotalClaims(tm, nil)
	if err != nil {
		return err
	}
	if e.Active.Balance.Cmp(totalClaims) < 0 {
		return ErrInsufficientStake
	}
	return nil
}

// AddStakeClaim attempts to add a stake claim to the given escrow account.
//
// In case there is insufficient stake to cover the claim or an error occurrs, no modifications are
// made to the stake accumulator.
func (e *EscrowAccount) AddStakeClaim(tm map[ThresholdKind]quantity.Quantity, claim StakeClaim, thresholds []ThresholdKind) error {
	// Compute total amount of claims excluding the claim that we are just adding. This is needed
	// in case the claim is being updated to avoid counting it twice.
	totalClaims, err := e.StakeAccumulator.TotalClaims(tm, &claim)
	if err != nil {
		return err
	}

	for _, kind := range thresholds {
		q := tm[kind]
		if err := totalClaims.Add(&q); err != nil {
			return fmt.Errorf("staking: failed to accumulate threshold: %w", err)
		}
	}

	// Make sure there is sufficient stake to satisfy the claim.
	if e.Active.Balance.Cmp(totalClaims) < 0 {
		return ErrInsufficientStake
	}

	e.StakeAccumulator.AddClaimUnchecked(claim, thresholds)
	return nil
}

// RemoveStakeClaim removes a given stake claim.
//
// It is an error if the stake claim does not exist.
func (e *EscrowAccount) RemoveStakeClaim(claim StakeClaim) error {
	return e.StakeAccumulator.RemoveClaim(claim)
}

// Account is an entry in the staking ledger.
//
// The same ledger entry can hold both general and escrow accounts. Escrow
// acounts are used to hold funds delegated for staking.
type Account struct {
	General GeneralAccount `json:"general,omitempty"`
	Escrow  EscrowAccount  `json:"escrow,omitempty"`
}

// Delegation is a delegation descriptor.
type Delegation struct {
	Shares quantity.Quantity `json:"shares"`
}

// DebondingDelegation is a debonding delegation descriptor.
type DebondingDelegation struct {
	Shares        quantity.Quantity   `json:"shares"`
	DebondEndTime epochtime.EpochTime `json:"debond_end"`
}

// Genesis is the initial ledger balances at genesis for use in the genesis
// block and test cases.
type Genesis struct {
	Parameters ConsensusParameters `json:"params"`

	TotalSupply   quantity.Quantity `json:"total_supply"`
	CommonPool    quantity.Quantity `json:"common_pool"`
	LastBlockFees quantity.Quantity `json:"last_block_fees"`

	Ledger map[Address]*Account `json:"ledger,omitempty"`

	Delegations          map[Address]map[Address]*Delegation            `json:"delegations,omitempty"`
	DebondingDelegations map[Address]map[Address][]*DebondingDelegation `json:"debonding_delegations,omitempty"`
}

// ConsensusParameters are the staking consensus parameters.
type ConsensusParameters struct {
	Thresholds                        map[ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
	DebondingInterval                 epochtime.EpochTime                 `json:"debonding_interval,omitempty"`
	RewardSchedule                    []RewardStep                        `json:"reward_schedule,omitempty"`
	SigningRewardThresholdNumerator   uint64                              `json:"signing_reward_threshold_numerator,omitempty"`
	SigningRewardThresholdDenominator uint64                              `json:"signing_reward_threshold_denominator,omitempty"`
	CommissionScheduleRules           CommissionScheduleRules             `json:"commission_schedule_rules,omitempty"`
	Slashing                          map[SlashReason]Slash               `json:"slashing,omitempty"`
	GasCosts                          transaction.Costs                   `json:"gas_costs,omitempty"`
	MinDelegationAmount               quantity.Quantity                   `json:"min_delegation"`

	DisableTransfers       bool             `json:"disable_transfers,omitempty"`
	DisableDelegation      bool             `json:"disable_delegation,omitempty"`
	UndisableTransfersFrom map[Address]bool `json:"undisable_transfers_from,omitempty"`

	// FeeSplitWeightPropose is the proportion of block fee portions that go to the proposer.
	FeeSplitWeightPropose quantity.Quantity `json:"fee_split_weight_propose"`
	// FeeSplitWeightVote is the proportion of block fee portions that go to the validator that votes.
	FeeSplitWeightVote quantity.Quantity `json:"fee_split_weight_vote"`
	// FeeSplitWeightNextPropose is the proportion of block fee portions that go to the next block's proposer.
	FeeSplitWeightNextPropose quantity.Quantity `json:"fee_split_weight_next_propose"`

	// RewardFactorEpochSigned is the factor for a reward distributed per epoch to
	// entities that have signed at least a threshold fraction of the blocks.
	RewardFactorEpochSigned quantity.Quantity `json:"reward_factor_epoch_signed"`
	// RewardFactorBlockProposed is the factor for a reward distributed per block
	// to the entity that proposed the block.
	RewardFactorBlockProposed quantity.Quantity `json:"reward_factor_block_proposed"`
}

const (
	// GasOpTransfer is the gas operation identifier for transfer.
	GasOpTransfer transaction.Op = "transfer"
	// GasOpBurn is the gas operation identifier for burn.
	GasOpBurn transaction.Op = "burn"
	// GasOpAddEscrow is the gas operation identifier for add escrow.
	GasOpAddEscrow transaction.Op = "add_escrow"
	// GasOpReclaimEscrow is the gas operation identifier for reclaim escrow.
	GasOpReclaimEscrow transaction.Op = "reclaim_escrow"
	// GasOpAmendCommissionSchedule is the gas operation identifier for amend commission schedule.
	GasOpAmendCommissionSchedule transaction.Op = "amend_commission_schedule"
)
