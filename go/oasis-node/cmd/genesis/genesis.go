// Package genesis implements the genesis sub-commands.
package genesis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasislabs/oasis-core/go/consensus/genesis"
	tendermint "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	stakingTests "github.com/oasislabs/oasis-core/go/staking/tests/debug"
)

const (
	cfgEntity      = "entity"
	cfgRuntime     = "runtime"
	cfgNode        = "node"
	cfgRootHash    = "roothash"
	cfgKeyManager  = "keymanager"
	cfgStaking     = "staking"
	cfgBlockHeight = "height"
	cfgChainID     = "chain.id"
	cfgHaltEpoch   = "halt.epoch"

	// Registry config flags.
	CfgRegistryMaxNodeExpiration                      = "registry.max_node_expiration"
	CfgRegistryDisableRuntimeRegistration             = "registry.disable_runtime_registration"
	cfgRegistryDebugAllowUnroutableAddresses          = "registry.debug.allow_unroutable_addresses"
	CfgRegistryDebugAllowTestRuntimes                 = "registry.debug.allow_test_runtimes"
	cfgRegistryDebugAllowEntitySignedNodeRegistration = "registry.debug.allow_entity_signed_registration"
	cfgRegistryDebugBypassStake                       = "registry.debug.bypass_stake" // nolint: gosec

	// Scheduler config flags.
	cfgSchedulerMinValidators          = "scheduler.min_validators"
	cfgSchedulerMaxValidators          = "scheduler.max_validators"
	cfgSchedulerMaxValidatorsPerEntity = "scheduler.max_validators_per_entity"
	cfgSchedulerDebugBypassStake       = "scheduler.debug.bypass_stake" // nolint: gosec
	cfgSchedulerDebugStaticValidators  = "scheduler.debug.static_validators"

	// Beacon config flags.
	cfgBeaconDebugDeterministic = "beacon.debug.deterministic"

	// EpochTime config flags.
	cfgEpochTimeDebugMockBackend   = "epochtime.debug.mock_backend"
	cfgEpochTimeTendermintInterval = "epochtime.tendermint.interval"

	// Roothash config flags.
	cfgRoothashDebugDoNotSuspendRuntimes = "roothash.debug.do_not_suspend_runtimes"
	cfgRoothashDebugBypassStake          = "roothash.debug.bypass_stake" // nolint: gosec

	// Tendermint config flags.
	cfgConsensusTimeoutCommit        = "consensus.tendermint.timeout_commit"
	cfgConsensusSkipTimeoutCommit    = "consensus.tendermint.skip_timeout_commit"
	cfgConsensusEmptyBlockInterval   = "consensus.tendermint.empty_block_interval"
	cfgConsensusMaxTxSizeBytes       = "consensus.tendermint.max_tx_size"
	cfgConsensusMaxBlockSizeBytes    = "consensus.tendermint.max_block_size"
	cfgConsensusMaxBlockGas          = "consensus.tendermint.max_block_gas"
	cfgConsensusMaxEvidenceAgeBlocks = "consensus.tendermint.max_evidence_age_blocks"
	cfgConsensusMaxEvidenceAgeTime   = "consensus.tendermint.max_evidence_age_time"
	CfgConsensusGasCostsTxByte       = "consensus.gas_costs.tx_byte"

	// Consensus backend config flag.
	cfgConsensusBackend = "consensus.backend"

	// Our 'entity' flag overlaps with the common flag 'entity'.
	// We bind it to a separate Viper key to disambiguate at runtime.
	viperEntity = "provision_entity"
)

var (
	checkGenesisFlags = flag.NewFlagSet("", flag.ContinueOnError)
	dumpGenesisFlags  = flag.NewFlagSet("", flag.ContinueOnError)
	initGenesisFlags  = flag.NewFlagSet("", flag.ContinueOnError)

	genesisCmd = &cobra.Command{
		Use:   "genesis",
		Short: "genesis block utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize the genesis file",
		Run:   doInitGenesis,
	}

	dumpGenesisCmd = &cobra.Command{
		Use:   "dump",
		Short: "dump state into genesis file",
		Run:   doDumpGenesis,
	}

	checkGenesisCmd = &cobra.Command{
		Use:   "check",
		Short: "sanity check the genesis file",
		Run:   doCheckGenesis,
	}

	logger = logging.GetLogger("cmd/genesis")
)

func doInitGenesis(cmd *cobra.Command, args []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	f := flags.GenesisFile()
	if len(f) == 0 {
		logger.Error("failed to determine output location")
		return
	}

	chainID := viper.GetString(cfgChainID)
	if chainID == "" {
		logger.Error("genesis chain id missing")
		return
	}

	// Build the genesis state, if any.
	doc := &genesis.Document{
		ChainID:   chainID,
		Time:      time.Now(),
		HaltEpoch: epochtime.EpochTime(viper.GetUint64(cfgHaltEpoch)),
	}
	entities := viper.GetStringSlice(viperEntity)
	runtimes := viper.GetStringSlice(cfgRuntime)
	nodes := viper.GetStringSlice(cfgNode)
	if err := AppendRegistryState(doc, entities, runtimes, nodes, logger); err != nil {
		logger.Error("failed to parse registry genesis state",
			"err", err,
		)
		return
	}

	rh := viper.GetStringSlice(cfgRootHash)
	if err := AppendRootHashState(doc, rh, logger); err != nil {
		logger.Error("failed to parse roothash genesis state",
			"err", err,
		)
		return
	}

	keymanager := viper.GetStringSlice(cfgKeyManager)
	if err := AppendKeyManagerState(doc, keymanager, logger); err != nil {
		logger.Error("failed to parse key manager genesis state",
			"err", err,
		)
		return
	}

	staking := viper.GetString(cfgStaking)
	if err := AppendStakingState(doc, staking, logger); err != nil {
		logger.Error("failed to parse staking genesis state",
			"err", err,
		)
		return
	}

	doc.Scheduler = scheduler.Genesis{
		Parameters: scheduler.ConsensusParameters{
			MinValidators:          viper.GetInt(cfgSchedulerMinValidators),
			MaxValidators:          viper.GetInt(cfgSchedulerMaxValidators),
			MaxValidatorsPerEntity: viper.GetInt(cfgSchedulerMaxValidatorsPerEntity),
			DebugBypassStake:       viper.GetBool(cfgSchedulerDebugBypassStake),
			DebugStaticValidators:  viper.GetBool(cfgSchedulerDebugStaticValidators),
		},
	}

	doc.Beacon = beacon.Genesis{
		Parameters: beacon.ConsensusParameters{
			DebugDeterministic: viper.GetBool(cfgBeaconDebugDeterministic),
		},
	}

	doc.EpochTime = epochtime.Genesis{
		Parameters: epochtime.ConsensusParameters{
			DebugMockBackend: viper.GetBool(cfgEpochTimeDebugMockBackend),
			Interval:         viper.GetInt64(cfgEpochTimeTendermintInterval),
		},
	}

	doc.Consensus = consensusGenesis.Genesis{
		Backend: viper.GetString(cfgConsensusBackend),
		Parameters: consensusGenesis.Parameters{
			TimeoutCommit:        viper.GetDuration(cfgConsensusTimeoutCommit),
			SkipTimeoutCommit:    viper.GetBool(cfgConsensusSkipTimeoutCommit),
			EmptyBlockInterval:   viper.GetDuration(cfgConsensusEmptyBlockInterval),
			MaxTxSize:            uint64(viper.GetSizeInBytes(cfgConsensusMaxTxSizeBytes)),
			MaxBlockSize:         uint64(viper.GetSizeInBytes(cfgConsensusMaxBlockSizeBytes)),
			MaxBlockGas:          transaction.Gas(viper.GetUint64(cfgConsensusMaxBlockGas)),
			MaxEvidenceAgeBlocks: viper.GetUint64(cfgConsensusMaxEvidenceAgeBlocks),
			MaxEvidenceAgeTime:   viper.GetDuration(cfgConsensusMaxEvidenceAgeTime),
			GasCosts: transaction.Costs{
				consensusGenesis.GasOpTxByte: transaction.Gas(viper.GetUint64(CfgConsensusGasCostsTxByte)),
			},
		},
	}

	// Ensure consistency/sanity.
	if err := doc.SanityCheck(); err != nil {
		logger.Error("genesis document failed sanity check",
			"err", err,
		)
		return
	}

	b, _ := json.Marshal(doc)
	if err := ioutil.WriteFile(f, b, 0600); err != nil {
		logger.Error("failed to save generated genesis document",
			"err", err,
		)
		return
	}

	ok = true
}

// AppendRegistryState appends the registry genesis state given a vector
// of entity registrations and runtime registrations.
func AppendRegistryState(doc *genesis.Document, entities, runtimes, nodes []string, l *logging.Logger) error {
	regSt := registry.Genesis{
		Parameters: registry.ConsensusParameters{
			DebugAllowUnroutableAddresses:          viper.GetBool(cfgRegistryDebugAllowUnroutableAddresses),
			DebugAllowTestRuntimes:                 viper.GetBool(CfgRegistryDebugAllowTestRuntimes),
			DebugAllowEntitySignedNodeRegistration: viper.GetBool(cfgRegistryDebugAllowEntitySignedNodeRegistration),
			DebugBypassStake:                       viper.GetBool(cfgRegistryDebugBypassStake),
			GasCosts:                               registry.DefaultGasCosts, // TODO: Make these configurable.
			MaxNodeExpiration:                      viper.GetUint64(CfgRegistryMaxNodeExpiration),
			DisableRuntimeRegistration:             viper.GetBool(CfgRegistryDisableRuntimeRegistration),
		},
		Entities: make([]*entity.SignedEntity, 0, len(entities)),
		Runtimes: make([]*registry.SignedRuntime, 0, len(runtimes)),
		Nodes:    make([]*node.MultiSignedNode, 0, len(nodes)),
	}

	entMap := make(map[signature.PublicKey]bool)
	appendToEntities := func(signedEntity *entity.SignedEntity, ent *entity.Entity) error {
		if entMap[ent.ID] {
			return errors.New("genesis: duplicate entity registration")
		}
		entMap[ent.ID] = true

		regSt.Entities = append(regSt.Entities, signedEntity)

		return nil
	}

	loadSignedEntity := func(fn string) (*entity.SignedEntity, *entity.Entity, error) {
		b, err := ioutil.ReadFile(fn)
		if err != nil {
			return nil, nil, err
		}

		var signedEntity entity.SignedEntity
		if err = json.Unmarshal(b, &signedEntity); err != nil {
			return nil, nil, err
		}

		var ent entity.Entity
		if err := signedEntity.Open(registry.RegisterGenesisEntitySignatureContext, &ent); err != nil {
			return nil, nil, err
		}

		return &signedEntity, &ent, nil
	}

	for _, v := range entities {
		signedEntity, ent, err := loadSignedEntity(v)
		if err != nil {
			l.Error("failed to load genesis entity",
				"err", err,
				"filename", v,
			)
			return err
		}

		if err = appendToEntities(signedEntity, ent); err != nil {
			l.Error("failed to process genesis entity",
				"err", err,
				"filename", v,
			)
		}
	}
	if flags.DebugTestEntity() {
		l.Warn("registering debug test entity")

		ent, signer, err := entity.TestEntity()
		if err != nil {
			l.Error("failed to retrive test entity",
				"err", err,
			)
			return err
		}

		signedEntity, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, ent)
		if err != nil {
			l.Error("failed to sign test entity",
				"err", err,
			)
			return err
		}

		if err = appendToEntities(signedEntity, ent); err != nil {
			l.Error("failed to process test entity",
				"err", err,
			)
			return err
		}
	}

	for _, v := range runtimes {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis runtime registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var rt registry.SignedRuntime
		if err = json.Unmarshal(b, &rt); err != nil {
			l.Error("failed to parse genesis runtime registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Runtimes = append(regSt.Runtimes, &rt)
	}

	for _, v := range nodes {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis node registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var n node.MultiSignedNode
		if err = json.Unmarshal(b, &n); err != nil {
			l.Error("failed to parse genesis node registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Nodes = append(regSt.Nodes, &n)
	}

	doc.Registry = regSt

	return nil
}

// AppendRootHashState appends the roothash genesis state given files with
// exported runtime states.
func AppendRootHashState(doc *genesis.Document, exports []string, l *logging.Logger) error {
	rootSt := roothash.Genesis{
		RuntimeStates: make(map[common.Namespace]*registry.RuntimeGenesis),

		Parameters: roothash.ConsensusParameters{
			DebugDoNotSuspendRuntimes: viper.GetBool(cfgRoothashDebugDoNotSuspendRuntimes),
			DebugBypassStake:          viper.GetBool(cfgRoothashDebugBypassStake),
			// TODO: Make these configurable.
			GasCosts: roothash.DefaultGasCosts,
		},
	}

	for _, v := range exports {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis roothash runtime states",
				"err", err,
				"filename", v,
			)
			return err
		}

		var rtStates map[common.Namespace]*registry.RuntimeGenesis
		if err = json.Unmarshal(b, &rtStates); err != nil {
			l.Error("failed to parse genesis roothash runtime states",
				"err", err,
				"filename", v,
			)
			return err
		}

		for id, rtg := range rtStates {
			// Each runtime state must be described exactly once!
			if _, ok := rootSt.RuntimeStates[id]; ok {
				l.Error("duplicate genesis roothash runtime state",
					"runtime_id", id,
					"block", rtg,
				)
				return errors.New("duplicate genesis roothash runtime states")
			}
			rootSt.RuntimeStates[id] = rtg
		}
	}

	doc.RootHash = rootSt

	return nil
}

// AppendKeyManagerState appends the key manager genesis state given a vector of
// key manager statuses.
func AppendKeyManagerState(doc *genesis.Document, statuses []string, l *logging.Logger) error {
	var kmSt keymanager.Genesis

	for _, v := range statuses {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis key manager status",
				"err", err,
				"filename", v,
			)
			return err
		}

		var status keymanager.Status
		if err = json.Unmarshal(b, &status); err != nil {
			l.Error("failed to parse genesis key manager status",
				"err", err,
				"filename", v,
			)
			return err
		}

		kmSt.Statuses = append(kmSt.Statuses, &status)
	}

	doc.KeyManager = kmSt

	return nil
}

// AppendStakingState appends the staking genesis state given a state file name.
func AppendStakingState(doc *genesis.Document, state string, l *logging.Logger) error {
	stakingSt := staking.Genesis{
		Ledger: make(map[staking.Address]*staking.Account),
	}
	if err := stakingSt.Parameters.FeeSplitWeightVote.FromInt64(1); err != nil {
		return fmt.Errorf("couldn't set default fee split: %w", err)
	}

	if state != "" {
		b, err := ioutil.ReadFile(state)
		if err != nil {
			l.Error("failed to load genesis staking status",
				"err", err,
				"filename", state,
			)
			return err
		}

		if err = json.Unmarshal(b, &stakingSt); err != nil {
			l.Error("failed to parse genesis staking status",
				"err", err,
				"filename", state,
			)
			return err
		}
	}
	if flags.DebugTestEntity() {
		l.Warn("granting stake to the debug test entity")

		ent, _, err := entity.TestEntity()
		if err != nil {
			l.Error("failed to retrieve test entity",
				"err", err,
			)
			return err
		}
		entAddr := staking.NewFromPublicKey(ent.ID)

		// Ok then, we hold the world ransom for One Hundred Billion Dollars.
		var q quantity.Quantity
		if err = q.FromBigInt(big.NewInt(100000000000)); err != nil {
			l.Error("failed to allocate test stake",
				"err", err,
			)
			return err
		}

		stakingSt.Ledger[entAddr] = &staking.Account{
			General: staking.GeneralAccount{
				Balance: q,
				Nonce:   0,
			},
			Escrow: staking.EscrowAccount{
				Active: staking.SharePool{
					Balance:     q,
					TotalShares: stakingTests.QtyFromInt(1),
				},
			},
		}
		stakingSt.Delegations = map[staking.Address]map[staking.Address]*staking.Delegation{
			entAddr: map[staking.Address]*staking.Delegation{
				entAddr: &staking.Delegation{
					Shares: stakingTests.QtyFromInt(1),
				},
			},
		}

		// Inflate the TotalSupply to account for the account's general and
		// escrow balances.
		_ = stakingSt.TotalSupply.Add(&q)
		_ = stakingSt.TotalSupply.Add(&q)

		// Set zero thresholds for all staking kinds, if none set.
		if len(stakingSt.Parameters.Thresholds) == 0 {
			var sq quantity.Quantity
			_ = sq.FromBigInt(big.NewInt(0))
			stakingSt.Parameters.Thresholds =
				map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            sq,
					staking.KindNodeValidator:     sq,
					staking.KindNodeCompute:       sq,
					staking.KindNodeStorage:       sq,
					staking.KindNodeKeyManager:    sq,
					staking.KindRuntimeCompute:    sq,
					staking.KindRuntimeKeyManager: sq,
				}
		}
	}

	doc.Staking = stakingSt

	return nil
}

func doDumpGenesis(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}
	defer conn.Close()

	client := consensus.NewConsensusClient(conn)

	doc, err := client.StateToGenesis(ctx, viper.GetInt64(cfgBlockHeight))
	if err != nil {
		logger.Error("failed to generate genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, flags.CfgGenesisFile)
	if err != nil {
		logger.Error("failed to get writer for genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}

	data, err := json.Marshal(doc)
	if err != nil {
		logger.Error("failed to marshal genesis document into JSON",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = w.Write(data); err != nil {
		logger.Error("failed to write genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

func doCheckGenesis(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	filename := flags.GenesisFile()
	provider, err := genesisFile.NewFileProvider(filename)
	if err != nil {
		logger.Error("failed to open genesis file", "err", err)
		os.Exit(1)
	}
	doc, err := provider.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to get genesis document", "err", err)
		os.Exit(1)
	}

	err = doc.SanityCheck()
	if err != nil {
		logger.Error("genesis document sanity check failed", "err", err)
		os.Exit(1)
	}

	// TODO: Pretty-print contents of genesis document.
}

// Register registers the genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	initGenesisCmd.Flags().AddFlagSet(initGenesisFlags)
	dumpGenesisCmd.Flags().AddFlagSet(dumpGenesisFlags)
	dumpGenesisCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	checkGenesisCmd.Flags().AddFlagSet(checkGenesisFlags)

	for _, v := range []*cobra.Command{
		initGenesisCmd,
		dumpGenesisCmd,
		checkGenesisCmd,
	} {
		genesisCmd.AddCommand(v)
	}

	parentCmd.AddCommand(genesisCmd)
}

func init() {
	_ = viper.BindPFlags(checkGenesisFlags)
	checkGenesisFlags.AddFlagSet(flags.GenesisFileFlags)

	dumpGenesisFlags.Int64(cfgBlockHeight, consensus.HeightLatest, "block height at which to dump state")
	_ = viper.BindPFlags(dumpGenesisFlags)
	dumpGenesisFlags.AddFlagSet(flags.GenesisFileFlags)

	initGenesisFlags.StringSlice(cfgRuntime, nil, "path to runtime registration file")
	initGenesisFlags.StringSlice(cfgNode, nil, "path to node registration file")
	initGenesisFlags.StringSlice(cfgRootHash, nil, "path to roothash genesis runtime states file")
	initGenesisFlags.String(cfgStaking, "", "path to staking genesis file")
	initGenesisFlags.StringSlice(cfgKeyManager, nil, "path to key manager genesis status file")
	initGenesisFlags.String(cfgChainID, "", "genesis chain id")
	initGenesisFlags.Uint64(cfgHaltEpoch, math.MaxUint64, "genesis halt epoch height")

	// Registry config flags.
	initGenesisFlags.Uint64(CfgRegistryMaxNodeExpiration, 5, "maximum node registration lifespan in epochs")
	initGenesisFlags.Bool(CfgRegistryDisableRuntimeRegistration, false, "disable non-genesis runtime registration")
	initGenesisFlags.Bool(cfgRegistryDebugAllowUnroutableAddresses, false, "allow unroutable addreses (UNSAFE)")
	initGenesisFlags.Bool(CfgRegistryDebugAllowTestRuntimes, false, "enable test runtime registration")
	initGenesisFlags.Bool(cfgRegistryDebugAllowEntitySignedNodeRegistration, false, "allow entity signed node registration (UNSAFE)")
	initGenesisFlags.Bool(cfgRegistryDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")
	_ = initGenesisFlags.MarkHidden(cfgRegistryDebugAllowUnroutableAddresses)
	_ = initGenesisFlags.MarkHidden(CfgRegistryDebugAllowTestRuntimes)
	_ = initGenesisFlags.MarkHidden(cfgRegistryDebugAllowEntitySignedNodeRegistration)
	_ = initGenesisFlags.MarkHidden(cfgRegistryDebugBypassStake)

	// Scheduler config flags.
	initGenesisFlags.Int(cfgSchedulerMinValidators, 1, "minumum number of validators")
	initGenesisFlags.Int(cfgSchedulerMaxValidators, 100, "maximum number of validators")
	initGenesisFlags.Int(cfgSchedulerMaxValidatorsPerEntity, 1, "maximum number of validators per entity")
	initGenesisFlags.Bool(cfgSchedulerDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")
	initGenesisFlags.Bool(cfgSchedulerDebugStaticValidators, false, "bypass all validator elections (UNSAFE)")
	_ = initGenesisFlags.MarkHidden(cfgSchedulerDebugBypassStake)
	_ = initGenesisFlags.MarkHidden(cfgSchedulerDebugStaticValidators)

	// Beacon config flags.
	initGenesisFlags.Bool(cfgBeaconDebugDeterministic, false, "enable deterministic beacon output (UNSAFE)")
	_ = initGenesisFlags.MarkHidden(cfgBeaconDebugDeterministic)

	// EpochTime config flags.
	initGenesisFlags.Bool(cfgEpochTimeDebugMockBackend, false, "use debug mock Epoch time backend")
	initGenesisFlags.Int64(cfgEpochTimeTendermintInterval, 86400, "Epoch interval (in blocks)")
	_ = initGenesisFlags.MarkHidden(cfgEpochTimeDebugMockBackend)

	// Roothash config flags.
	initGenesisFlags.Bool(cfgRoothashDebugDoNotSuspendRuntimes, false, "do not suspend runtimes (UNSAFE)")
	initGenesisFlags.Bool(cfgRoothashDebugBypassStake, false, "bypass all roothash stake checks and operations (UNSAFE)")
	_ = initGenesisFlags.MarkHidden(cfgRoothashDebugDoNotSuspendRuntimes)
	_ = initGenesisFlags.MarkHidden(cfgRoothashDebugBypassStake)

	// Tendermint config flags.
	initGenesisFlags.Duration(cfgConsensusTimeoutCommit, 1*time.Second, "tendermint commit timeout")
	initGenesisFlags.Bool(cfgConsensusSkipTimeoutCommit, false, "skip tendermint commit timeout")
	initGenesisFlags.Duration(cfgConsensusEmptyBlockInterval, 0*time.Second, "tendermint empty block interval")
	initGenesisFlags.String(cfgConsensusMaxTxSizeBytes, "32kb", "tendermint maximum transaction size (in bytes)")
	initGenesisFlags.String(cfgConsensusMaxBlockSizeBytes, "21mb", "tendermint maximum block size (in bytes)")
	initGenesisFlags.Uint64(cfgConsensusMaxBlockGas, 0, "tendermint max gas used per block")
	initGenesisFlags.Uint64(cfgConsensusMaxEvidenceAgeBlocks, 100000, "tendermint max evidence age (in blocks)")
	initGenesisFlags.Duration(cfgConsensusMaxEvidenceAgeTime, 48*time.Hour, "tendermint max evidence age (in time)")
	initGenesisFlags.Uint64(CfgConsensusGasCostsTxByte, 1, "consensus gas costs: each transaction byte")

	// Consensus backend flag.
	initGenesisFlags.String(cfgConsensusBackend, tendermint.BackendName, "consensus backend")

	_ = viper.BindPFlags(initGenesisFlags)
	initGenesisFlags.StringSlice(cfgEntity, nil, "path to entity registration file")
	_ = viper.BindPFlag(viperEntity, initGenesisFlags.Lookup(cfgEntity))
	initGenesisFlags.AddFlagSet(flags.DebugTestEntityFlags)
	initGenesisFlags.AddFlagSet(flags.GenesisFileFlags)
	initGenesisFlags.AddFlagSet(flags.DebugDontBlameOasisFlag)
}
