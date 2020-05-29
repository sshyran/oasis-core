package txsource

import (
	"context"
	"crypto"
	"fmt"
	"math/rand"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/control/api"
	genesisFile "github.com/oasislabs/oasis-core/go/genesis/file"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/debug/txsource/workload"
)

const (
	CfgWorkload  = "workload"
	CfgSeed      = "seed"
	CfgTimeLimit = "time_limit"
)

var (
	logger      = logging.GetLogger("cmd/txsource")
	txsourceCmd = &cobra.Command{
		Use:   "txsource",
		Short: "send random transactions",
		RunE:  doRun,
	}
)

func doRun(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	// Set up the time limit.
	ctx := context.Background()
	timeLimit := viper.GetDuration(CfgTimeLimit)
	if timeLimit != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeLimit)
		defer cancel()
	}

	// Set up the genesis system for the signature system's chain context.
	genesis, err := genesisFile.DefaultFileProvider()
	if err != nil {
		return fmt.Errorf("genesisFile.DefaultFileProvider: %w", err)
	}
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("genesis.GetGenesisDocument: %w", err)
	}
	logger.Debug("setting chain context", "chain_context", genesisDoc.ChainContext())
	genesisDoc.SetChainContext()

	// Resolve the workload.
	name := viper.GetString(CfgWorkload)
	w, ok := workload.ByName[name]
	if !ok {
		return fmt.Errorf("workload %s not found", name)
	}

	// Set up the deterministic random source.
	hash := crypto.SHA512
	seed := []byte(viper.GetString(CfgSeed))
	src, err := drbg.New(hash, seed, nil, []byte(fmt.Sprintf("txsource workload generator v1, workload %s", name)))
	if err != nil {
		return fmt.Errorf("drbg.New: %w", err)
	}
	rng := rand.New(mathrand.New(src))

	// Set up the gRPC client.
	logger.Debug("dialing node", "addr", viper.GetString(cmdGrpc.CfgAddress))
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		return fmt.Errorf("cmdGrpc.NewClient: %w", err)
	}
	defer conn.Close()

	// Set up the consensus client.
	cnsc := consensus.NewConsensusClient(conn)

	// Wait for sync before transferring control to the workload.
	ncc := api.NewNodeControllerClient(conn)
	logger.Debug("waiting for node sync")
	if err = ncc.WaitSync(context.Background()); err != nil {
		return fmt.Errorf("node controller client WaitSync: %w", err)
	}
	logger.Debug("node synced")

	// Generate and fund the account that will be used for funding accounts
	// during the workload.
	// NOTE: we don't use Test Entity account directly in the workloads
	// as using the same account in all runs would lead to a lot of
	// contention and nonce mismatches.
	fundingAccount, err := memorySigner.NewFactory().Generate(signature.SignerEntity, rng)
	if err != nil {
		return fmt.Errorf("memory signer factory generate funding account %w", err)
	}
	if err = workload.FundAccountFromTestEntity(ctx, logger, cnsc, fundingAccount); err != nil {
		return fmt.Errorf("test entity account funding failure: %w", err)
	}

	logger.Debug("entering workload", "name", name)
	if err = w.Run(ctx, rng, conn, cnsc, fundingAccount); err != nil {
		logger.Error("workload error", "err", err)
		return fmt.Errorf("workload %s: %w", name, err)
	}
	logger.Debug("workload returned", "name", name)

	return nil
}

// Register registers the txsource sub-command.
func Register(parentCmd *cobra.Command) {
	parentCmd.AddCommand(txsourceCmd)
}

func init() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.String(CfgWorkload, workload.NameTransfer, "Name of the workload to run (see source for listing)")
	fs.String(CfgSeed, "seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed", "Seed to use for randomized workloads")
	fs.Duration(CfgTimeLimit, 0, "Exit successfully after this long, or 0 to run forever")
	_ = viper.BindPFlags(fs)
	txsourceCmd.Flags().AddFlagSet(fs)

	txsourceCmd.Flags().AddFlagSet(workload.Flags)
	txsourceCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	txsourceCmd.Flags().AddFlagSet(cmdFlags.DebugTestEntityFlags)
	txsourceCmd.Flags().AddFlagSet(cmdFlags.GenesisFileFlags)
	txsourceCmd.Flags().AddFlagSet(cmdFlags.DebugDontBlameOasisFlag)
}
