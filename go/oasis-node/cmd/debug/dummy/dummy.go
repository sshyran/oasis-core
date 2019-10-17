// Package dummy implements the dummy debug sub-commands.
package dummy

import (
	"context"
	"os"

	"github.com/cenkalti/backoff"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/grpc/dummydebug"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
)

var (
	epoch uint64
	nodes uint64

	dummyCmd = &cobra.Command{
		Use:   "dummy",
		Short: "control dummy node during tests",
	}

	dummySetEpochCmd = &cobra.Command{
		Use:   "set-epoch",
		Short: "set mock epochtime",
		Run:   doSetEpoch,
	}

	dummyWaitNodesCmd = &cobra.Command{
		Use:   "wait-nodes",
		Short: "wait for specific number of nodes to register",
		Run:   doWaitNodes,
	}

	logger = logging.GetLogger("cmd/dummy")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, dummydebug.DummyDebugClient) {
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

	client := dummydebug.NewDummyDebugClient(conn)

	return conn, client
}

func doSetEpoch(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Info("setting epoch",
		"epoch", epoch,
	)

	// Use background context to block until mock epoch transition is done.
	_, err := client.SetEpoch(context.Background(), &dummydebug.SetEpochRequest{Epoch: epoch})
	if err != nil {
		logger.Error("failed to set epoch",
			"err", err,
		)
	}
}

func doWaitNodes(cmd *cobra.Command, args []string) {
	conn, client := doConnect(cmd)
	defer conn.Close()

	logger.Info("waiting for nodes",
		"nodes", nodes,
	)

	// Use background context to block until all nodes register.
	ctx := context.Background()

	err := backoff.Retry(func() error {
		_, err := client.WaitNodes(ctx, &dummydebug.WaitNodesRequest{Nodes: nodes})
		// Treat Unavailable errors as transient (and retry), all other errors are permanent.
		if s, _ := status.FromError(err); s.Code() == codes.Unavailable {
			return err
		} else if err != nil {
			return backoff.Permanent(err)
		}

		return nil
	}, backoff.NewExponentialBackOff())
	if err != nil {
		logger.Error("failed to wait for nodes",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("enough nodes have been registered")
}

// Register registers the dummy sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	dummyCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	dummySetEpochCmd.Flags().Uint64VarP(&epoch, "epoch", "e", 0, "set epoch to given value")
	dummyWaitNodesCmd.Flags().Uint64VarP(&nodes, "nodes", "n", 1, "number of nodes to wait for")

	dummyCmd.AddCommand(dummySetEpochCmd)
	dummyCmd.AddCommand(dummyWaitNodesCmd)
	parentCmd.AddCommand(dummyCmd)
}