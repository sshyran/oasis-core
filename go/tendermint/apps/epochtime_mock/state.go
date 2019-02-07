package epochtimemock

import (
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	// Mock epochtime state.
	stateCurrentEpoch = "epochtime_mock/current"
)

var (
	_ cbor.Marshaler   = (*mockEpochTimeState)(nil)
	_ cbor.Unmarshaler = (*mockEpochTimeState)(nil)
)

type mockEpochTimeState struct {
	Epoch  api.EpochTime `codec:"epoch"`
	Height int64         `codec:"height"`
}

func (s *mockEpochTimeState) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

func (s *mockEpochTimeState) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) getEpoch() (api.EpochTime, int64, error) {
	_, raw := s.Snapshot.Get([]byte(stateCurrentEpoch))
	if raw == nil {
		return api.EpochTime(0), 0, nil
	}

	var state mockEpochTimeState
	err := state.UnmarshalCBOR(raw)
	return state.Epoch, state.Height, err
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

type mutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *mutableState) setEpoch(epoch api.EpochTime, height int64) {
	state := mockEpochTimeState{Epoch: epoch, Height: height}

	s.tree.Set(
		[]byte(stateCurrentEpoch),
		state.MarshalCBOR(),
	)
}

func newMutableState(tree *iavl.MutableTree) *mutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &mutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
