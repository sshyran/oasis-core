package signature

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	require := require.New(t)

	// Make sure a context can be registered.
	var ctx, ctx2 Context
	require.NotPanics(func() { ctx = NewContext("test: dummy context 1") })
	require.NotPanics(func() { ctx2 = NewContext("test: dummy context 2") })

	// Make sure we panic if the same context is registered twice.
	require.Panics(func() { NewContext("test: dummy context 1") })
	// Even with different options.
	require.Panics(func() { NewContext("test: dummy context 1", WithChainSeparation()) })

	// Make sure we panic if context is too long.
	require.Panics(func() { NewContext(strings.Repeat("a", 500)) })

	// Make sure we panic if context includes the chain context separator.
	require.Panics(func() { NewContext("test: dummy context 1 for chain blah") })

	// Make sure a context with chain separation can be registered.
	var chainCtx Context
	require.NotPanics(func() { chainCtx = NewContext("test: dummy context 3", WithChainSeparation()) })

	// Make sure we cannot use an unregistered context.
	unregCtx := Context("test: unregistered")
	_, err := PrepareSignerMessage(unregCtx, []byte("message"))
	require.Error(err, "PrepareSignerMessage should fail with unregistered context")

	// Should work with registered context.
	msg1, err := PrepareSignerMessage(ctx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	msg2, err := PrepareSignerMessage(ctx2, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	require.NotEqual(msg1, msg2, "messages for different contexts should be different")

	// Should fail with context that requires chain separation as no
	// chain context has been set.
	_, err = PrepareSignerMessage(chainCtx, []byte("message"))
	require.Error(err, "PrepareSignerMessage should fail without chain context")

	// Make sure we can set a chain context.
	require.NotPanics(func() { SetChainContext("test: oasis-core tests 1") })
	// Make sure we can set the same chain context again.
	require.NotPanics(func() { SetChainContext("test: oasis-core tests 1") })
	// Make sure we can't modify a set chain context.
	require.Panics(func() { SetChainContext("test: context change") })

	msg1, err = PrepareSignerMessage(chainCtx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work with chain context")

	// Manually change the chain context to test that this generates different
	// messages with different contexts (this is otherwise not allowed).
	UnsafeResetChainContext()
	SetChainContext("test: oasis-core tests")

	msg2, err = PrepareSignerMessage(chainCtx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work with chain context")
	require.NotEqual(msg1, msg2, "messages for different chain contexts should be different")

	// Manually delete a registered context so that we can re-register with
	// different options and check that the messages are different.
	registeredContexts.Delete(chainCtx)

	chainCtx = NewContext("test: dummy context 3")
	msg3, err := PrepareSignerMessage(chainCtx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	require.NotEqual(msg2, msg3, "messages for different contexts should be different")

	// The remote signer requires bypassing the context registration checks.
	UnsafeAllowUnregisteredContexts()
	defer func() {
		allowUnregisteredContexts = false
	}()
	require.True(IsUnsafeUnregisteredContextsAllowed(), "context registration must be bypassed")

	_, err = PrepareSignerMessage(unregCtx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work with unregisered context (bypassed)")
}

func TestBlacklist(t *testing.T) {
	require := require.New(t)

	var pk PublicKey
	err := pk.UnmarshalHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	require.NoError(err, "UnmarshalHex")
	require.True(pk.IsValid(), "test key should initially be valid")

	require.False(pk.IsBlacklisted(), "test key should not initially be blacklisted")
	err = pk.Blacklist()
	require.NoError(err, "Blacklist")
	require.True(pk.IsBlacklisted(), "test key should now be blacklisted")
	require.False(pk.IsValid(), "test key should now be invalid")
}
