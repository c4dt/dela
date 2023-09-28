package pbft

import (
	"testing"

	"github.com/c4dt/dela/core/ordering/cosipbft/types"
	"github.com/c4dt/dela/crypto/bls"
	"github.com/c4dt/dela/internal/testing/fake"
	"github.com/stretchr/testify/require"
)

func TestView_Getters(t *testing.T) {
	param := ViewParam{
		From:   fake.NewAddress(0),
		ID:     types.Digest{1},
		Leader: 5,
	}

	view := NewView(param, fake.Signature{})

	require.Equal(t, fake.NewAddress(0), view.GetFrom())
	require.Equal(t, types.Digest{1}, view.GetID())
	require.Equal(t, uint16(5), view.GetLeader())
	require.Equal(t, fake.Signature{}, view.GetSignature())
}

func TestView_Verify(t *testing.T) {
	param := ViewParam{
		From:   fake.NewAddress(0),
		ID:     types.Digest{2},
		Leader: 3,
	}

	signer := bls.NewSigner()

	view, err := NewViewAndSign(param, signer)
	require.NoError(t, err)
	require.NoError(t, view.Verify(signer.GetPublicKey()))

	_, err = NewViewAndSign(param, fake.NewBadSigner())
	require.EqualError(t, err, fake.Err("signer"))

	err = view.Verify(fake.NewBadPublicKey())
	require.EqualError(t, err, fake.Err("verify"))
}
