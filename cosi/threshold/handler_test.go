package threshold

import (
	"testing"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/dela/encoding"
	"go.dedis.ch/dela/internal/testing/fake"
	"golang.org/x/xerrors"
)

func TestThresholdHandler_Stream(t *testing.T) {
	handler := newHandler(
		&CoSi{signer: fake.NewSigner(), encoder: encoding.NewProtoEncoder()},
		fakeReactor{},
	)

	rcvr := &fakeReceiver{resps: makeResponse()}
	sender := fakeSender{}

	err := handler.Stream(sender, rcvr)
	require.NoError(t, err)

	rcvr.err = xerrors.New("oops")
	err = handler.processRequest(sender, rcvr)
	require.EqualError(t, err, "failed to receive: oops")

	handler.reactor = fakeReactor{err: xerrors.New("oops")}
	rcvr.err = nil
	rcvr.resps = makeResponse()
	err = handler.processRequest(sender, rcvr)
	require.EqualError(t, err, "couldn't hash message: oops")

	handler.reactor = fakeReactor{}
	handler.signer = fake.NewBadSigner()
	rcvr.resps = makeResponse()
	err = handler.processRequest(sender, rcvr)
	require.EqualError(t, err, "couldn't sign: fake error")

	handler.signer = fake.NewSigner()
	handler.encoder = fake.BadPackEncoder{}
	rcvr.resps = makeResponse()
	err = handler.processRequest(sender, rcvr)
	require.EqualError(t, err, "couldn't pack signature: fake error")

	handler.encoder = encoding.NewProtoEncoder()
	sender = fakeSender{numErr: 1}
	rcvr.resps = makeResponse()
	err = handler.Stream(sender, rcvr)
	require.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Utility functions

func makeResponse() [][]interface{} {
	return [][]interface{}{{fake.Address{}, &empty.Empty{}}}
}
