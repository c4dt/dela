package flatcosi

import (
	"github.com/c4dt/dela/cosi"
	"github.com/c4dt/dela/crypto"
	"github.com/c4dt/dela/mino"
	"github.com/c4dt/dela/serde"
	"golang.org/x/xerrors"
)

// Handler is the RPC callback when a participant of a collective signing
// receives a request. It will invoke the reactor and sign the unique value, or
// return an error if the reactor refuses the message.
//
// - implements mino.Handler
type handler struct {
	mino.UnsupportedHandler
	signer  crypto.Signer
	reactor cosi.Reactor
}

func newHandler(s crypto.Signer, r cosi.Reactor) handler {
	return handler{
		signer:  s,
		reactor: r,
	}
}

// Process implements mino.Handler. It sends the message to the reactor and
// sends back the signature if the message is correctly processed, otherwise it
// returns an error.
func (h handler) Process(req mino.Request) (serde.Message, error) {
	switch msg := req.Message.(type) {

	case cosi.SignatureRequest:
		buf, err := h.reactor.Invoke(req.Address, msg.Value)
		if err != nil {
			return nil, xerrors.Errorf("couldn't hash message: %v", err)
		}

		sig, err := h.signer.Sign(buf)
		if err != nil {
			return nil, xerrors.Errorf("couldn't sign: %v", err)
		}

		resp := cosi.SignatureResponse{
			Signature: sig,
		}

		return resp, nil

	default:
		return nil, xerrors.Errorf("invalid message type '%T'", msg)
	}
}
