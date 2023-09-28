package controller

import (
	"github.com/c4dt/dela"
	"github.com/c4dt/dela/cli"
	"github.com/c4dt/dela/cli/node"
	"github.com/c4dt/dela/dkg/pedersen"
	"github.com/c4dt/dela/mino"
	"golang.org/x/xerrors"
)

// NewMinimal returns a new minimal initializer
func NewMinimal() node.Initializer {
	return minimal{}
}

// minimal is an initializer with the minimum set of commands. Indeed it only
// creates and injects a new DKG
//
// - implements node.Initializer
type minimal struct{}

// Build implements node.Initializer. In this case we don't need any command.
func (m minimal) SetCommands(_ node.Builder) {}

// OnStart implements node.Initializer. It creates and registers a pedersen DKG.
func (m minimal) OnStart(ctx cli.Flags, inj node.Injector) error {
	var no mino.Mino
	err := inj.Resolve(&no)
	if err != nil {
		return xerrors.Errorf("failed to resolve mino: %v", err)
	}

	dkg, pubkey := pedersen.NewPedersen(no)

	inj.Inject(dkg)

	pubkeyBuf, err := pubkey.MarshalBinary()
	if err != nil {
		return xerrors.Errorf("failed to encode pubkey: %v", err)
	}

	dela.Logger.Info().
		Hex("public key", pubkeyBuf).
		Msg("perdersen public key")

	return nil
}

// OnStop implements node.Initializer.
func (minimal) OnStop(node.Injector) error {
	return nil
}
