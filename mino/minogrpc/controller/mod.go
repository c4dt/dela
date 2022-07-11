// Package controller implements a controller for minogrpc.
//
// The controller can be used in a CLI to inject a dependency for Mino. It will
// start the overlay on the start command, and make sure resources are cleaned
// when the CLI daemon is stopping.
//
// Documentation Last Review: 07.10.2020
//
package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"go.dedis.ch/dela"
	"go.dedis.ch/dela/cli"
	"go.dedis.ch/dela/cli/node"
	"go.dedis.ch/dela/core/store/kv"
	"go.dedis.ch/dela/crypto/loader"
	"go.dedis.ch/dela/mino"
	"go.dedis.ch/dela/mino/minogrpc"
	"go.dedis.ch/dela/mino/minogrpc/certs"
	"go.dedis.ch/dela/mino/minogrpc/session"
	"go.dedis.ch/dela/mino/router"
	"go.dedis.ch/dela/mino/router/flat"
	"go.dedis.ch/dela/mino/router/tree"
	"golang.org/x/xerrors"
)

const certKeyName = "cert.key"

// MiniController is an initializer with the minimum set of commands.
//
// - implements node.Initializer
type miniController struct {
	random io.Reader
	curve  elliptic.Curve
}

// NewController returns a new initializer to start an instance of Minogrpc.
func NewController() node.Initializer {
	return miniController{
		random: rand.Reader,
		curve:  elliptic.P521(),
	}
}

// Build implements node.Initializer. It populates the builder with the commands
// to control Minogrpc.
func (m miniController) SetCommands(builder node.Builder) {
	builder.SetStartFlags(
		cli.StringFlag{
			Name:  "listen",
			Usage: "set the address to listen on",
			Value: "0.0.0.0:2000",
		},
		cli.StringFlag{
			Name:     "public",
			Usage:    "sets the public node address. By default it uses the same as --listen",
			Value:    "",
			Required: false,
		},
		cli.StringFlag{
			Name:     "routing",
			Usage:    "sets the kind of routing: 'flat' or 'tree'",
			Value:    "flat",
			Required: false,
		},
	)

	cmd := builder.SetCommand("minogrpc")
	cmd.SetDescription("Network overlay administration")

	sub := cmd.SetSubCommand("certificates")
	sub.SetDescription("list the certificates of the server")
	sub.SetAction(builder.MakeAction(certAction{}))

	rm := sub.SetSubCommand("rm")
	rm.SetDescription("remove a certificate")
	rm.SetFlags(cli.StringFlag{
		Name:     "address",
		Usage:    "address associated to the certificate(s), in base64",
		Required: true,
	})
	rm.SetAction(builder.MakeAction(removeAction{}))

	sub = cmd.SetSubCommand("token")
	sub.SetDescription("generate a token to share to others to join the network")
	sub.SetFlags(
		cli.DurationFlag{
			Name:  "expiration",
			Usage: "amount of time before expiration",
			Value: 24 * time.Hour,
		},
	)
	sub.SetAction(builder.MakeAction(tokenAction{}))

	sub = cmd.SetSubCommand("join")
	sub.SetDescription("join a network of participants")
	sub.SetFlags(
		cli.StringFlag{
			Name:     "token",
			Usage:    "secret token generated by the node to join",
			Required: true,
		},
		cli.StringFlag{
			Name:     "address",
			Usage:    "address of the node to join",
			Required: true,
		},
		cli.StringFlag{
			Name:     "cert-hash",
			Usage:    "certificate hash of the distant server",
			Required: true,
		},
	)
	sub.SetAction(builder.MakeAction(joinAction{}))
}

// OnStart implements node.Initializer. It starts the minogrpc instance and
// injects it in the dependency resolver.
func (m miniController) OnStart(ctx cli.Flags, inj node.Injector) error {
	listenURL, err := url.Parse(ctx.String("listen"))
	if err != nil {
		return xerrors.Errorf("failed to parse listen URL: %v", err)
	}

	listen, err := net.ResolveTCPAddr(listenURL.Scheme, listenURL.Host)
	if err != nil {
		return xerrors.Errorf("failed to resolve tcp address: %v", err)
	}

	var rter router.Router

	switch ctx.String("routing") {
	case "flat":
		rter = flat.NewRouter(minogrpc.NewAddressFactory())
	case "tree":
		rter = tree.NewRouter(minogrpc.NewAddressFactory())
	default:
		return xerrors.Errorf("unknown routing: %s", ctx.String("routing"))
	}

	var db kv.DB
	err = inj.Resolve(&db)
	if err != nil {
		return xerrors.Errorf("injector: %v", err)
	}

	certs := certs.NewDiskStore(db, session.AddressFactory{})

	key, err := m.getKey(ctx)
	if err != nil {
		return xerrors.Errorf("cert private key: %v", err)
	}

	opts := []minogrpc.Option{
		minogrpc.WithStorage(certs),
		minogrpc.WithCertificateKey(key, key.Public()),
	}

	var public *url.URL

	if ctx.String("public") != "" {
		public, err = url.Parse(ctx.String("public"))
		if err != nil {
			return xerrors.Errorf("failed to parse public: %v", err)
		}
	}

	o, err := minogrpc.NewMinogrpc(listen, public, rter, opts...)
	if err != nil {
		return xerrors.Errorf("couldn't make overlay: %v", err)
	}

	inj.Inject(o)

	dela.Logger.Info().Msgf("%v is running", o)

	return nil
}

// StoppableMino is an extension of Mino to allow one to stop the instance.
type StoppableMino interface {
	mino.Mino

	GracefulStop() error
}

// OnStop implements node.Initializer. It stops the network overlay.
func (m miniController) OnStop(inj node.Injector) error {
	var o StoppableMino
	err := inj.Resolve(&o)
	if err != nil {
		return xerrors.Errorf("injector: %v", err)
	}

	err = o.GracefulStop()
	if err != nil {
		return xerrors.Errorf("while stopping mino: %v", err)
	}

	return nil
}

func (m miniController) getKey(flags cli.Flags) (*ecdsa.PrivateKey, error) {
	loader := loader.NewFileLoader(filepath.Join(flags.Path("config"), certKeyName))

	keydata, err := loader.LoadOrCreate(newGenerator(m.random, m.curve))
	if err != nil {
		return nil, xerrors.Errorf("while loading: %v", err)
	}

	key, err := x509.ParseECPrivateKey(keydata)
	if err != nil {
		return nil, xerrors.Errorf("while parsing: %v", err)
	}

	return key, nil
}

// generator can generate a private key compatible with the x509 certificate.
//
// - implements loader.Generator
type generator struct {
	random io.Reader
	curve  elliptic.Curve
}

func newGenerator(r io.Reader, c elliptic.Curve) loader.Generator {
	return generator{
		random: r,
		curve:  c,
	}
}

// Generate implements loader.Generator. It returns the serialized data of a
// private key generated from the an elliptic curve. The data is formatted as a
// PEM block "EC PRIVATE KEY".
func (g generator) Generate() ([]byte, error) {
	priv, err := ecdsa.GenerateKey(g.curve, g.random)
	if err != nil {
		return nil, xerrors.Errorf("ecdsa: %v", err)
	}

	data, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, xerrors.Errorf("while marshaling: %v", err)
	}

	return data, nil
}
