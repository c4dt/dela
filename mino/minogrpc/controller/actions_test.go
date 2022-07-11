package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/dela/cli"
	"go.dedis.ch/dela/cli/node"
	"go.dedis.ch/dela/internal/testing/fake"
	"go.dedis.ch/dela/mino"
	"go.dedis.ch/dela/mino/minogrpc"
	"go.dedis.ch/dela/mino/minogrpc/certs"
)

func TestCertAction_Execute(t *testing.T) {
	action := certAction{}

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Injector: node.NewInjector(),
	}

	cert := fake.MakeCertificate(t, 1)

	store := certs.NewInMemoryStore()
	store.Store(fake.NewAddress(0), cert)

	req.Injector.Inject(fakeJoinable{certs: store})

	err := action.Execute(req)
	require.NoError(t, err)
	expected := fmt.Sprintf("Address: fake.Address[0] (AAAAAA==) Certificate: %v\n", cert.Leaf.NotAfter)
	require.Equal(t, expected, out.String())

	req.Injector = node.NewInjector()
	err = action.Execute(req)
	require.EqualError(t, err,
		"couldn't resolve: couldn't find dependency for 'minogrpc.Joinable'")
}

func TestRemoveCert_Execute(t *testing.T) {
	action := removeAction{}

	addr := fake.NewAddress(0)
	addrBuff, err := addr.MarshalText()
	require.NoError(t, err)

	addrB64 := base64.StdEncoding.EncodeToString(addrBuff)

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Injector: node.NewInjector(),
		Flags: node.FlagSet{
			"address": addrB64,
		},
	}

	cert := fake.MakeCertificate(t, 1)

	store := certs.NewInMemoryStore()
	store.Store(addr, cert)

	req.Injector.Inject(fakeJoinable{certs: store})

	err = action.Execute(req)
	require.NoError(t, err)

	store.Range(func(addr mino.Address, cert *tls.Certificate) bool {
		t.Error("store should be empty")
		return false
	})

	expected := fmt.Sprintf("certificate(s) with address %q removed", addrBuff)
	require.Equal(t, expected, out.String())
}

func TestRemoveCert_Execute_NoJoinable(t *testing.T) {
	action := removeAction{}

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Injector: node.NewInjector(),
	}

	err := action.Execute(req)
	require.EqualError(t, err, "couldn't resolve: couldn't find dependency for 'minogrpc.Joinable'")
}

func TestRemoveCert_Execute_BadAddress(t *testing.T) {
	action := removeAction{}

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Injector: node.NewInjector(),
		Flags: node.FlagSet{
			"address": "xx",
		},
	}

	store := certs.NewInMemoryStore()

	req.Injector.Inject(fakeJoinable{certs: store})

	err := action.Execute(req)
	require.EqualError(t, err, "failed to decode base64 address: illegal base64 data at input byte 0")
}

func TestRemoveCert_Execute_BadDelete(t *testing.T) {
	action := removeAction{}

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Injector: node.NewInjector(),
		Flags: node.FlagSet{
			"address": "xx==",
		},
	}

	store := badCertStore{err: fake.GetError()}

	req.Injector.Inject(fakeJoinable{certs: store})

	err := action.Execute(req)
	require.EqualError(t, err, fake.Err("failed to delete"))
}

func TestTokenAction_Execute(t *testing.T) {
	action := tokenAction{}

	flags := make(node.FlagSet)
	flags["expiration"] = time.Millisecond

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Flags:    flags,
		Injector: node.NewInjector(),
	}

	cert := fake.MakeCertificate(t, 1)

	store := certs.NewInMemoryStore()
	store.Store(fake.NewAddress(0), cert)

	hash, err := store.Hash(cert)
	require.NoError(t, err)

	req.Injector.Inject(fakeJoinable{certs: store})

	err = action.Execute(req)
	require.NoError(t, err)

	expected := fmt.Sprintf("--token abc --cert-hash %s\n",
		base64.StdEncoding.EncodeToString(hash))
	require.Equal(t, expected, out.String())

	req.Injector = node.NewInjector()
	err = action.Execute(req)
	require.EqualError(t, err,
		"couldn't resolve: couldn't find dependency for 'minogrpc.Joinable'")
}

func TestTokenAction_FailedHash(t *testing.T) {
	action := tokenAction{}

	flags := make(node.FlagSet)
	flags["expiration"] = time.Millisecond

	out := new(bytes.Buffer)
	req := node.Context{
		Out:      out,
		Flags:    flags,
		Injector: node.NewInjector(),
	}

	cert := fake.MakeCertificate(t, 1)

	store := certs.NewInMemoryStore()
	store.Store(fake.NewAddress(0), cert)

	req.Injector.Inject(fakeJoinable{certs: badCertStore{err: fake.GetError()}})

	err := action.Execute(req)
	require.EqualError(t, err, fake.Err("couldn't hash certificate"))
}

func TestJoinAction_Execute(t *testing.T) {
	action := joinAction{}

	flags := make(node.FlagSet)
	flags["cert-hash"] = "YQ=="

	req := node.Context{
		Flags:    flags,
		Injector: node.NewInjector(),
	}

	req.Injector.Inject(fakeJoinable{})

	err := action.Execute(req)
	require.NoError(t, err)

	flags["cert-hash"] = "a"
	err = action.Execute(req)
	require.EqualError(t, err,
		"couldn't decode digest: illegal base64 data at input byte 0")

	flags["cert-hash"] = "YQ=="
	req.Injector.Inject(fakeJoinable{err: fake.GetError()})
	err = action.Execute(req)
	require.EqualError(t, err, fake.Err("couldn't join"))

	req.Injector = node.NewInjector()
	err = action.Execute(req)
	require.EqualError(t, err,
		"couldn't resolve: couldn't find dependency for 'minogrpc.Joinable'")
}

func TestJoinAction_FailedParseAddr(t *testing.T) {
	action := joinAction{}

	flags := make(node.FlagSet)
	flags["address"] = ":xxx"

	err := action.Execute(node.Context{Flags: flags})
	require.EqualError(t, err, "failed to parse addr: parse \":xxx\": missing protocol scheme")
}

// -----------------------------------------------------------------------------
// Utility functions

type fakeJoinable struct {
	minogrpc.Joinable
	certs certs.Storage
	err   error
}

func (j fakeJoinable) GetCertificate() *tls.Certificate {
	cert, _ := j.certs.Load(fake.NewAddress(0))

	return cert
}

func (j fakeJoinable) GetCertificateStore() certs.Storage {
	return j.certs
}

func (j fakeJoinable) GenerateToken(time.Duration) string {
	return "abc"
}

func (j fakeJoinable) Join(*url.URL, string, []byte) error {
	return j.err
}

func (fakeJoinable) GetAddressFactory() mino.AddressFactory {
	return fake.AddressFactory{}
}

type fakeContext struct {
	cli.Flags
	duration time.Duration
	str      map[string]string
	path     string
	num      int
}

func (ctx fakeContext) Duration(string) time.Duration {
	return ctx.duration
}

func (ctx fakeContext) String(key string) string {
	return ctx.str[key]
}

func (ctx fakeContext) Path(string) string {
	return ctx.path
}

func (ctx fakeContext) Int(string) int {
	return ctx.num
}

type badCertStore struct {
	certs.Storage
	err error
}

func (badCertStore) Load(mino.Address) (*tls.Certificate, error) {
	return nil, nil
}

func (c badCertStore) Hash(*tls.Certificate) ([]byte, error) {
	return nil, c.err
}

func (c badCertStore) Delete(mino.Address) error {
	return c.err
}
