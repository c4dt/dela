package command

import (
	"testing"

	"github.com/c4dt/dela/cli"
	"github.com/c4dt/dela/internal/testing/fake"
	"github.com/stretchr/testify/require"
)

func TestSetCommands(t *testing.T) {
	init := Initializer{}

	call := &fake.Call{}
	provider := fakeBuilder{call: call}
	init.SetCommands(provider)

	require.Equal(t, 10, call.Len())
}

// -----------------------------------------------------------------------------
// Utility functions

type fakeCommandBuilder struct {
	call *fake.Call
}

func (b fakeCommandBuilder) SetSubCommand(name string) cli.CommandBuilder {
	b.call.Add(name)
	return b
}

func (b fakeCommandBuilder) SetDescription(value string) {
	b.call.Add(value)
}

func (b fakeCommandBuilder) SetFlags(flags ...cli.Flag) {
	b.call.Add(flags)
}

func (b fakeCommandBuilder) SetAction(a cli.Action) {
	b.call.Add(a)
}

type fakeBuilder struct {
	call *fake.Call
}

func (b fakeBuilder) SetCommand(name string) cli.CommandBuilder {
	b.call.Add(name)
	return fakeCommandBuilder(b)
}
