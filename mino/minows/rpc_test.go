package minows

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/dela/mino"
	"go.dedis.ch/dela/serde"
	"go.dedis.ch/dela/testing/fake"
)

func Test_rpc_Call(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6002/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := fake.Message{}
	players := mino.NewAddresses(player.GetAddress())

	responses, err := r.Call(ctx, req, players)
	require.NoError(t, err)
	resp := <-responses
	from := resp.GetFrom().(address)
	require.Equal(t, player.GetAddress(), from)
	msg, err := resp.GetMessageOrError()
	require.NoError(t, err)
	require.Equal(t, fake.Message{}, msg)
	_, ok := <-responses
	require.False(t, ok)
	require.Equal(t, []mino.Address{initiator.GetAddress()}, handler.from)
}

func Test_rpc_Call_ToSelf(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := fake.Message{}
	players := mino.NewAddresses(initiator.GetAddress())

	responses, err := r.Call(ctx, req, players)
	require.NoError(t, err)
	resp := <-responses
	from := resp.GetFrom().(address)
	require.Equal(t, initiator.GetAddress(), from)
	msg, err := resp.GetMessageOrError()
	require.NoError(t, err)
	require.Equal(t, fake.Message{}, msg)
	_, ok := <-responses
	require.False(t, ok)
}

func Test_rpc_Call_NoPlayers(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := fake.Message{}
	players := mino.NewAddresses()

	_, err := r.Call(ctx, req, players)
	require.Nil(t, err)
}

func Test_rpc_Call_WrongAddressType(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6002/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := fake.Message{}
	players := mino.NewAddresses(fake.Address{})

	_, err := r.Call(ctx, req, players)
	require.ErrorContains(t, err, "wrong address type")
}

func Test_rpc_Call_DiffNamespace(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6002/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player.WithSegment("segment"), handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := fake.Message{}
	players := mino.NewAddresses(player.GetAddress())

	responses, err := r.Call(ctx, req, players)
	require.NoError(t, err)
	resp := <-responses
	from := resp.GetFrom().(address)
	require.Equal(t, player.GetAddress(), from)
	_, err = resp.GetMessageOrError()
	require.ErrorContains(t, err, "protocols not supported")
	_, open := <-responses
	require.False(t, open)
}

func Test_rpc_Call_ContextCancelled(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6002/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	req := fake.Message{}
	players := mino.NewAddresses(player.GetAddress())

	cancel()
	responses, _ := r.Call(ctx, req, players)
	<-responses
	_, ok := <-responses
	require.False(t, ok)
}

func Test_rpc_Call_ReleasesStreams(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6011/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6012/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	players := mino.NewAddresses(player.GetAddress())
	for range 300 {
		responses, err := r.Call(t.Context(), fake.Message{}, players)
		require.NoError(t, err)

		resp := <-responses
		_, err = resp.GetMessageOrError()
		require.NoError(t, err)
		_, open := <-responses
		require.False(t, open)
	}
}

func Test_rpc_Stream_ReleasesHandledStream(t *testing.T) {
	handler := &returnHandler{done: make(chan struct{})}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6041/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6042/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	players := mino.NewAddresses(player.GetAddress())

	_, _, err := r.Stream(ctx, players)
	require.NoError(t, err)
	select {
	case <-handler.done:
	case <-time.After(time.Second):
		t.Fatal("stream handler did not return")
	}

	require.Eventually(t, func() bool {
		for _, conn := range player.host.Network().Conns() {
			if len(conn.GetStreams()) > 0 {
				return false
			}
		}
		return true
	}, time.Second, 10*time.Millisecond)
}

func Test_rpc_Stream_DeliversBeforeCancel(t *testing.T) {
	handler := &receiveHandler{received: make(chan serde.Message, 1)}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6071/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6072/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	players := mino.NewAddresses(player.GetAddress())
	sender, _, err := r.Stream(ctx, players)
	require.NoError(t, err)

	errs := sender.Send(fake.Message{}, player.GetAddress())
	require.NoError(t, <-errs)
	cancel()

	select {
	case msg := <-handler.received:
		require.Equal(t, fake.Message{}, msg)
	case <-time.After(time.Second):
		t.Fatal("message was not delivered before shutdown")
	}
}

func Test_rpc_Stream(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6002/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	players := mino.NewAddresses(player.GetAddress())

	sender, receiver, err := r.Stream(ctx, players)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)
}

func Test_rpc_Stream_PartialConnectivity(t *testing.T) {
	handler := newEchoHandler()
	const addrInitiator = "/ip4/127.0.0.1/tcp/6051/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	const addrPlayer = "/ip4/127.0.0.1/tcp/6052/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	unreachable := mustCreateAddress(t, "/ip4/127.0.0.1/tcp/6059/ws",
		"QmaD31nEzFGwD8dK96UFWHtTYTqYJgHLMYSFz4W4Hm2WCU")
	players := mino.NewAddresses(player.GetAddress(), unreachable)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	sender, receiver, err := r.Stream(ctx, players)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)

	errs := sender.Send(fake.Message{}, player.GetAddress(), unreachable)
	require.ErrorContains(t, <-errs, "not player")
	_, open := <-errs
	require.False(t, open)
	handler.wait(1)
}

func Test_rpc_Stream_NoReachablePlayers(t *testing.T) {
	handler := newEchoHandler()
	const addrInitiator = "/ip4/127.0.0.1/tcp/6061/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	unreachable := mustCreateAddress(t, "/ip4/127.0.0.1/tcp/6069/ws",
		"QmaD31nEzFGwD8dK96UFWHtTYTqYJgHLMYSFz4W4Hm2WCU")
	players := mino.NewAddresses(unreachable)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, _, err := r.Stream(ctx, players)
	require.ErrorContains(t, err, "could not open stream")
}

func Test_rpc_Stream_ToSelf(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	players := mino.NewAddresses(initiator.GetAddress())

	sender, receiver, err := r.Stream(ctx, players)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, receiver)
}

func Test_rpc_Stream_NoPlayers(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	players := mino.NewAddresses()

	_, _, err := r.Stream(ctx, players)
	require.ErrorContains(t, err, "no players")
}

func Test_rpc_Stream_WrongAddressType(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	players := mino.NewAddresses(fake.Address{})

	_, _, err := r.Stream(ctx, players)
	require.ErrorContains(t, err, "wrong address type")
}

func Test_rpc_Stream_ContextCancelled(t *testing.T) {
	handler := &echoHandler{}
	const addrInitiator = "/ip4/127.0.0.1/tcp/6001/ws"
	initiator, stop := mustCreateMinows(t, addrInitiator, addrInitiator)
	defer stop()
	r := mustCreateRPC(t, initiator, handler)
	const addrPlayer = "/ip4/127.0.0.1/tcp/6002/ws"
	player, stop := mustCreateMinows(t, addrPlayer, addrPlayer)
	defer stop()
	mustCreateRPC(t, player, handler)

	ctx, cancel := context.WithCancel(t.Context())
	players := mino.NewAddresses(player.GetAddress())

	cancel()
	_, _, err := r.Stream(ctx, players)
	require.Error(t, err)
}

// echoHandler implements mino.Handler
// Captures senders of received messages for test assertions and
// echos back the same message
// - implements mino.Handler
type echoHandler struct {
	from       []mino.Address
	messages   []serde.Message
	mutex      sync.Mutex
	msgCounter chan struct{}
}

func newEchoHandler() *echoHandler {
	return &echoHandler{msgCounter: make(chan struct{}, 100)}
}

func (h *echoHandler) Process(req mino.Request) (
	resp serde.Message,
	err error,
) {
	h.from = append(h.from, req.Address)
	h.messages = append(h.messages, req.Message)
	return req.Message, nil
}

func (h *echoHandler) Stream(out mino.Sender, in mino.Receiver) error {
	for {
		from, msg, err := in.Recv(context.Background())
		if err != nil {
			return err
		}
		h.mutex.Lock()
		h.from = append(h.from, from)
		h.messages = append(h.messages, msg)
		err = <-out.Send(msg, from)
		h.msgCounter <- struct{}{}
		h.mutex.Unlock()
		if err != nil {
			return err
		}
	}
}

func (h *echoHandler) wait(count int) {
	for i := 0; i < count; i++ {
		<-h.msgCounter
	}
}

func mustCreateRPC(t *testing.T, m mino.Mino, h mino.Handler) mino.RPC {
	r, err := m.CreateRPC("test", h, fake.MessageFactory{})
	require.NoError(t, err)
	return r
}

// forwardHandler implements mino.Handler
// Forwards received stream messages to a configured target.
// - implements mino.Handler
type forwardHandler struct {
	target mino.Address
	result chan error
}

func (h forwardHandler) Process(req mino.Request) (serde.Message, error) {
	return req.Message, nil
}

func (h forwardHandler) Stream(out mino.Sender, in mino.Receiver) error {
	_, msg, err := in.Recv(context.Background())
	if err != nil {
		return err
	}

	err = <-out.Send(msg, h.target)
	h.result <- err

	return err
}

type returnHandler struct {
	done chan struct{}
}

func (h *returnHandler) Process(req mino.Request) (serde.Message, error) {
	return req.Message, nil
}

func (h *returnHandler) Stream(mino.Sender, mino.Receiver) error {
	close(h.done)
	return nil
}

type receiveHandler struct {
	received chan serde.Message
}

func (h *receiveHandler) Process(req mino.Request) (serde.Message, error) {
	return req.Message, nil
}

func (h *receiveHandler) Stream(_ mino.Sender, in mino.Receiver) error {
	_, msg, err := in.Recv(context.Background())
	if err != nil {
		return err
	}
	h.received <- msg
	return nil
}
