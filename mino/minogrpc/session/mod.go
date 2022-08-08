// Package session defines an abstraction of a session during a distributed RPC.
//
// During a stream-based distributed RPC in minogrpc, the stream is kept alive
// during the whole protocol to act as a health check so that resources can be
// cleaned eventually, or if something goes wrong. The session manages this
// state while also managing the relays to other participants that the node must
// forward the messages to. Basically, a session has one or several relays open
// to the parent nodes and zero, one or multiple relays to other participants
// depending on the routing of the messages.
//
// The package implements a unicast and a stream relay. Stream relay is only
// used when the orchestrator of a protocol is connecting to the first
// participant. Unicast is then used so that the sender of a message can receive
// feedbacks on the status of the message.
//
// Documentation Last Review: 07.10.20202
//
package session

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/dlsniper/debugger"
	"github.com/rs/zerolog"
	"go.dedis.ch/dela"
	"go.dedis.ch/dela/internal/traffic"
	"go.dedis.ch/dela/mino"
	"go.dedis.ch/dela/mino/minogrpc/ptypes"
	"go.dedis.ch/dela/mino/router"
	"go.dedis.ch/dela/serde"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func goid() string {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	_, err := strconv.Atoi(idField)
	if err != nil {
		panic(fmt.Sprintf("cannot get goroutine id: %v", err))
	}
	return idField
}

// HandshakeKey is the key to the handshake store in the headers.
const HandshakeKey = "handshake"

// ConnectionManager is an interface required by the session to open and release
// connections to the relays.
type ConnectionManager interface {
	Len() int
	Acquire(mino.Address) (grpc.ClientConnInterface, error)
	Release(mino.Address)
}

// Session is an interface for a stream session that allows to send messages to
// the parent and relays, while receiving the ones for the local address.
type Session interface {
	mino.Sender
	mino.Receiver

	// GetNumParents returns the number of active parents for the session.
	GetNumParents() int

	// Listen takes a stream that will determine when to close the session.
	Listen(parent Relay, table router.RoutingTable, ready chan struct{})

	// SetPassive sets a new passive parent. A passive parent is part of the
	// parent relays, but the stream does not listen to, and thus it is not
	// removed from the map if it closed.
	SetPassive(parent Relay, table router.RoutingTable)

	// Close shutdowns the session so that future calls to receive will return
	// an error.
	Close()

	// RecvPacket takes a packet and the address of the distant peer that have
	// sent it, then pass it to the correct relay according to the routing
	// table.
	RecvPacket(from mino.Address, p *ptypes.Packet) (*ptypes.Ack, error)
}

// Relay is the interface of the relays spawn by the session when trying to
// contact a child node.
type Relay interface {
	// GetDistantAddress returns the address of the peer at the other end of the
	// relay.
	GetDistantAddress() mino.Address

	// Stream returns the stream that is holding the relay.
	Stream() PacketStream

	// Send sends a packet through the relay.
	Send(ctx context.Context, p router.Packet) (*ptypes.Ack, error)

	// Close closes the relay and clean the resources.
	Close() error
}

type parent struct {
	relay Relay
	table router.RoutingTable
}

// session is a participant to a stream protocol which has a parent gateway that
// determines when to close, and it can open further relays to distant peers if
// the routing table requires it.
//
// - implements session.Session
type session struct {
	sync.Mutex
	sync.WaitGroup

	logger  zerolog.Logger
	md      metadata.MD
	me      mino.Address
	errs    chan error
	pktFac  router.PacketFactory
	msgFac  serde.Factory
	context serde.Context
	queue   Queue
	relays  map[mino.Address]Relay
	connMgr ConnectionManager
	traffic *traffic.Traffic

	parents map[mino.Address]parent
	// A read-write lock is used there as there are much more read requests than
	// write ones, and the read should be parallelized.
	parentsLock sync.RWMutex
}

// NewSession creates a new session for the provided parent relay.
func NewSession(
	md metadata.MD,
	me mino.Address,
	msgFac serde.Factory,
	pktFac router.PacketFactory,
	ctx serde.Context,
	connMgr ConnectionManager,
) Session {
	sess := &session{
		logger:  dela.Logger.With().Str("addr", me.String()).Logger(),
		md:      md,
		me:      me,
		errs:    make(chan error, 1),
		msgFac:  msgFac,
		pktFac:  pktFac,
		context: ctx,
		queue:   newNonBlockingQueue(),
		relays:  make(map[mino.Address]Relay),
		connMgr: connMgr,
		parents: make(map[mino.Address]parent),
	}

	switch os.Getenv(traffic.EnvVariable) {
	case "log":
		sess.traffic = traffic.NewTraffic(me, ioutil.Discard)
	case "print":
		sess.traffic = traffic.NewTraffic(me, os.Stdout)
	}

	return sess
}

// GetNumParents implements session.Session. It returns the number of active
// parents in the session.
func (s *session) GetNumParents() int {
	s.parentsLock.RLock()
	defer s.parentsLock.RUnlock()

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("reading number of parents!")

	return len(s.parents)
}

// Listen implements session.Session. It listens for the stream and returns only
// when the stream has been closed.
func (s *session) Listen(
	relay Relay, table router.RoutingTable, ready chan struct{},
) {
	defer func() {
		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("deleting distant address from parents!")
		s.parentsLock.Lock()

		delete(s.parents, relay.GetDistantAddress())

		s.parentsLock.Unlock()

		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("deleted distant address from parents!")
	}()

	s.SetPassive(relay, table)

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("listen ready!")
	close(ready)

	stream := relay.Stream()
	for {
		_, err := stream.Recv()
		code := status.Code(err)
		if err == io.EOF || code != codes.Unknown {
			s.logger.Trace().Stringer("code", code).Msg("session closing")
			return
		}
		if err != nil {
			s.logger.Err(err).
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("stream closed unexpectedly!")
			s.errs <- xerrors.Errorf("stream closed unexpectedly: %v", err)
			return
		}
	}
}

// SetPassive implements session.Session. It adds the parent relay to the map
// but in the contrary of Listen, it won't listen for the stream.
func (s *session) SetPassive(p Relay, table router.RoutingTable) {
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("adding distant address to parents")

	s.parentsLock.Lock()
	defer s.parentsLock.Unlock()

	addr := p.GetDistantAddress()

	s.parents[addr] = parent{
		relay: p,
		table: table,
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("added distant address to parents")
}

// Close implements session.Session. It shutdowns the session and waits for the
// relays to close.
func (s *session) Close() {
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("closing session")

	close(s.errs)

	s.Wait()

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("closing session - done")
}

// RecvPacket implements session.Session. It process the packet and send it to
// the relays, or itself.
func (s *session) RecvPacket(from mino.Address, p *ptypes.Packet) (
	*ptypes.Ack, error,
) {
	pkt, err := s.pktFac.PacketOf(s.context, p.GetSerialized())
	if err != nil {
		return nil, xerrors.Errorf("packet malformed: %v", err)
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("RecvPacket() sending to a parent")
	s.parentsLock.RLock()
	defer s.parentsLock.RUnlock()

	// Try to send the packet to each parent until one works.
	for _, parent := range s.parents {
		s.traffic.LogRecv(parent.relay.Stream().Context(), from, pkt)

		errs := make(chan error, len(pkt.GetDestination()))
		sent := s.sendPacket(parent, pkt, errs)
		close(errs)

		if sent {
			ack := &ptypes.Ack{}

			for err := range errs {
				ack.Errors = append(ack.Errors, err.Error())
			}

			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("RecvPacket() sending to a parent - done")
			return ack, nil
		}
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("RecvPacket() sending to a parent - failed")
	return nil, xerrors.Errorf(
		"packet is dropped (tried %d parent-s)", len(s.parents),
	)
}

// Send implements mino.Sender. It sends the message to the provided addresses
// through the relays or the parent.
func (s *session) Send(msg serde.Message, addrs ...mino.Address) <-chan error {
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("Send() sends messages")

	errs := make(chan error, len(addrs)+1)

	for i, addr := range addrs {
		switch to := addr.(type) {
		case wrapAddress:
			addrs[i] = to.Unwrap()
		}
	}

	go func() {
		defer close(errs)

		debugger.SetLabels(
			func() []string {
				return []string{
					"module", "mino/session",
					"operation", "send",
				}
			},
		)

		data, err := msg.Serialize(s.context)
		if err != nil {
			errs <- xerrors.Errorf("failed to serialize msg: %v", err)
			return
		}

		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("Send() finding a parent to send packet")

		s.parentsLock.RLock()
		defer s.parentsLock.RUnlock()

		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("Send() iterating over parents")

		for _, parent := range s.parents {
			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("Send() making a packet")

			packet := parent.table.Make(s.me, addrs, data) // <---

			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("Send() about to send a packet")
			sent := s.sendPacket(parent, packet, errs) // <---
			if sent {
				s.logger.Trace().
					Stringer("from", s.me).
					Str("goid", goid()).
					Msg("Send() found a parent to send packet")
				return
			}
		}

		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("Send() failed finding a parent to send packet")
		errs <- xerrors.New("packet ignored")
	}()

	return errs
}

// Recv implements mino.Receiver. It waits for a message to arrive and returns
// it, or returns an error if something wrong happens. The context can cancel
// the blocking call.
func (s *session) Recv(ctx context.Context) (
	mino.Address, serde.Message, error,
) {
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("Recv() receiving new message")

	select {
	case <-ctx.Done():
		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("Recv() receiving new message - done (ctx)")
		return nil, nil, ctx.Err()

	case err := <-s.errs:
		if err != nil {
			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("Recv() receiving new message - failed (stream closed)")
			return nil, nil, xerrors.Errorf(
				"stream closed unexpectedly: %v", err,
			)
		}
		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("Recv() receiving new message - failed (EOF)")

		return nil, nil, io.EOF

	case packet := <-s.queue.Channel():
		msg, err := s.msgFac.Deserialize(s.context, packet.GetMessage())
		if err != nil {
			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("Recv() receiving new message - failed (deserialize)")
			return nil, nil, xerrors.Errorf("message: %v", err)
		}

		// The source address is wrapped so that an orchestrator will look like
		// its actual source address to the caller.
		from := newWrapAddress(packet.GetSource())

		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Stringer("alias-from", from).
			Msg("Recv() receiving new message - done")
		return from, msg, nil
	}
}

func (s *session) sendPacket(
	p parent, pkt router.Packet, errs chan error,
) bool {
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendPacket() making a packet")

	me := pkt.Slice(s.me)
	if me != nil {
		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("sendPacket() pushing on queue")
		err := s.queue.Push(me)
		if err != nil {
			s.logger.Warn().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("sendPacket() dropping packet")
			errs <- xerrors.Errorf("%v dropped the packet: %v", s.me, err)
		}
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendPacket() forward")
	routes, voids := p.table.Forward(pkt)
	for addr, void := range voids {
		s.logger.Warn().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("sendPacket() no route")
		errs <- xerrors.Errorf("no route to %v: %v", addr, void.Error)
	}

	if len(routes) == 0 && len(voids) == 0 {
		return me != nil
	}

	wg := sync.WaitGroup{}
	wg.Add(len(routes))

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendPacket() starting sendTo's")
	for addr, packet := range routes {
		go s.sendTo(p, addr, packet, errs, &wg)
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendPacket() waiting")

	wg.Wait()

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendPacket() done waiting")

	return true
}

func (s *session) sendTo(
	p parent, to mino.Address, pkt router.Packet, errs chan error,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	debugger.SetLabels(
		func() []string {
			return []string{
				"module", "mino/session",
				"operation", "sendTo",
				"source", pkt.GetSource().String(),
			}
		},
	)

	var relay Relay
	var err error

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendTo() starting")

	if to == nil {
		relay = p.relay
	} else {
		relay, err = s.setupRelay(p, to)
		if err != nil {
			s.logger.Warn().Err(err).Stringer(
				"to", to,
			).Msg("failed to setup relay")

			// Try to open a different relay.
			s.onFailure(p, to, pkt, errs)

			return
		}
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendTo() streaming")

	ctx := p.relay.Stream().Context()

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendTo() log send")
	s.traffic.LogSend(ctx, relay.GetDistantAddress(), pkt)

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendTo() relay send")
	ack, err := relay.Send(ctx, pkt)
	if to == nil && err != nil {
		// The parent relay is unavailable which means the session will
		// eventually close.
		s.logger.Warn().Err(err).Msg("parent is closing")

		code := status.Code(xerrors.Unwrap(err))

		errs <- xerrors.Errorf("session %v is closing: %v", s.me, code)

		return
	}
	if err != nil {
		s.logger.Warn().Err(err).Msg("relay failed to send")

		// Try to send the packet through a different route.
		s.onFailure(p, relay.GetDistantAddress(), pkt, errs)

		return
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendTo() adding errors to channel")

	for _, err := range ack.Errors {
		// Note: it would be possible to use this ack feedback to further
		// improve the correction of the routes by retrying here too.
		errs <- xerrors.New(err)
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("sendTo() done adding errors to channel")
}

func (s *session) setupRelay(p parent, addr mino.Address) (Relay, error) {
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("setupRelay() locking")
	defer s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("setupRelay() unlocking")

	s.Lock()
	defer s.Unlock()

	relay, initiated := s.relays[addr]

	if initiated {
		return relay, nil
	}

	hs, err := p.table.PrepareHandshakeFor(addr).Serialize(s.context)
	if err != nil {
		return nil, xerrors.Errorf("failed to serialize handshake: %v", err)
	}

	s.logger.Trace().
		Stringer("from", s.me).
		Stringer("to", s.me).
		Str("goid", goid()).
		Msg("setupRelay() acquiring addr")

	// 1. Acquire a connection to the distant peer.
	conn, err := s.connMgr.Acquire(addr)
	if err != nil {
		return nil, xerrors.Errorf("failed to dial: %v", err)
	}

	md := s.md.Copy()
	md.Set(HandshakeKey, string(hs))

	ctx := metadata.NewOutgoingContext(p.relay.Stream().Context(), md)

	cl := ptypes.NewOverlayClient(conn)

	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("setupRelay() streaming")

	stream, err := cl.Stream(ctx, grpc.WaitForReady(false))
	if err != nil {
		s.connMgr.Release(addr)
		return nil, xerrors.Errorf("client: %v", err)
	}

	// 2. Wait for the header event to confirm the stream is registered in the
	// session at the other end.
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("setupRelay() asking for header")
	_, err = stream.Header()
	if err != nil {
		s.connMgr.Release(addr)
		return nil, xerrors.Errorf("failed to receive header: %v", err)
	}

	// 3. Create and run the relay to respond to incoming packets.
	s.logger.Trace().
		Stringer("from", s.me).
		Str("goid", goid()).
		Msg("setupRelay() new relay")
	newRelay := NewRelay(stream, addr, s.context, conn, s.md)

	s.relays[addr] = newRelay
	s.Add(1)

	go func() {
		defer func() {
			debugger.SetLabels(
				func() []string {
					return []string{
						"module", "mino/session",
						"operation", "relay",
						"addr", addr.String(),
						"status", "terminating",
					}
				},
			)

			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("setupRelay() go lock")

			s.Lock()
			delete(s.relays, addr)
			s.Unlock()

			s.logger.Trace().
				Stringer("from", s.me).
				Str("goid", goid()).
				Msg("setupRelay() go unlock")

			newRelay.Close()

			// Let the manager know it can close the connection if necessary.
			s.connMgr.Release(addr)

			s.Done()

			s.traffic.LogRelayClosed(addr)
			s.logger.Trace().
				Err(err).
				Stringer("gateway", addr).
				Msg("relay has closed")
		}()

		debugger.SetLabels(
			func() []string {
				return []string{
					"module", "mino/session",
					"operation", "relay",
					"addr", addr.String(),
					"status", "relaying",
				}
			},
		)

		s.logger.Trace().
			Stringer("from", s.me).
			Str("goid", goid()).
			Msg("setupRelay() receiving")

		for {
			_, err := stream.Recv()
			code := status.Code(err)
			if err == io.EOF || code != codes.Unknown {
				s.logger.Trace().
					Stringer("code", code).
					Stringer("to", addr).
					Msg("relay is closing")

				return
			}
			if err != nil {
				s.logger.
					Err(err).
					Stringer("to", addr).
					Msg("relay closed unexpectedly")

				// Relay has lost the connection, therefore we announce the
				// address as unreachable.
				p.table.OnFailure(addr)

				return
			}
		}
	}()

	s.traffic.LogRelay(addr)

	s.logger.Trace().Stringer("to", addr).Msg("relay opened")

	return newRelay, nil
}

func (s *session) onFailure(
	p parent, gateway mino.Address, pkt router.Packet, errs chan error,
) {
	err := p.table.OnFailure(gateway)
	if err != nil {
		errs <- xerrors.Errorf("no route to %v: %v", gateway, err)
		return
	}

	// Retry to send the packet after the announcement of a link failure. This
	// recursive call will eventually end by either a success, or a total
	// failure to send the packet.
	s.sendPacket(p, pkt, errs)
}

// PacketStream is a gRPC stream to send and receive protobuf packets.
type PacketStream interface {
	Context() context.Context
	Send(*ptypes.Packet) error
	Recv() (*ptypes.Packet, error)
}

// UnicastRelay is a relay to a distant peer that is using unicast to send
// packets so that it can learn about failures.
//
// - implements session.Relay
type unicastRelay struct {
	sync.Mutex
	md      metadata.MD
	gw      mino.Address
	stream  PacketStream
	conn    grpc.ClientConnInterface
	context serde.Context
}

// NewRelay returns a new relay that will send messages to the gateway through
// unicast requests.
func NewRelay(
	stream PacketStream, gw mino.Address,
	ctx serde.Context, conn grpc.ClientConnInterface, md metadata.MD,
) Relay {

	r := &unicastRelay{
		md:      md,
		gw:      gw,
		stream:  stream,
		context: ctx,
		conn:    conn,
	}

	return r
}

// GetDistantAddress implements session.Relay. It returns the address of the
// distant peer.
func (r *unicastRelay) GetDistantAddress() mino.Address {
	return r.gw
}

// Stream implements session.Relay. It returns the stream associated to the
// relay.
func (r *unicastRelay) Stream() PacketStream {
	return r.stream
}

// Send implements session.Relay. It sends the message to the distant peer.
func (r *unicastRelay) Send(ctx context.Context, p router.Packet) (
	*ptypes.Ack, error,
) {
	dela.Logger.Trace().
		Str("goid", goid()).
		Msg("unicastRelay.Send()")
	defer dela.Logger.Trace().
		Str("goid", goid()).
		Msg("unicastRelay.Send() done")

	data, err := p.Serialize(r.context)
	if err != nil {
		return nil, xerrors.Errorf("failed to serialize: %v", err)
	}

	client := ptypes.NewOverlayClient(r.conn)

	ctx = metadata.NewOutgoingContext(ctx, r.md)

	ack, err := client.Forward(ctx, &ptypes.Packet{Serialized: data})
	if err != nil {
		return nil, xerrors.Errorf("client: %w", err)
	}

	return ack, nil
}

// Close implements session.Relay. It closes the stream.
func (r *unicastRelay) Close() error {
	stream, ok := r.stream.(ptypes.Overlay_StreamClient)
	if ok {
		err := stream.CloseSend()
		if err != nil {
			return xerrors.Errorf("failed to close stream: %v", err)
		}
	}

	return nil
}

// StreamRelay is a relay to a distant peer that will send the packets through a
// stream, which means that it assumes the packet arrived if send is successful.
//
// - implements session.Relay
type streamRelay struct {
	gw      mino.Address
	stream  PacketStream
	context serde.Context
}

// NewStreamRelay creates a new relay that will send the packets through the
// stream.
func NewStreamRelay(
	gw mino.Address, stream PacketStream, ctx serde.Context,
) Relay {
	return &streamRelay{
		gw:      gw,
		stream:  stream,
		context: ctx,
	}
}

// GetDistantAddress implements session.Relay. It returns the address of the
// distant peer.
func (r *streamRelay) GetDistantAddress() mino.Address {
	return r.gw
}

// Stream implements session.Relay. It returns the stream associated with the
// relay.
func (r *streamRelay) Stream() PacketStream {
	return r.stream
}

// Send implements session.Relay. It sends the packet through the stream.
func (r *streamRelay) Send(ctx context.Context, p router.Packet) (
	*ptypes.Ack, error,
) {
	dela.Logger.Trace().
		Str("goid", goid()).
		Msg("streamRelay.Send()")
	defer dela.Logger.Trace().
		Str("goid", goid()).
		Msg("streamRelay.Send() done")

	data, err := p.Serialize(r.context)
	if err != nil {
		return nil, xerrors.Errorf("failed to serialize: %v", err)
	}

	err = r.stream.Send(&ptypes.Packet{Serialized: data})
	if err != nil {
		return nil, xerrors.Errorf("stream: %v", err)
	}

	return &ptypes.Ack{}, nil
}

// Close implements session.Relay. It does not do anything as it is not
// responsible for closing the stream.
func (r *streamRelay) Close() error {
	return nil
}
