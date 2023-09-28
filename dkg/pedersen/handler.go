package pedersen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/c4dt/dela"
	"github.com/c4dt/dela/cosi/threshold"
	"github.com/c4dt/dela/dkg/pedersen/types"
	"github.com/c4dt/dela/mino"
	"github.com/rs/zerolog"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	pedersen "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	vss "go.dedis.ch/kyber/v3/share/vss/pedersen"
	"golang.org/x/xerrors"
)

// the receiving time out, after which we check if the DKG setup is done or not.
// Allows to exit the loop.
const recvTimeout = time.Second * 4

// the channel size used to stored buffered deals and responses. This arbitrary
// value must be set according to the characteristic of the system: number of
// nodes, networking, memory, etc...
const chanSize = 200

// constant used in the logs
const newState = "new state"

func newCryChan[T any](bufSize int) cryChan[T] {
	llvl := zerolog.NoLevel
	if os.Getenv("CRY_LVL") == "warn" {
		llvl = zerolog.WarnLevel
	}

	return cryChan[T]{
		c: make(chan T, bufSize),
		log: dela.Logger.With().Str("role", "cry chan").Int("size", bufSize).
			Logger().Level(llvl),
	}
}

type cryChan[T any] struct {
	c   chan T
	log zerolog.Logger
}

func (c *cryChan[T]) push(e T) {
	start := time.Now()
	select {
	case c.c <- e:
	case <-time.After(time.Second * 1):
		// prints the first 16 bytes of the trace, which should contain at least
		// the goroutine id.
		trace := make([]byte, 16)
		runtime.Stack(trace, false)
		c.log.Warn().Str("obj", fmt.Sprintf("%+v", e)).
			Str("trace", string(trace)).Msg("channel blocking")
		c.c <- e
		c.log.Warn().Str("obj", fmt.Sprintf("%+v", e)).
			Str("elapsed", time.Since(start).String()).
			Str("trace", string(trace)).Msg("channel unblocked")
	}
}

func (c *cryChan[T]) pop(ctx context.Context) (t T, err error) {
	select {
	case el := <-c.c:
		return el, nil
	case <-ctx.Done():
		return t, ctx.Err()
	}
}

func (c *cryChan[T]) Len() int {
	return len(c.c)
}

// state is a struct contained in a handler that allows an actor to read the
// state of that handler. The actor should only use the getter functions to read
// the attributes.
type state struct {
	sync.Mutex
	distrKey     kyber.Point
	participants []mino.Address
}

func (s *state) Done() bool {
	s.Lock()
	defer s.Unlock()
	return s.distrKey != nil && s.participants != nil
}

func (s *state) GetDistKey() kyber.Point {
	s.Lock()
	defer s.Unlock()
	return s.distrKey
}

func (s *state) SetDistKey(key kyber.Point) {
	s.Lock()
	s.distrKey = key
	s.Unlock()
}

func (s *state) GetParticipants() []mino.Address {
	s.Lock()
	defer s.Unlock()
	return s.participants
}

func (s *state) SetParticipants(addrs []mino.Address) {
	s.Lock()
	s.participants = addrs
	s.Unlock()
}

// Handler represents the RPC executed on each node
//
// - implements mino.Handler
type Handler struct {
	mino.UnsupportedHandler
	sync.RWMutex
	dkg       *pedersen.DistKeyGenerator
	privKey   kyber.Scalar
	me        mino.Address
	privShare *share.PriShare
	startRes  *state
	log       zerolog.Logger
	running   bool
}

// NewHandler creates a new handler
func NewHandler(privKey kyber.Scalar, me mino.Address) *Handler {
	log := dela.Logger.With().Str("role", "DKG handler").Str("addr", me.String()).Logger()

	return &Handler{
		privKey:  privKey,
		me:       me,
		startRes: &state{},
		log:      log,
		running:  false,
	}
}

// Stream implements mino.Handler. It allows one to stream messages to the
// players.
func (h *Handler) Stream(out mino.Sender, in mino.Receiver) error {
	// Note: one should never assume any synchronous properties on the messages.
	// For example we can not expect to receive the start message from the
	// initiator of the DKG protocol first because some node could have received
	// this start message earlier than us, start their DKG work by sending
	// messages to the other nodes, and then we might get their messages before
	// the start message.

	// We make sure not additional request is accepted if a setup is in
	// progress.
	h.Lock()
	if h.running {
		h.Unlock()
		return xerrors.Errorf("DKG is running")
	}
	if !h.startRes.Done() {
		// This is the first setup
		h.running = true
	}
	h.Unlock()

	deals := newCryChan[types.Deal](chanSize)
	responses := newCryChan[types.Response](chanSize)

	globalCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
		from, msg, err := in.Recv(ctx)
		cancel()

		if errors.Is(err, context.DeadlineExceeded) {
			if h.startRes.Done() {
				return nil
			}

			continue
		}

		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return xerrors.Errorf("failed to receive: %v", err)
		}

		h.log.Info().Str("from", from.String()).Str("type", fmt.Sprintf("%T", msg)).
			Msg("message received")

		// We expect a Start message or a decrypt request at first, but we might
		// receive other messages in the meantime, like a Deal.
		switch msg := msg.(type) {

		case types.Start:
			err := h.start(globalCtx, msg, deals, responses, from, out)
			if err != nil {
				return xerrors.Errorf("failed to start: %v", err)
			}

		case types.Deal:
			deals.push(msg)

		case types.Response:
			responses.push(msg)
			h.log.Info().Int("total", responses.Len()).Msg("pushing a response")

		case types.DecryptRequest:
			dela.Logger.Trace().Msgf("%v received decrypt request from %v", h.me, from)

			return h.handleDecrypt(out, msg, from)

		default:
			return xerrors.Errorf("expected Start message, decrypt request or "+
				"Deal as first message, got: %T", msg)
		}
	}
}

func (h *Handler) handleDecrypt(out mino.Sender, msg types.DecryptRequest,
	from mino.Address) error {

	if !h.startRes.Done() {
		return xerrors.Errorf("you must first initialize DKG. Did you call setup() first?")
	}

	h.RLock()
	S := suite.Point().Mul(h.privShare.V, msg.K)
	h.RUnlock()

	partial := suite.Point().Sub(msg.C, S)

	h.RLock()
	decryptReply := types.NewDecryptReply(int64(h.privShare.I), partial)
	h.RUnlock()

	errs := out.Send(decryptReply, from)
	err := <-errs
	if err != nil {
		return xerrors.Errorf("got an error while sending the decrypt reply: %v", err)
	}

	return nil
}

// start is called when the node has received its start message. Note that we
// might have already received some deals from other nodes in the meantime. The
// function handles the DKG creation protocol.
func (h *Handler) start(ctx context.Context, start types.Start, deals cryChan[types.Deal],
	resps cryChan[types.Response], from mino.Address, out mino.Sender) error {

	if len(start.GetAddresses()) != len(start.GetPublicKeys()) {
		return xerrors.Errorf("there should be as many participants as "+
			"pubKey: %d != %d", len(start.GetAddresses()), len(start.GetPublicKeys()))
	}

	// create the DKG
	t := threshold.ByzantineThreshold(len(start.GetPublicKeys()))
	d, err := pedersen.NewDistKeyGenerator(suite, h.privKey, start.GetPublicKeys(), t)
	if err != nil {
		return xerrors.Errorf("failed to create new DKG: %v", err)
	}

	h.dkg = d

	h.startRes.SetParticipants(start.GetAddresses())

	// asynchronously start the procedure. This allows for receiving messages
	// in the main for loop in the meantime.
	go func() {
		err = h.doDKG(ctx, deals, resps, out, from)
		if err != nil {
			h.log.Err(err).Msg("something went wrong during DKG")
		}
	}()

	return nil
}

// doDKG calls the subsequent DKG steps
func (h *Handler) doDKG(ctx context.Context, deals cryChan[types.Deal],
	resps cryChan[types.Response], out mino.Sender, from mino.Address) error {

	defer func() {
		h.Lock()
		h.running = false
		h.Unlock()
	}()

	h.log.Info().Str("action", "deal").Msg(newState)
	err := h.deal(ctx, out)
	if err != nil {
		return xerrors.Errorf("failed to deal: %v", err)
	}

	h.log.Info().Str("action", "respond").Msg(newState)
	err = h.respond(ctx, deals, out)
	if err != nil {
		return xerrors.Errorf("failed to respond: %v", err)
	}

	h.log.Info().Str("action", "certify").Msg(newState)
	err = h.certify(ctx, resps, out)
	if err != nil {
		return xerrors.Errorf("failed to certify: %v", err)
	}

	h.log.Info().Str("action", "finalize").Msg(newState)
	err = h.finalize(ctx, from, out)
	if err != nil {
		return xerrors.Errorf("failed to finalize: %v", err)
	}

	h.log.Info().Str("action", "done").Msg(newState)

	return nil
}

func (h *Handler) deal(ctx context.Context, out mino.Sender) error {
	// Send my Deals to the other nodes. Note that we take an optimistic
	// approach and expect nodes to always accept messages. If not, the protocol
	// can hang forever.

	deals, err := h.dkg.Deals()
	if err != nil {
		return xerrors.Errorf("failed to compute the deals: %v", err)
	}

	for i, deal := range deals {
		dealMsg := types.NewDeal(
			deal.Index,
			deal.Signature,
			types.NewEncryptedDeal(
				deal.Deal.DHKey,
				deal.Deal.Signature,
				deal.Deal.Nonce,
				deal.Deal.Cipher,
			),
		)

		to := h.startRes.participants[i]

		h.log.Info().Str("to", to.String()).Msg("send deal")

		errs := out.Send(dealMsg, to)

		// this can be blocking if the recipient is not receiving message
		select {
		case err = <-errs:
			if err != nil {
				h.log.Err(err).Str("to", to.String()).Msg("failed to send deal")
			}
		case <-ctx.Done():
			return xerrors.Errorf("context done: %v", ctx.Err())
		}
	}

	return nil
}

func (h *Handler) respond(ctx context.Context, deals cryChan[types.Deal], out mino.Sender) error {
	numReceivedDeals := 0

	for numReceivedDeals < len(h.startRes.participants)-1 {
		deal, err := deals.pop(ctx)
		if err != nil {
			return xerrors.Errorf("context done: %v", err)
		}

		err = h.handleDeal(ctx, deal, out)
		if err != nil {
			return xerrors.Errorf("failed to handle received deal: %v", err)
		}

		numReceivedDeals++

		h.log.Info().Str("total", strconv.Itoa(numReceivedDeals)).Msg("deal received")
	}

	return nil
}

func (h *Handler) certify(ctx context.Context, resps cryChan[types.Response], out mino.Sender) error {

	responsesReceived := 0
	expected := (len(h.startRes.participants) - 1) * (len(h.startRes.participants) - 1)

	for responsesReceived < expected {
		msg, err := resps.pop(ctx)
		if err != nil {
			return xerrors.Errorf("context done: %v", err)
		}

		resp := pedersen.Response{
			Index: msg.GetIndex(),
			Response: &vss.Response{
				SessionID: msg.GetResponse().GetSessionID(),
				Index:     msg.GetResponse().GetIndex(),
				Status:    msg.GetResponse().GetStatus(),
				Signature: msg.GetResponse().GetSignature(),
			},
		}

		_, err = h.dkg.ProcessResponse(&resp)
		if err != nil {
			return xerrors.Errorf("failed to process response: %v", err)
		}

		responsesReceived++

		h.log.Info().Int("total", responsesReceived).Msg("response processed")
	}

	if !h.dkg.Certified() {
		return xerrors.New("node is not certified")
	}

	return nil
}

// finalize saves the result and announces it to the orchestrator.
func (h *Handler) finalize(ctx context.Context, from mino.Address, out mino.Sender) error {
	// Send back the public DKG key
	distKey, err := h.dkg.DistKeyShare()
	if err != nil {
		return xerrors.Errorf("failed to get distr key: %v", err)

	}

	// Update the state before sending the acknowledgement to the
	// orchestrator, so that it can process decrypt requests right away.
	h.startRes.SetDistKey(distKey.Public())

	h.Lock()
	h.privShare = distKey.PriShare()
	h.Unlock()

	done := types.NewStartDone(distKey.Public())

	select {
	case err = <-out.Send(done, from):
		if err != nil {
			return xerrors.Errorf("got an error while sending pub key: %v", err)
		}
	case <-ctx.Done():
		return xerrors.Errorf("context done: %v", ctx.Err())
	}

	return nil
}

// handleDeal process the Deal and send the responses to the other nodes.
func (h *Handler) handleDeal(ctx context.Context, msg types.Deal, out mino.Sender) error {

	deal := &pedersen.Deal{
		Index: msg.GetIndex(),
		Deal: &vss.EncryptedDeal{
			DHKey:     msg.GetEncryptedDeal().GetDHKey(),
			Signature: msg.GetEncryptedDeal().GetSignature(),
			Nonce:     msg.GetEncryptedDeal().GetNonce(),
			Cipher:    msg.GetEncryptedDeal().GetCipher(),
		},
		Signature: msg.GetSignature(),
	}

	response, err := h.dkg.ProcessDeal(deal)
	if err != nil {
		return xerrors.Errorf("failed to process deal: %v", err)
	}

	resp := types.NewResponse(
		response.Index,
		types.NewDealerResponse(
			response.Response.Index,
			response.Response.Status,
			response.Response.SessionID,
			response.Response.Signature,
		),
	)

	for _, addr := range h.startRes.participants {
		if addr.Equal(h.me) {
			continue
		}

		h.log.Info().Str("to", addr.String()).Str("dealer", strconv.Itoa(int(response.Index))).Msg("sending response")

		errs := out.Send(resp, addr)

		select {
		case err = <-errs:
			if err != nil {
				return xerrors.Errorf("failed to send response to '%s': %v", addr, err)
			}
		case <-ctx.Done():
			return xerrors.Errorf("context done: %v", ctx.Err())
		}
	}

	return nil
}
