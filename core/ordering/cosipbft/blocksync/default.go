package blocksync

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"go.dedis.ch/dela"
	"go.dedis.ch/dela/core/ordering/cosipbft/blockstore"
	"go.dedis.ch/dela/core/ordering/cosipbft/blocksync/types"
	"go.dedis.ch/dela/core/ordering/cosipbft/pbft"
	cosipbft "go.dedis.ch/dela/core/ordering/cosipbft/types"
	"go.dedis.ch/dela/mino"
	"golang.org/x/xerrors"
)

// DefaultSync is a block synchronizer that allow soft and hard synchronization
// of the participants. A soft threshold means that a given number of
// participants have updated the latest index, whereas a hard one means that
// they have stored all the blocks up to the latest index.
//
// - implements blocksync.Synchronizer
type defaultSync struct {
	logger zerolog.Logger
	rpc    mino.RPC
	pbftsm pbft.StateMachine
	blocks blockstore.BlockStore
	latest *uint64
}

// SyncParam is the parameter object to create a new synchronizer.
type SyncParam struct {
	Mino        mino.Mino
	PBFT        pbft.StateMachine
	Blocks      blockstore.BlockStore
	LinkFactory cosipbft.BlockLinkFactory
}

// NewSynchronizer creates a new block synchronizer.
func NewSynchronizer(param SyncParam) (Synchronizer, error) {
	latest := param.Blocks.Len()

	logger := dela.Logger.With().Str("addr", param.Mino.GetAddress().String()).Logger()

	h := &handler{
		logger: logger,
		latest: &latest,
		blocks: param.Blocks,
		pbftsm: param.PBFT,
	}

	rpc, err := param.Mino.MakeRPC("blocksync", h, types.NewMessageFactory(param.LinkFactory))
	if err != nil {
		return nil, xerrors.Errorf("rpc creation failed: %v", err)
	}

	s := defaultSync{
		logger: logger,
		rpc:    rpc,
		pbftsm: param.PBFT,
		blocks: param.Blocks,
		latest: &latest,
	}

	return s, nil
}

// GetLatest implements blocksync.Synchronizer. It returns the latest index
// known by the instance.
func (s defaultSync) GetLatest() uint64 {
	return atomic.LoadUint64(s.latest)
}

// Sync implements blocksync.Synchronizer. it starts a routine to first
// soft-sync the participants and then send the blocks when necessary.
func (s defaultSync) Sync(ctx context.Context, players mino.Players) <-chan Event {
	ch := make(chan Event, 1)

	go func() {
		err := s.routine(ctx, players, ch)
		if err != nil {
			s.logger.Warn().Err(err).Msg("synchronization failed")
		}

		close(ch)
	}()

	return ch
}

func (s defaultSync) routine(ctx context.Context, players mino.Players, ch chan Event) error {
	sender, rcvr, err := s.rpc.Stream(ctx, players)
	if err != nil {
		return xerrors.Errorf("stream failed: %v", err)
	}

	// 1. Send the announcement message to everyone so that they can learn about
	// the latest block.
	latest := s.blocks.Len()

	errs := sender.Send(types.NewSyncMessage(latest), iter2arr(players.AddressIterator())...)
	for err := range errs {
		if err != nil {
			return xerrors.Errorf("announcement failed: %v", err)
		}
	}

	// 2. Wait for the hard synchronization to end. It can be interrupted with
	// the context.
	soft := map[mino.Address]struct{}{}
	hard := map[mino.Address]struct{}{}
	hardErrs := []error{}

	for len(hard) < players.Len() {
		from, msg, err := rcvr.Recv(ctx)
		if err != nil {
			return xerrors.Errorf("receiver failed: %v", err)
		}

		switch in := msg.(type) {
		case types.SyncRequest:
			_, found := soft[from]
			if found {
				s.logger.Warn().Msg("found duplicate request")
				continue
			}

			soft[from] = struct{}{}

			sendToChannel(ch, soft, hard, hardErrs)

			err := s.syncNode(in.GetFrom(), sender, from)
			if err != nil {
				hard[from] = struct{}{}
				hardErrs = append(hardErrs, err)

				sendToChannel(ch, soft, hard, hardErrs)
			}
		case types.SyncAck:
			soft[from] = struct{}{}
			hard[from] = struct{}{}

			sendToChannel(ch, soft, hard, hardErrs)
		}
	}

	return nil
}

func (s defaultSync) syncNode(from uint64, sender mino.Sender, to mino.Address) error {
	for i := from; i < s.blocks.Len(); i++ {
		s.logger.Debug().Uint64("index", i).Str("to", to.String()).Msg("send block")

		link, err := s.blocks.GetByIndex(i)
		if err != nil {
			return xerrors.Errorf("couldn't get block: %v", err)
		}

		err = <-sender.Send(types.NewSyncReply(link), to)
		if err != nil {
			return xerrors.Errorf("failed to send block: %v", err)
		}
	}

	return nil
}

type handler struct {
	sync.Mutex
	mino.UnsupportedHandler

	latest *uint64
	logger zerolog.Logger
	blocks blockstore.BlockStore
	pbftsm pbft.StateMachine
}

func (h *handler) Stream(out mino.Sender, in mino.Receiver) error {
	ctx := context.Background()

	m, orch, err := h.waitAnnounce(ctx, in)
	if err != nil {
		return xerrors.Errorf("no announcement: %v", err)
	}

	h.logger.Debug().
		Uint64("index", m.GetLatestIndex()).
		Msg("received synchronization message")

	if m.GetLatestIndex() <= h.blocks.Len() {
		// The block storage has already all the block known so far so we can
		// send the hard-sync acknowledgement.
		return h.ack(out, orch)
	}

	// At this point, the synchronization can only happen on one thread, so it
	// waits for the lock to be free, which means that in the meantime some
	// blocks might have been stored but the request is sent with the most
	// up-to-date block index, so it won't catch up twice the same block.
	h.Lock()
	defer h.Unlock()

	// Update the latest index through atomic operations as it can be read
	// asynchronously from the getter.
	if m.GetLatestIndex() > atomic.LoadUint64(h.latest) {
		atomic.StoreUint64(h.latest, m.GetLatestIndex())
	}

	err = <-out.Send(types.NewSyncRequest(h.blocks.Len()), orch)
	if err != nil {
		return xerrors.Errorf("sending request failed: %v", err)
	}

	for h.blocks.Len() < m.GetLatestIndex() {
		_, msg, err := in.Recv(ctx)
		if err != nil {
			return xerrors.Errorf("receiver failed: %v", err)
		}

		reply, ok := msg.(types.SyncReply)
		if ok {
			h.logger.Debug().
				Uint64("index", reply.GetLink().GetTo().GetIndex()).
				Msg("catch up block")

			err = h.pbftsm.CatchUp(reply.GetLink())
			if err != nil {
				return xerrors.Errorf("pbft catch up failed: %v", err)
			}
		}
	}

	return h.ack(out, orch)
}

func (h *handler) waitAnnounce(ctx context.Context,
	in mino.Receiver) (*types.SyncMessage, mino.Address, error) {

	for {
		orch, msg, err := in.Recv(ctx)
		if err != nil {
			return nil, nil, xerrors.Errorf("receiver failed: %v", err)
		}

		m, ok := msg.(types.SyncMessage)
		if ok {
			return &m, orch, nil
		}

		// TODO: get a proof from the genesis to verify that the latest index
		// exists. It should be at least equal to the current value as a leader
		// won't send a previous index.
	}
}

func (h *handler) ack(out mino.Sender, orch mino.Address) error {
	// Send the acknowledgement to the orchestrator that the blocks have been
	// caught up.
	err := <-out.Send(types.NewSyncAck(), orch)
	if err != nil {
		return xerrors.Errorf("sending ack failed: %v", err)
	}

	return nil
}

func sendToChannel(ch chan Event, soft, hard map[mino.Address]struct{}, errs []error) {
	empty := false
	for !empty {
		select {
		case <-ch:
			// A new event is always an update of the previous ones, therefore
			// the channel is drained to keep only one message in the buffer.
		default:
			empty = true
		}
	}

	ch <- Event{
		Soft:   len(soft),
		Hard:   len(hard),
		Errors: errs,
	}
}

func iter2arr(iter mino.AddressIterator) []mino.Address {
	addrs := []mino.Address{}
	for iter.HasNext() {
		addrs = append(addrs, iter.GetNext())
	}

	return addrs
}