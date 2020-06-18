package skipchain

import (
	fmt "fmt"
	"sync"

	"go.dedis.ch/dela/blockchain/skipchain/types"
	"golang.org/x/xerrors"
)

// Queries is an interface to provide high-level queries to store and read
// blocks.
type Queries interface {
	Write(block types.SkipBlock) error
	Contains(index uint64) bool
	Read(index int64) (types.SkipBlock, error)
	ReadLast() (types.SkipBlock, error)
}

// Database is an interface that provides the primitives to read and write
// blocks to a storage.
type Database interface {
	Queries

	// Atomic allows the execution of atomic operations. If the callback returns
	// any error, the transaction will be aborted.
	Atomic(func(ops Queries) error) error
}

// NoBlockError is an error returned when the block is not found. It can be used
// in comparison as it complies with the xerrors.Is requirement.
type NoBlockError struct {
	index int64
}

// NewNoBlockError returns a new instance of the error.
func NewNoBlockError(index int64) NoBlockError {
	return NoBlockError{index: index}
}

func (err NoBlockError) Error() string {
	return fmt.Sprintf("block at index %d not found", err.index)
}

// Is returns true when both errors are equal, otherwise it returns false.
func (err NoBlockError) Is(other error) bool {
	otherErr, ok := other.(NoBlockError)
	return ok && otherErr.index == err.index
}

// InMemoryDatabase is an implementation of the database interface that is
// an in-memory storage.
//
// - implements skipchain.Database
type InMemoryDatabase struct {
	sync.Mutex
	blocks []types.SkipBlock
}

// NewInMemoryDatabase creates a new in-memory storage for blocks.
func NewInMemoryDatabase() *InMemoryDatabase {
	return &InMemoryDatabase{
		blocks: make([]types.SkipBlock, 0),
	}
}

// Write implements skipchain.Database. It writes the block to the storage.
func (db *InMemoryDatabase) Write(block types.SkipBlock) error {
	db.Lock()
	defer db.Unlock()

	if uint64(len(db.blocks)) == block.Index {
		db.blocks = append(db.blocks, block)
	} else if block.Index < uint64(len(db.blocks)) {
		db.blocks[block.Index] = block
	} else {
		return xerrors.Errorf("missing intermediate blocks for index %d", block.Index)
	}

	return nil
}

// Contains implements skipchain.Database. It returns true if the block is
// stored in the database, otherwise false.
func (db *InMemoryDatabase) Contains(index uint64) bool {
	db.Lock()
	defer db.Unlock()

	return index < uint64(len(db.blocks))
}

// Read implements skipchain.Database. It returns the block at the given index
// if it exists, otherwise an error.
func (db *InMemoryDatabase) Read(index int64) (types.SkipBlock, error) {
	db.Lock()
	defer db.Unlock()

	if index < int64(len(db.blocks)) {
		return db.blocks[index], nil
	}

	return types.SkipBlock{}, NewNoBlockError(index)
}

// ReadLast implements skipchain.Database. It reads the last known block of the
// chain.
func (db *InMemoryDatabase) ReadLast() (types.SkipBlock, error) {
	db.Lock()
	defer db.Unlock()

	if len(db.blocks) == 0 {
		return types.SkipBlock{}, xerrors.New("database is empty")
	}

	return db.blocks[len(db.blocks)-1], nil
}

// Atomic implements skipchain.Database. It executes the transaction so that any
// error returned will revert any previous operations.
func (db *InMemoryDatabase) Atomic(tx func(Queries) error) error {
	db.Lock()
	snapshot := db.clone()
	db.Unlock()

	err := tx(snapshot)
	if err != nil {
		return xerrors.Errorf("couldn't execute transaction: %v", err)
	}

	db.Lock()
	db.blocks = snapshot.blocks
	db.Unlock()

	return nil
}

// clone returns a deep copy of the in-memory database.
func (db *InMemoryDatabase) clone() *InMemoryDatabase {
	blocks := make([]types.SkipBlock, len(db.blocks))
	copy(blocks, db.blocks)

	return &InMemoryDatabase{
		blocks: blocks,
	}
}
