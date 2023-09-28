package integration

import (
	"github.com/c4dt/dela/core/access"
	"github.com/c4dt/dela/core/ordering"
	"github.com/c4dt/dela/core/txn"
	"github.com/c4dt/dela/mino"
)

// dela defines the common interface for a Dela node.
type dela interface {
	Setup(...dela)
	GetMino() mino.Mino
	GetOrdering() ordering.Service
	GetTxManager() txn.Manager
	GetAccessService() access.Service
}
