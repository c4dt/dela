package pow

import "github.com/c4dt/dela/core/ordering"

type observer struct {
	events chan ordering.Event
}

func (o observer) NotifyCallback(event interface{}) {
	o.events <- event.(ordering.Event)
}
