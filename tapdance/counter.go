package tapdance

import "sync"

type counter_uint64 struct {
	sync.Mutex
	value uint64
}

func (c *counter_uint64) inc() (uint64) {
	c.Lock()
	if c.value == ^uint64(0) {
		// if max
		c.value = 0
	} else {
		c.value++
	}
	c.Unlock()
	return c.value
}

func (c *counter_uint64) dec() (uint64) {
	c.Lock()
	if c.value == 0 {
		c.value = ^uint64(0)
	} else {
		c.value--
	}
	c.Unlock()
	return c.value
}

func (c *counter_uint64) get() (value uint64) {
	c.Lock()
	value = c.value
	c.Unlock()
	return
}

