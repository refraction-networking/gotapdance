package tapdance

import "sync"

type counter_uint64 struct {
	sync.Mutex
	value uint64
}

func (c *counter_uint64) inc() (uint64) {
	c.Lock()
	defer c.Unlock()
	if c.value == ^uint64(0) {
		// if max
		c.value = 0
	} else {
		c.value++
	}
	return c.value
}

func (c *counter_uint64) dec() (uint64) {
	c.Lock()
	defer c.Unlock()
	if c.value == 0 {
		c.value = ^uint64(0)
	} else {
		c.value--
	}
	return c.value
}

func (c *counter_uint64) get() (value uint64) {
	c.Lock()
	defer c.Unlock()
	value = c.value
	return
}

