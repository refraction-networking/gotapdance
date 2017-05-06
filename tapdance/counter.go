package tapdance

import "sync"

type CounterUint64 struct {
	sync.Mutex
	value uint64
}

func (c *CounterUint64) Inc() uint64 {
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

func (c *CounterUint64) GetAndInc() uint64 {
	c.Lock()
	defer c.Unlock()
	if c.value == ^uint64(0) {
		// if max
		c.value = 0
	}
	retVal := c.value
	c.value++
	return retVal
}

func (c *CounterUint64) Dec() uint64 {
	c.Lock()
	defer c.Unlock()
	if c.value == 0 {
		c.value = ^uint64(0)
	} else {
		c.value--
	}
	return c.value
}

func (c *CounterUint64) Get() (value uint64) {
	c.Lock()
	defer c.Unlock()
	value = c.value
	return
}
