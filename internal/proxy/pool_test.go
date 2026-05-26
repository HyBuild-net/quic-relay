package proxy

import (
	"net"
	"quic-relay/internal/handler"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_Submit(t *testing.T) {
	var processed atomic.Int32

	pool := NewWorkerPool(2, 100, func(addr *net.UDPAddr, packet []byte) {
		processed.Add(1)
	})
	pool.Start()
	defer pool.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	for i := 0; i < 10; i++ {
		if !pool.Submit(WorkItem{ClientAddr: addr, Packet: []byte{0x01}}) {
			t.Error("Submit should succeed")
		}
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	if processed.Load() != 10 {
		t.Errorf("expected 10 processed, got %d", processed.Load())
	}
}

func TestWorkerPool_Backpressure(t *testing.T) {
	// Create pool with tiny queue (min queuePerShard is 100, so we need more items)
	pool := NewWorkerPool(1, 100, func(addr *net.UDPAddr, packet []byte) {
		// Simulate slow processing
		time.Sleep(10 * time.Millisecond)
	})
	pool.Start()
	defer pool.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	// Fill the queue - need more than 100 items to trigger backpressure
	dropped := 0
	for i := 0; i < 200; i++ {
		if !pool.Submit(WorkItem{ClientAddr: addr, Packet: []byte{0x01}}) {
			dropped++
		}
	}

	// Should have dropped some packets due to backpressure
	if dropped == 0 {
		t.Error("expected some dropped packets due to backpressure")
	}

	if pool.Dropped() == 0 {
		t.Error("Dropped() should report dropped packets")
	}
}

func TestWorkerPool_Stop(t *testing.T) {
	var processed atomic.Int32

	pool := NewWorkerPool(4, 100, func(addr *net.UDPAddr, packet []byte) {
		processed.Add(1)
	})
	pool.Start()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	// Submit some work
	for i := 0; i < 50; i++ {
		pool.Submit(WorkItem{ClientAddr: addr, Packet: []byte{0x01}})
	}

	// Stop should wait for all work to complete
	pool.Stop()

	// All submitted work should be processed
	if processed.Load() != 50 {
		t.Errorf("expected 50 processed after Stop, got %d", processed.Load())
	}
}

func TestWorkerPool_QueueSize(t *testing.T) {
	pool := NewWorkerPool(1, 100, func(addr *net.UDPAddr, packet []byte) {
		time.Sleep(10 * time.Millisecond)
	})
	pool.Start()
	defer pool.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	// Submit some work
	for i := 0; i < 10; i++ {
		pool.Submit(WorkItem{ClientAddr: addr, Packet: []byte{0x01}})
	}

	queueSize := pool.QueueSize()
	if queueSize < 0 || queueSize > 10 {
		t.Errorf("unexpected queue size: %d", queueSize)
	}
}

func TestWorkerPool_BufferReturn(t *testing.T) {
	var bufferReturned atomic.Bool

	pool := NewWorkerPool(1, 10, func(addr *net.UDPAddr, packet []byte) {
		// Do nothing
	})
	pool.Start()
	defer pool.Stop()

	// Create a tracked buffer
	buf := handler.GetBuffer()
	originalBuf := buf

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	pool.Submit(WorkItem{
		ClientAddr: addr,
		Packet:     (*buf)[:10],
		Buffer:     buf,
	})

	// Wait for processing
	time.Sleep(50 * time.Millisecond)

	// Get a buffer from pool - if our buffer was returned, we might get it back
	newBuf := handler.GetBuffer()
	if newBuf == originalBuf {
		bufferReturned.Store(true)
	}
	handler.PutBuffer(newBuf)

	// This test mainly ensures no panic occurs
}

func TestNewWorkerPool_Defaults(t *testing.T) {
	pool := NewWorkerPool(0, 0, func(addr *net.UDPAddr, packet []byte) {})

	if pool.workers <= 0 {
		t.Error("workers should be set to default when 0")
	}
	if pool.queuePerShard <= 0 {
		t.Error("queuePerShard should be set to default when 0")
	}
}

func TestNewWorkerPool_DefaultQueueSizeIsBounded(t *testing.T) {
	pool := NewWorkerPool(4, 0, func(addr *net.UDPAddr, packet []byte) {})

	if pool.queuePerShard != 256 {
		t.Fatalf("expected queuePerShard=256, got %d", pool.queuePerShard)
	}
}
