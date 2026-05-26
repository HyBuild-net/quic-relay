package proxy

import (
	"net"
	"quic-relay/internal/handler"
	"runtime"
	"sync"
	"sync/atomic"
)

// WorkItem represents a UDP packet to be processed by a worker.
type WorkItem struct {
	ClientAddr *net.UDPAddr
	Packet     []byte
	Buffer     *[]byte // Reference for returning to pool
}

// WorkerPool manages a sharded pool of packet processing workers.
// Each worker has its own queue to eliminate channel contention.
// Packets from the same client always go to the same worker (affinity via hash).
type WorkerPool struct {
	queues        []chan WorkItem
	wg            sync.WaitGroup
	handler       func(*net.UDPAddr, []byte)
	workers       int
	queuePerShard int
	dropped       []uint64 // Per-shard drop counters (atomic)
}

// NewWorkerPool creates a sharded worker pool.
// workers: number of workers/shards (0 = NumCPU * 2)
// queueSize: total queue capacity across all shards (0 = 1024)
func NewWorkerPool(workers, queueSize int, handler func(*net.UDPAddr, []byte)) *WorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	if queueSize <= 0 {
		queueSize = 1024
	}

	queuePerShard := queueSize / workers
	if queuePerShard < 100 {
		queuePerShard = 100
	}

	p := &WorkerPool{
		queues:        make([]chan WorkItem, workers),
		handler:       handler,
		workers:       workers,
		queuePerShard: queuePerShard,
		dropped:       make([]uint64, workers),
	}

	for i := 0; i < workers; i++ {
		p.queues[i] = make(chan WorkItem, queuePerShard)
	}

	return p
}

// Start launches all worker goroutines.
func (p *WorkerPool) Start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

// Stop gracefully shuts down the pool and waits for workers to finish.
func (p *WorkerPool) Stop() {
	for i := 0; i < p.workers; i++ {
		close(p.queues[i])
	}
	p.wg.Wait()
}

// Submit adds a packet to the appropriate shard's queue.
// Uses client address hash for affinity (same client -> same worker).
// Returns false if queue is full (backpressure).
func (p *WorkerPool) Submit(item WorkItem) bool {
	idx := hashAddr(item.ClientAddr) % uint32(p.workers)
	select {
	case p.queues[idx] <- item:
		return true
	default:
		atomic.AddUint64(&p.dropped[idx], 1)
		if item.Buffer != nil {
			handler.PutBuffer(item.Buffer)
		}
		return false
	}
}

// Dropped returns total dropped packets across all shards.
func (p *WorkerPool) Dropped() uint64 {
	var total uint64
	for i := 0; i < p.workers; i++ {
		total += atomic.LoadUint64(&p.dropped[i])
	}
	return total
}

// QueueSize returns total pending items across all shards.
func (p *WorkerPool) QueueSize() int {
	var total int
	for i := 0; i < p.workers; i++ {
		total += len(p.queues[i])
	}
	return total
}

func (p *WorkerPool) worker(id int) {
	defer p.wg.Done()
	for item := range p.queues[id] {
		p.handler(item.ClientAddr, item.Packet)
		if item.Buffer != nil {
			handler.PutBuffer(item.Buffer)
		}
	}
}

// hashAddr computes FNV-1a hash of UDPAddr without string allocation.
func hashAddr(addr *net.UDPAddr) uint32 {
	h := uint32(2166136261)
	for _, b := range addr.IP {
		h ^= uint32(b)
		h *= 16777619
	}
	h ^= uint32(addr.Port)
	h *= 16777619
	h ^= uint32(addr.Port >> 8)
	h *= 16777619
	return h
}
