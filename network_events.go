package main

import (
	"sync"
)

// Типы событий сети
const (
	EventPeerDiscovered  = "peer_discovered"
	EventPeerLost        = "peer_lost"
	EventScanStarted     = "scan_started"
	EventScanFinished    = "scan_finished"
	EventError           = "error"
	EventMessageReceived = "message_received"
)

// NetworkEvent представляет событие в сети
type NetworkEvent struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// NetworkError представляет ошибку в сети
type NetworkError struct {
	Message string `json:"message"`
	Err     error  `json:"error"`
}

// EventBus для передачи событий
var eventBus = NewEventBus()

// GetEventBus возвращает экземпляр шины событий
func GetEventBus() *EventBus {
	return eventBus
}

// EventBus реализует простую шину событий
type EventBus struct {
	subscribers []func(NetworkEvent)
	mu          sync.RWMutex
}

// NewEventBus создает новую шину событий
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make([]func(NetworkEvent), 0),
	}
}

// Subscribe подписывает функцию на события
func (eb *EventBus) Subscribe(fn func(NetworkEvent)) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.subscribers = append(eb.subscribers, fn)
}

// Publish публикует событие всем подписчикам
func (eb *EventBus) Publish(event NetworkEvent) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for _, subscriber := range eb.subscribers {
		go subscriber(event)
	}
}
