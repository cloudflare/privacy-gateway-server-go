package main

type Metrics interface {
	Fire(result string)
}

type MetricsFactory interface {
	Create(eventName string) Metrics
}
