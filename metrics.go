package main

type Metrics interface {
	Fire(result string)
	ResponseStatus(prefix string, status int)
}

type MetricsFactory interface {
	Create(eventName string) Metrics
}
