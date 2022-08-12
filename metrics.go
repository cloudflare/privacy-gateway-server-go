package main

type Metrics interface {
	Fire(result string)
}

type MetricsFactory func(requestName string) Metrics
