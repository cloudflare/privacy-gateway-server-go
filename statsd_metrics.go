package main

import (
	"fmt"
	"log"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
)

type StatsDMetrics struct {
	metricsName string
	requestName string
	startedAt   time.Time
	client      statsd.ClientInterface
}

func (s *StatsDMetrics) Fire(result string) {
	tags := []string{fmt.Sprintf("request_name:%s", s.requestName), fmt.Sprintf("result:%s", result)}

	err := s.client.TimeInMilliseconds(s.metricsName, float64(time.Since(s.startedAt).Milliseconds()), tags, 1)

	if err != nil {
		log.Printf("Cannot send metrics to statsd: %s", err)
	}
}

func CreateStatsDMetricsFactory(metricsName string, client statsd.ClientInterface) MetricsFactory {
	return func(requestName string) Metrics {
		return &StatsDMetrics{
			metricsName: metricsName,
			requestName: requestName,
			startedAt:   time.Now(),
			client:      client,
		}
	}
}
