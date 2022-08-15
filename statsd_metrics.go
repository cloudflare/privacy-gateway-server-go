package main

import (
	"fmt"
	"log"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
)

type StatsDMetrics struct {
	serviceName string
	metricsName string
	eventName   string
	startedAt   time.Time
	client      statsd.ClientInterface
}

func (s *StatsDMetrics) Fire(result string) {
	tags := []string{fmt.Sprintf("event_name:%s", s.eventName), fmt.Sprintf("result:%s", result), fmt.Sprintf("service:%s", s.serviceName)}

	err := s.client.TimeInMilliseconds(s.metricsName, float64(time.Since(s.startedAt).Milliseconds()), tags, 1)
	if err != nil {
		log.Printf("Cannot send metrics to statsd: %s", err)
	}
}

func createStatsDClient(host, port string, timeout int) (statsd.ClientInterface, error) {
	if host == "" || port == "" {
		return &statsd.NoOpClient{}, nil
	}

	return statsd.New(host+":"+port, statsd.WithWriteTimeout(time.Duration(timeout)*time.Millisecond), statsd.WithoutTelemetry())
}

type StatsDMetricsFactory struct {
	serviceName string
	metricsName string
	client      statsd.ClientInterface
}

func (f StatsDMetricsFactory) Create(eventName string) Metrics {
	return &StatsDMetrics{
		serviceName: f.serviceName,
		metricsName: f.metricsName,
		eventName:   eventName,
		startedAt:   time.Now(),
		client:      f.client,
	}
}
