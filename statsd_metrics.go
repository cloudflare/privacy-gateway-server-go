package main

import (
	"fmt"
	"log/slog"
	"net"
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
		slog.Warn("Cannot send metrics to statsd", "error", err)
	}
}

func (s *StatsDMetrics) ResponseStatus(prefix string, status int) {
	s.Fire(fmt.Sprintf("%s_response_status_%d", prefix, status))
}

func createStatsDClient(host, port string, timeout int) (statsd.ClientInterface, error) {
	if host == "" || port == "" {
		return &statsd.NoOpClient{}, nil
	}

	return statsd.New(net.JoinHostPort(host, port), statsd.WithWriteTimeout(time.Duration(timeout)*time.Millisecond), statsd.WithoutTelemetry())
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
