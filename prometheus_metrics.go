// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusConfig struct {
	Host       string
	Port       string
	ScrapePath string
	MetricName string
}

type PrometheusMetrics struct {
	startedAt time.Time
	histogram prometheus.ObserverVec
}

func (p *PrometheusMetrics) Fire(result string) {
	observer := p.histogram.With(prometheus.Labels{
		"method": "unknown",
		"status": "unknown",
		"result": result,
	})
	p.observe(observer)
}

func (p *PrometheusMetrics) ResponseStatus(method string, status int) {
	observer := p.histogram.With(prometheus.Labels{
		"method": method,
		"status": fmt.Sprint(status),
		"result": "unknown",
	})
	p.observe(observer)
}

func (p *PrometheusMetrics) observe(observer prometheus.Observer) {
	elapsed := time.Now().Sub(p.startedAt)
	observer.Observe(float64(elapsed.Milliseconds()))
}

type PrometheusMetricsFactory struct {
	metricName string
}

func NewPrometheusMetricsFactory(config PrometheusConfig) (MetricsFactory, error) {
	serveMux := http.NewServeMux()
	serveMux.Handle(config.ScrapePath, promhttp.Handler())
	server := http.Server{
		Addr:    net.JoinHostPort(config.Host, config.Port),
		Handler: serveMux,
	}

	go func() {
		slog.Debug("Listening for Prometheus scrapes", "host", config.Host, "port", config.Port)
		slog.Error("Error serving Prometheus scrapes", "error", server.ListenAndServe())
		os.Exit(1)
	}()

	return &PrometheusMetricsFactory{metricName: config.MetricName}, nil
}

func (p PrometheusMetricsFactory) Create(eventName string) Metrics {
	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: p.metricName,
	}, []string{"eventName", "status", "method", "result"})

	if err := prometheus.Register(histogram); err != nil {
		are := &prometheus.AlreadyRegisteredError{}
		if errors.As(err, are) {
			// Use previously registered metric collector
			histogram = are.ExistingCollector.(*prometheus.HistogramVec)
		} else {
			// There's no other reason prometheus.Register should fail and the interface won't let
			// us return an error.
			panic(err)
		}
	}

	return &PrometheusMetrics{
		startedAt: time.Now(),
		histogram: histogram.MustCurryWith(prometheus.Labels{"eventName": eventName}),
	}
}
