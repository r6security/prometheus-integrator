/*
 * Copyright (C) 2024 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	amtdv1beta1client "github.com/r6security/prometheus-integrator/clients"
	seceventclient "github.com/r6security/prometheus-integrator/clients/securityevent"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// DefaultPort is the default port to use if one is not specified by the SERVER_PORT environment variable
const DefaultPort = "33337"
const MAX_BODY_SIZE = 1048576

func getServerPort() string {
	port := os.Getenv("SERVER_PORT")
	if port != "" {
		return port
	}

	return DefaultPort
}

type PrometheusBackend struct {
	client *seceventclient.SecurityEventInterface
	ctx    context.Context
}

type PrometheusResponse struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`        // key identifying the group of alerts (e.g. to deduplicate)
	TruncatedAlerts   int               `json:"truncatedAlerts"` // how many alerts have been truncated due to "max_alerts"
	Status            string            `json:"status"`          // "resolved" or "firing"
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"` // backlink to the Alertmanager
	Alerts            []Alert           `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status"` // "resolved" or "firing"
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`     // RFC3339 format
	EndsAt       time.Time         `json:"endsAt"`       // RFC3339 format
	GeneratorURL string            `json:"generatorURL"` // URL of the entity that generated the alert
	Fingerprint  string            `json:"fingerprint"`  // Unique fingerprint of the alert
}

// Use the webhook feature in prometheus to get prometheus trigger alerts.
// The Alertmanager will send HTTP POST requests in the following JSON format to the configured endpoint:
/*
	{
	"version": "4",
	"groupKey": <string>,              // key identifying the group of alerts (e.g. to deduplicate)
	"truncatedAlerts": <int>,          // how many alerts have been truncated due to "max_alerts"
	"status": "<resolved|firing>",
	"receiver": <string>,
	"groupLabels": <object>,
	"commonLabels": <object>,
	"commonAnnotations": <object>,
	"externalURL": <string>,           // backlink to the Alertmanager.
	"alerts": [
		{
		"status": "<resolved|firing>",
		"labels": <object>,
		"annotations": <object>,
		"startsAt": "<rfc3339>",
		"endsAt": "<rfc3339>",
		"generatorURL": <string>,      // identifies the entity that caused the alert
		"fingerprint": <string>        // fingerprint to identify the alert
		},
		...
	]
	}
*/
func (pb PrometheusBackend) PrometheusHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, MAX_BODY_SIZE)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Cannot read body %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"Cannot read request body\"}"))
		return
	}

	var response PrometheusResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("Cannot unmarshall %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"Cannot parse request body\"}"))
		return
	}

	for _, alert := range response.Alerts {
		name := fmt.Sprintf("prometheus-%s-%d", alert.Labels["pod"], alert.StartsAt.Unix())
		log.Printf("Creating secevent with name %s", name)
		c := *pb.client
		_, error := c.Create(pb.ctx, &amtdapi.SecurityEvent{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
				Name:        name,
				Namespace:   alert.Labels["namespace"],
			},
			Spec: amtdapi.SecurityEventSpec{
				Targets:     []string{fmt.Sprintf("%s/%s", alert.Labels["namespace"], alert.Labels["pod"])},
				Description: alert.Fingerprint,
				Rule: amtdapi.Rule{
					Type:        alert.Labels["rule"],
					ThreatLevel: alert.Labels["priority"],
					Source:      "PrometheusIntegrator",
				},
			},
		})

		if error != nil {
			log.Printf("Error: %v", error)
		} else {
			log.Printf("SecurityEvent was successfully created")
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"OK\"}"))
}

func main() {
	log.Print("Loading configuration")
	cfg := ctrl.GetConfigOrDie()
	client, error := amtdv1beta1client.NewClient(cfg)
	if error != nil {
		log.Panic(error)
	}
	secEventClient := client.SecurityEvents()
	prometheusBackend := PrometheusBackend{
		client: &secEventClient,
		ctx:    context.Background(),
	}
	port := getServerPort()
	log.Println("Starting server, listening on port " + port)

	http.HandleFunc("/", prometheusBackend.PrometheusHandler)
	http.ListenAndServe(":"+port, nil)
}
