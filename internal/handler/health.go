package handler

import (
	"encoding/json"
	"net/http"
)

// HealthResponse represents the health check response
type HealthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version"`
	Services map[string]string `json:"services"`
}

// Health returns the health status of the service
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	services := make(map[string]string)

	// Check PostgreSQL
	if err := h.db.HealthCheck(ctx); err != nil {
		services["postgres"] = "unhealthy"
	} else {
		services["postgres"] = "healthy"
	}

	// Check Redis
	if err := h.rdb.HealthCheck(ctx); err != nil {
		services["redis"] = "unhealthy"
	} else {
		services["redis"] = "healthy"
	}

	// Determine overall status
	status := "healthy"
	for _, s := range services {
		if s == "unhealthy" {
			status = "degraded"
			break
		}
	}

	resp := HealthResponse{
		Status:   status,
		Version:  "0.1.0",
		Services: services,
	}

	w.Header().Set("Content-Type", "application/json")
	if status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

// Ready returns whether the service is ready to accept requests
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check all dependencies
	if err := h.db.HealthCheck(ctx); err != nil {
		http.Error(w, "database not ready", http.StatusServiceUnavailable)
		return
	}

	if err := h.rdb.HealthCheck(ctx); err != nil {
		http.Error(w, "redis not ready", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
