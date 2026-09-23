package httpapi

import "net/http"

func (s *Server) feishuEvents(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.FeishuEvents(queryInt(r, "limit", 50))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) feishuStatus(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	status, err := s.store.FeishuSyncStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, http.StatusOK, status)
}
