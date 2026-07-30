package web

import (
	"encoding/json"
	"net/http"

	"github.com/thomasteoh/boardchestrator/internal/action"
)

// ActionHandler provides an HTTP handler for action dispatch.
// It reads the action name from the URL path and the input from the request body,
// resolves the actor from the session, and calls disp.Dispatch.
type ActionHandler struct {
	disp *action.Dispatcher
}

func NewActionHandler(disp *action.Dispatcher) *ActionHandler {
	return &ActionHandler{disp: disp}
}

// HandleAction dispatches an action from an HTTP POST request.
// URL: POST /api/action/{name}
// Body: JSON payload
// Response: JSON result
func (h *ActionHandler) HandleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Path[len("/api/action/"):]

	actor, err := actorFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var input json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	result, err := h.disp.Dispatch(r.Context(), actor, name, input, action.Opts{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// actorFromRequest extracts the actor from the authenticated session.
func actorFromRequest(r *http.Request) (action.Actor, error) {
	// TODO: resolve from session middleware — for now, return a placeholder.
	// This will be wired properly in a follow-up.
	return action.Actor{
		Type: action.ActorUser,
		ID:   "placeholder",
		IP:   r.RemoteAddr,
	}, nil
}
