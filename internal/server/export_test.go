package server

import "time"

// SetClock replaces the service clock (tests only).
func SetClock(s *Server, now func() time.Time) { s.now = now }
