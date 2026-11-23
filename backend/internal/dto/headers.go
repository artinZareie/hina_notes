package dto

type CSRFHeader struct {
	CSRFToken string `header:"X-CSRF-Token" doc:"CSRF token from GET /api/v1/csrf-token"`
}
