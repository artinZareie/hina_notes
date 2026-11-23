package dto

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type VerifyEmailQuery struct {
	Token string `query:"token" required:"true" doc:"Email verification token"`
}

type ProtectedActionRequest struct {
	CSRFHeader
}
