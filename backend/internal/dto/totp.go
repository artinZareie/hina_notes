package dto

type TOTPSetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

type TOTPEnableRequest struct {
	Code string `json:"code" binding:"required"`
}

type TOTPEnableResponse struct {
	Message       string   `json:"message"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type TOTPVerifyRequest struct {
	Code string `json:"code" binding:"required"`
}
