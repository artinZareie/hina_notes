package mailables

import "github.com/wneessen/go-mail"

type VerifyEmail struct {
	Name string
	Link string
}

func (v VerifyEmail) Subject() string          { return "Verify your Hina Notes account" }
func (v VerifyEmail) Template() string         { return "verify_email" }
func (v VerifyEmail) Data() any                { return v }
func (v VerifyEmail) Attach(_ *mail.Msg) error { return nil }
