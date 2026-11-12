package mail

import "github.com/wneessen/go-mail"

type Mailable interface {
	Subject() string
	Template() string
	Data() any
	Attach(m *mail.Msg) error
}
