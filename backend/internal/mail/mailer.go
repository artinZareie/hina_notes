package mail

import (
	"fmt"

	"github.com/artinZareie/hina_notes/backend/internal/config"
	"github.com/wneessen/go-mail"
)

type Mailer struct {
	client *mail.Client
	from   string
}

func NewMailer(cfg config.MailConfig) (*Mailer, error) {
	opts := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(cfg.Username),
		mail.WithPassword(cfg.Password),
	}

	switch cfg.Encryption {
	case "tls":
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	case "ssl":
		opts = append(opts, mail.WithSSL())
	default: // "none" — local Mailpit
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	}

	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("mail client: %w", err)
	}

	return &Mailer{client: client, from: cfg.From}, nil
}
