package mail

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/artinZareie/hina_notes/backend/internal/config"
	"github.com/wneessen/go-mail"
)

type Mailer struct {
	client *mail.Client
	from   string
	tmpls  *template.Template
}

func NewMailer(cfg config.MailConfig) (*Mailer, error) {
	tmpls, err := template.New("mails").ParseGlob("internal/mail/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse mail templates: %w", err)
	}

	opts := []mail.Option{
		mail.WithPort(cfg.Port),
	}

	if cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(cfg.Username),
			mail.WithPassword(cfg.Password),
		)
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

	return &Mailer{
		client: client,
		from:   cfg.From,
		tmpls:  tmpls,
	}, nil
}

func (m *Mailer) Send(to string, mailable Mailable) error {
	var body bytes.Buffer
	if err := m.tmpls.ExecuteTemplate(&body, mailable.Template()+".html", mailable.Data()); err != nil {
		return fmt.Errorf("render mail template %q: %w", mailable.Template(), err)
	}

	msg := mail.NewMsg()
	if err := msg.From(m.from); err != nil {
		return fmt.Errorf("set from: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("set to: %w", err)
	}
	msg.Subject(mailable.Subject())
	msg.SetBodyString(mail.TypeTextHTML, body.String())

	if err := mailable.Attach(msg); err != nil {
		return fmt.Errorf("attach files: %w", err)
	}

	if err := m.client.DialAndSend(msg); err != nil {
		return fmt.Errorf("send mail: %w", err)
	}

	return nil
}
