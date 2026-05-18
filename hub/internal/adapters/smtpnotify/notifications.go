package smtpnotify

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type Config struct {
	Host        string
	Port        string
	Username    string
	Password    string
	From        string
	To          []string
	BaseURL     string
	MinSeverity string
	Events      []string
	Timeout     time.Duration
}

type NotificationSink struct {
	host        string
	port        string
	username    string
	password    string
	from        string
	to          []string
	baseURL     string
	minSeverity string
	events      map[string]struct{}
	timeout     time.Duration
}

func NewNotificationSink(config Config) (*NotificationSink, error) {
	recipients := cleanEmailList(config.To)
	host := strings.TrimSpace(config.Host)
	username := strings.TrimSpace(config.Username)
	password := strings.TrimSpace(config.Password)
	from := strings.TrimSpace(config.From)
	if len(recipients) == 0 && username == "" && password == "" && from == "" {
		return nil, nil
	}
	if host == "" {
		host = "in-v3.mailjet.com"
	}
	port := strings.TrimSpace(config.Port)
	if port == "" {
		port = "587"
	}
	if len(recipients) == 0 || username == "" || password == "" || from == "" {
		return nil, fmt.Errorf("SMTP notifications require from, recipients, username, and password")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	events := eventSet(config.Events)
	if len(events) == 0 {
		events["finding.observed"] = struct{}{}
	}
	minSeverity := strings.ToLower(strings.TrimSpace(config.MinSeverity))
	if minSeverity == "" {
		minSeverity = "medium"
	}
	return &NotificationSink{
		host:        host,
		port:        port,
		username:    username,
		password:    password,
		from:        from,
		to:          recipients,
		baseURL:     strings.TrimRight(strings.TrimSpace(config.BaseURL), "/"),
		minSeverity: minSeverity,
		events:      events,
		timeout:     timeout,
	}, nil
}

func (s *NotificationSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	if s == nil || !s.shouldSend(notification) {
		return nil
	}
	subject := sanitizeHeader(fmt.Sprintf("[Aegrail] %s %s: %s", strings.ToUpper(string(notification.Finding.Severity)), notification.Finding.RuleID, notification.Finding.Title))
	message := s.emailMessage(notification, subject)
	return s.send(ctx, subject, message)
}

func (s *NotificationSink) shouldSend(notification ports.HubFindingNotification) bool {
	if _, ok := s.events[strings.TrimSpace(notification.Type)]; !ok {
		return false
	}
	return severityRank(notification.Finding.Severity) >= severityRank(domain.Severity(s.minSeverity))
}

func (s *NotificationSink) send(ctx context.Context, _ string, message []byte) error {
	address := net.JoinHostPort(s.host, s.port)
	dialer := &net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if s.username != "" || s.password != "" {
		if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return err
		}
	}
	from, err := smtpEnvelopeAddress(s.from)
	if err != nil {
		return err
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range s.to {
		address, err := smtpEnvelopeAddress(recipient)
		if err != nil {
			return err
		}
		if err := client.Rcpt(address); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (s *NotificationSink) emailMessage(notification ports.HubFindingNotification, subject string) []byte {
	finding := notification.Finding
	link := s.findingURL(finding.ID)
	var body bytes.Buffer
	fmt.Fprintf(&body, "From: %s\r\n", sanitizeHeader(s.from))
	fmt.Fprintf(&body, "To: %s\r\n", sanitizeHeader(strings.Join(s.to, ", ")))
	fmt.Fprintf(&body, "Subject: %s\r\n", subject)
	body.WriteString("MIME-Version: 1.0\r\n")
	body.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	body.WriteString("\r\n")
	body.WriteString("<!doctype html><html><body style=\"font-family:Arial,sans-serif;color:#172033\">")
	body.WriteString("<h2 style=\"margin:0 0 12px\">Aegrail finding</h2>")
	fmt.Fprintf(&body, "<p><strong>%s</strong> / %s confidence</p>", html.EscapeString(string(finding.Severity)), html.EscapeString(string(finding.Confidence)))
	fmt.Fprintf(&body, "<p><strong>%s</strong></p>", html.EscapeString(finding.Title))
	fmt.Fprintf(&body, "<p>%s</p>", html.EscapeString(finding.Summary))
	body.WriteString("<table cellpadding=\"6\" cellspacing=\"0\" style=\"border-collapse:collapse\">")
	emailRow(&body, "Event", notification.Type)
	emailRow(&body, "Rule", finding.RuleID)
	emailRow(&body, "Status", findingStatus(finding))
	emailRow(&body, "First event", finding.FirstEventAt.UTC().Format(time.RFC3339))
	emailRow(&body, "Last event", finding.LastEventAt.UTC().Format(time.RFC3339))
	if link != "" {
		emailRow(&body, "Dashboard", link)
	}
	body.WriteString("</table>")
	body.WriteString("</body></html>")
	return body.Bytes()
}

func (s *NotificationSink) findingURL(findingID domain.ID) string {
	if s.baseURL == "" || findingID == "" {
		return ""
	}
	return s.baseURL + "/dashboard/issue/" + string(findingID)
}

func emailRow(body *bytes.Buffer, label string, value string) {
	fmt.Fprintf(body, "<tr><td style=\"color:#667085\">%s</td><td>%s</td></tr>", html.EscapeString(label), html.EscapeString(value))
}

func cleanEmailList(values []string) []string {
	var cleaned []string
	seen := map[string]struct{}{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, ok := seen[strings.ToLower(item)]; ok {
				continue
			}
			seen[strings.ToLower(item)] = struct{}{}
			cleaned = append(cleaned, item)
		}
	}
	return cleaned
}

func eventSet(values []string) map[string]struct{} {
	events := map[string]struct{}{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				events[item] = struct{}{}
			}
		}
	}
	return events
}

func severityRank(severity domain.Severity) int {
	switch strings.ToLower(strings.TrimSpace(string(severity))) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func findingStatus(finding domain.HubFinding) string {
	if strings.TrimSpace(finding.Status) == "" {
		return "open"
	}
	return finding.Status
}

func sanitizeHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func smtpEnvelopeAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("email address is required")
	}
	address, err := mail.ParseAddress(value)
	if err != nil {
		return value, nil
	}
	return address.Address, nil
}
