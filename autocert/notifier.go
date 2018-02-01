package autocert

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Notifier is used by Manager to send notifications on main events
type Notifier interface {
	Created(hosts []string)
	Renewed(hosts []string)
	Error(hosts []string, msg string)
}

// SlackNotifier implements Notifier for Slack with a provided Webhook URL
type SlackNotifier string

// Created implements Notifier.Created
func (n SlackNotifier) Created(hosts []string) {
	n.sendRequest(hosts, "created", "good")
}

// Renewed implements Notifier.Renewed
func (n SlackNotifier) Renewed(hosts []string) {
	n.sendRequest(hosts, "renewed", "good")
}

// Error implements Notifier.Error
func (n SlackNotifier) Error(hosts []string, msg string) {
	n.sendRequest(hosts, msg, "danger")
}

func (n SlackNotifier) sendRequest(hosts []string, message, colour string) {

	hostname, _ := os.Hostname()

	json := `
		{
			"username": "go-certs",
			"attachments": [
				{
					"title": "` + strings.Join(hosts, ", ") + `",
					"text": "` + "```\n" + strings.Replace(message, "\"", "\\\"", -1) + "\n```" + `",
					"color": "` + colour + `",
					"footer": "` + hostname + `",
					"mrkdwn_in": ["text"]
				}
			]
		}
`

	client := http.Client{}
	req, err := http.NewRequest("POST", string(n), bytes.NewBufferString(json))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer req.Body.Close()

	req.Header.Set("Content-Type", "application/json")
	_, err = client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

}
