package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookManager struct {
	config Webhooks
}

func NewWebhookManager(cfg Webhooks) *WebhookManager {
	return &WebhookManager{config: cfg}
}

func (wm *WebhookManager) SetConfig(w Webhooks) {
	wm.config = w
}

func (wm *WebhookManager) SendAttackNotification(username, host, method string, port, duration int) {
	if wm.config.Telegram.Enabled {
		wm.sendTelegram(username, host, method, port, duration)
	}
	if wm.config.Discord.Enabled {
		wm.sendDiscord(username, host, method, port, duration)
	}
}

func (wm *WebhookManager) SendLoginNotification(username, ip string) {
	if wm.config.Telegram.Enabled {
		msg := fmt.Sprintf("🔑 Login: %s from %s", username, ip)
		wm.sendTelegramMessage(msg)
	}
	if wm.config.Discord.Enabled {
		wm.sendDiscordEmbed("Login Notification",
			fmt.Sprintf("**User:** %s\n**IP:** %s", username, ip), 0x00FF00)
	}
}

func (wm *WebhookManager) sendTelegram(username, host, method string, port, duration int) {
	msg := fmt.Sprintf(
		"⚡ Attack Sent\n\nUser: %s\nTarget: %s:%d\nMethod: %s\nDuration: %ds\nTime: %s",
		username, host, port, method, duration,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	wm.sendTelegramMessage(msg)
}

func (wm *WebhookManager) sendTelegramMessage(text string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", wm.config.Telegram.Token)
	payload := map[string]string{
		"chat_id": wm.config.Telegram.ChatID,
		"text":    text,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (wm *WebhookManager) sendDiscord(username, host, method string, port, duration int) {
	wm.sendDiscordEmbed("Attack Sent",
		fmt.Sprintf("**User:** %s\n**Target:** %s:%d\n**Method:** %s\n**Duration:** %ds\n**Time:** %s",
			username, host, port, method, duration,
			time.Now().Format("2006-01-02 15:04:05")),
		0xFF0000)
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Color       int             `json:"color"`
	Thumbnail   *discordThumb   `json:"thumbnail,omitempty"`
	Footer      *discordFooter  `json:"footer,omitempty"`
}

type discordThumb struct {
	URL string `json:"url"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (wm *WebhookManager) sendDiscordEmbed(title, description string, color int) {
	embed := discordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Footer:      &discordFooter{Text: time.Now().Format("2006-01-02 15:04:05")},
	}

	if wm.config.Discord.Image != "" {
		embed.Thumbnail = &discordThumb{URL: wm.config.Discord.Image}
	}

	payload := discordPayload{Embeds: []discordEmbed{embed}}
	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(wm.config.Discord.Webhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	resp.Body.Close()
}
