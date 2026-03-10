package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	base := flag.String("api", "http://127.0.0.1:8095", "Platform API base URL")
	username := flag.String("user", "admin", "Username")
	password := flag.String("pass", os.Getenv("PLATFORM_PASSWORD"), "Password (or set PLATFORM_PASSWORD)")
	target := flag.String("target", "", "Target host or URL")
	infra := flag.Bool("infra", false, "Run infra scan")
	web := flag.Bool("web", false, "Run web scan")
	full := flag.Bool("full", false, "Run full scan")
	list := flag.Bool("list", false, "List scans")
	flag.Parse()
	if strings.TrimSpace(*password) == "" {
		fmt.Fprintln(os.Stderr, "--pass is required (or set PLATFORM_PASSWORD)")
		os.Exit(2)
	}

	token, err := login(*base, *username, *password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login error:", err)
		os.Exit(1)
	}

	if *list {
		resp, err := authedGET(*base+"/api/v1/scans", token)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(resp)
		return
	}

	if strings.TrimSpace(*target) == "" {
		fmt.Fprintln(os.Stderr, "--target is required unless --list")
		os.Exit(2)
	}
	mode := "full"
	if *infra {
		mode = "infra"
	} else if *web {
		mode = "web"
	} else if *full {
		mode = "full"
	}

	payload := map[string]any{"target": *target, "mode": mode}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, *base+"/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(string(b))
}

func login(base, user, pass string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := http.Post(base+"/api/v1/auth/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login failed: %s", string(b))
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	tok, _ := data["access_token"].(string)
	if tok == "" {
		return "", fmt.Errorf("empty access token")
	}
	return tok, nil
}

func authedGET(url, token string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("request failed: %s", string(b))
	}
	return string(b), nil
}
