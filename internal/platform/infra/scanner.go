package infra

import (
	"fmt"
	"net"
	"time"

	"scannn3d/internal/platform/storage"
)

var commonPorts = []int{21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443}

func ScanHost(host string) ([]storage.Asset, []storage.Service) {
	asset := storage.Asset{Host: host}
	services := make([]storage.Service, 0, len(commonPorts))
	for _, port := range commonPorts {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, 1200*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		banner := make([]byte, 128)
		n, _ := conn.Read(banner)
		_ = conn.Close()
		services = append(services, storage.Service{
			AssetID:  asset.ID,
			Port:     port,
			Protocol: "tcp",
			Name:     guessServiceName(port),
			Banner:   string(banner[:n]),
		})
	}
	return []storage.Asset{asset}, services
}

func guessServiceName(port int) string {
	switch port {
	case 80, 8080:
		return "http"
	case 443, 8443:
		return "https"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 6379:
		return "redis"
	default:
		return "unknown"
	}
}
