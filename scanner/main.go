package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type PortResult struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service"`
}

type ScanRequest struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

var blockedCIDRs []*net.IPNet

func init() {
	blocked := []string{
		"10.0.0.0/8",       
		"172.16.0.0/12",  
		"192.168.0.0/16",  
		"127.0.0.0/8",     
		"169.254.0.0/16",   
		"::1/128",      
		"fc00::/7",    
		"fe80::/10",      
	}
	for _, cidr := range blocked {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, network)
		}
	}
}

func isBlockedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // geçersiz IP → engelle
	}
	for _, network := range blockedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func validateHost(host string) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("host boş olamaz")
	}

	hostLower := strings.ToLower(strings.TrimSpace(host))

	forbidden := []string{"localhost", "metadata", "internal"}
	for _, f := range forbidden {
		if strings.Contains(hostLower, f) {
			return fmt.Errorf("bu host adresine izin verilmiyor: %s", host)
		}
	}

	// Direk IP ise engellenmiş mi kontrol et
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(host) {
			return fmt.Errorf("özel/dahili IP adreslerine tarama yapılamaz: %s", host)
		}
		return nil
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("host çözümlenemedi: %s", host)
	}
	for _, resolvedIP := range ips {
		if isBlockedIP(resolvedIP) {
			return fmt.Errorf("domain dahili bir IP'ye çözümleniyor, tarama engellendi: %s → %s", host, resolvedIP)
		}
	}

	return nil
}


func scanPort(host string, port int, results chan<- PortResult, wg *sync.WaitGroup) {
	defer wg.Done()

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)

	if err != nil {
		results <- PortResult{Port: port, Open: false}
		return
	}
	conn.Close()
	results <- PortResult{Port: port, Open: true}
}

func massPortScan(host string, ports []int) []PortResult {
	results := make(chan PortResult, len(ports))
	var wg sync.WaitGroup

	sem := make(chan struct{}, 300)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer func() { <-sem }()
			scanPort(host, p, results, &wg)
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []PortResult
	for r := range results {
		if r.Open {
			openPorts = append(openPorts, r)
		}
	}
	return openPorts
}


func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "sadece POST metodu desteklenir")
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "geçersiz JSON gövdesi")
		return
	}

	if err := validateHost(req.Host); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if len(req.Ports) == 0 {
		for i := 1; i <= 10000; i++ {
			req.Ports = append(req.Ports, i)
		}
	}

	if len(req.Ports) > 10000 {
		writeError(w, http.StatusBadRequest, "en fazla 10000 port taranabilir")
		return
	}

	results := massPortScan(req.Host, req.Ports)

	if results == nil {
		results = []PortResult{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func main() {
	http.HandleFunc("/scan", scanHandler)
	fmt.Println("Go tarayıcı :8765 portunda başlatıldı")
	fmt.Println("SSRF koruması aktif — RFC-1918 ve link-local adresler engellendi")
	http.ListenAndServe(":8765", nil)
}
