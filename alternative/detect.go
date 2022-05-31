package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	OriginCIDR  string
	Port        int
	Concurrency int
	ParsedCIDR  string
)

type result struct {
	IP   netip.Addr
	Name string
}

func init() {
	flag.StringVar(&OriginCIDR, "C", "202.81.0.0/16", "IPs that's scanned")
	flag.IntVar(&Port, "P", 443, "port that's scanned")
	flag.IntVar(&Concurrency, "T", 512, "max goroutines")
	flag.Parse()
}

func getTlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "www.cloudflare.com",
		RootCAs:            nil,
	}
}

func detect(host string, tlsConfig *tls.Config) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", host, tlsConfig)
	if err != nil {
		//fmt.Printf("%T, %s\n", err, err)
		return ""
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	DNSNames := certs[0].DNSNames
	return strings.Join(DNSNames, " ")
}

func writeResults(results *[]result) {
	sort.Slice(*results, func(p, q int) bool {
		return (*results)[p].IP.Less((*results)[q].IP)
	})
	dir := "results"
	os.Mkdir(dir, 0755)
	filepath := fmt.Sprintf("%s/%s_%d", dir, strings.ReplaceAll(ParsedCIDR, "/", "_"), Port)
	fmt.Println(filepath)
	//_, err := os.Stat(filepath)
	//if !os.IsNotExist(err) {
	//	os.Rename(filepath, filepath+".bck")
	//}

	f, err := os.OpenFile(filepath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}
	for _, data := range (*results) {
		line := fmt.Sprintf("%s:%d %s\n", data.IP.String(), Port, data.Name)
		if _, err := f.Write([]byte(line)); err != nil {
			f.Close() // ignore error; Write error takes precedence
			fmt.Println(err)
		}
	}
	if err := f.Close(); err != nil {
		fmt.Println(err)
	}
}

func main() {
	tlsConfig := getTlsConfig()
	results := make([]result, 0)
	sem := make(chan bool, Concurrency)

	prefix, err := netip.ParsePrefix(OriginCIDR)
	if err != nil {
		panic(err)
	}
	ParsedCIDR = prefix.String()
	fmt.Printf("Scanning port %d of %s with %d concurrencies...\n", Port, ParsedCIDR, Concurrency)

	for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
		sem <- true
		go func(ip netip.Addr, tlsConfig *tls.Config) {
			defer func() { <-sem }()
			host := fmt.Sprintf("%s:%d", ip.String(), Port)
			name := detect(host, tlsConfig)
			if len(name) > 0 {
				results = append(results, result{IP: ip, Name: name})
			}
		}(ip, tlsConfig)
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	fmt.Println(len(results))
	writeResults(&results)
}
