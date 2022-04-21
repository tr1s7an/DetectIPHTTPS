package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	Apart       int
	Bpart       int
	Port        int
	Concurrency int
	CAPath      string
)

type result struct {
	C    int
	D    int
	name string
}

func init() {
	flag.IntVar(&Apart, "A", 202, "first part of ip range")
	flag.IntVar(&Bpart, "B", 81, "second part of ip range")
	flag.IntVar(&Port, "P", 443, "port that's scanned")
	flag.IntVar(&Concurrency, "T", 512, "max goroutines")
	flag.StringVar(&CAPath, "CA", "/etc/ssl/certs/ca-certificates.crt", "CA path")
	flag.Parse()
}

func init() {
	if Apart <= 0 || Apart >= 256 {
		Apart = 202
	}
	if Bpart <= 0 || Bpart >= 256 {
		Bpart = 81
	}
	if Port <= 0 || Port >= 65536 {
		Port = 443
	}
	if Concurrency <= 0 || Concurrency >= 1024 {
		Concurrency = 512
	}
	fmt.Printf("Scanning %d port of %d.%d.0.0/16 with %d concurrencies...\n", Port, Apart, Bpart, Concurrency)
}

func detect(host string, conf *tls.Config) string {

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", host, conf)
	if err != nil { //&& !strings.HasPrefix(err.Error(), "x509: certificate is valid for") {
		//fmt.Printf("%T, %s\n", err, err)
		return ""
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	DNSNames := certs[0].DNSNames
	return strings.Join(DNSNames, " ")
	//if len(DNSNames) > 0 {
	//	fmt.Printf("%s: %s \n", host, DNSNames)
	//}

	//n, err := conn.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\n\r\n"))
	//if err != nil {
	//	fmt.Println(n, err)
	//	return
	//}

	//buf := make([]byte, 512)
	//n, err = conn.Read(buf)
	//if err != nil {
	//	fmt.Println(n, err)
	//	return
	//}

	//fmt.Println(string(buf[:n]))
}

func write(results []result) {

	sort.Slice(results, func(p, q int) bool {
		if results[p].C == results[q].C {
			return results[p].D < results[q].D
		} else {
			return results[p].C < results[q].C
		}

	})
	dir := "results"
	os.Mkdir(dir, 0755)
	filepath := fmt.Sprintf("%s/%d.%d.x.x:%d", dir, Apart, Bpart, Port)
	_, err := os.Stat(filepath)
	if !os.IsNotExist(err) {
		os.Rename(filepath, filepath+".bck")
	}

	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
	}
	for _, data := range results {
		line := fmt.Sprintf("%d.%d.%d.%d:%d %s\n", Apart, Bpart, data.C, data.D, Port, data.name)
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
	caCert, err := os.ReadFile(CAPath)
	if err != nil {
		fmt.Println("CAPath error")
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "www.cloudflare.com",
		RootCAs:            caCertPool,
	}
	results := make([]result, 0)
	sem := make(chan bool, Concurrency)
	for Cpart := 0; Cpart < 256; Cpart++ {
		for Dpart := 0; Dpart < 256; Dpart++ {
			sem <- true
			go func(Cpart int, Dpart int, conf *tls.Config) {
				defer func() { <-sem }()
				host := fmt.Sprintf("%d.%d.%d.%d:%d", Apart, Bpart, Cpart, Dpart, Port)
				data := detect(host, conf)
				if len(data) > 0 {
					results = append(results, result{Cpart, Dpart, data})
				}
			}(Cpart, Dpart, conf)

		}
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	fmt.Println(len(results))
	write(results)
}
