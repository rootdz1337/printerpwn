package main

import (
	"crypto/tls"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/hashicorp/mdns"
)

// ---------------- Config ----------------

var printerPorts = []int{
	9100, // Raw JetDirect / PJL
	515,  // LPD
	631,  // IPP
	9220, 9221, 9222, // HP JetDirect
	80, 443, 8080, 8443, // Web UI
	161, // SNMP (TCP probe only; UDP scan separate)
	427, // SLP
	137, 138, 139, 445, // NetBIOS/SMB
	21,  // FTP (many printers have it)
	23,  // Telnet
	3702, // WSD (WS-Discovery)
}

// ---------------- Data Model ----------------

type Result struct {
	IP         string            `json:"ip"`
	Hostname   string            `json:"hostname,omitempty"`
	MAC        string            `json:"mac,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	Model      string            `json:"model,omitempty"`
	Serial     string            `json:"serial,omitempty"`
	Firmware   string            `json:"firmware,omitempty"`
	OpenPorts  []int             `json:"open_ports"`
	Banners    map[string]string `json:"banners,omitempty"`
	Services   map[string]string `json:"services,omitempty"`
	NetBIOS    []string          `json:"netbios,omitempty"`
	SMB        string            `json:"smb,omitempty"`
	IPP        map[string]string `json:"ipp,omitempty"`
	PJL        map[string]string `json:"pjl,omitempty"`
	SNMP       map[string]string `json:"snmp,omitempty"`
	MDNS       []string          `json:"mdns,omitempty"`
	SLP        []string          `json:"slp,omitempty"`
	WSD        string            `json:"wsd,omitempty"`
	LPDQueue   []string          `json:"lpd_queue,omitempty"`
	IsPrinter  bool              `json:"is_printer"`
	Findings   []string          `json:"findings,omitempty"`
	ScanTime   string            `json:"scan_time"`
}

// ---------------- Main ----------------

type Config struct {
	Timeout   time.Duration
	Threads   int
	SNMPComm  string
	UseMDNS   bool
	OutputFmt string
	OutFile   string
	Verbose   bool
}

var cfg Config

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func main() {
	target := flag.String("target", "", "Target CIDR (e.g. 192.168.1.0/24) or single IP")
	timeout := flag.Duration("timeout", 800*time.Millisecond, "Per-probe timeout")
	threads := flag.Int("threads", 100, "Concurrent workers")
	snmpComm := flag.String("snmp", "public", "SNMP community string")
	useMDNS := flag.Bool("mdns", true, "Enable mDNS printer discovery")
	outputFmt := flag.String("format", "text", "Output: text|json|csv")
	outFile := flag.String("o", "", "Output file (default stdout)")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *target == "" && !*useMDNS {
		fmt.Println("Usage: printerscan -target 192.168.1.0/24 [-mdns] [-format json -o out.json]")
		os.Exit(1)
	}

	cfg = Config{
		Timeout:   *timeout,
		Threads:   *threads,
		SNMPComm:  *snmpComm,
		UseMDNS:   *useMDNS,
		OutputFmt: *outputFmt,
		OutFile:   *outFile,
		Verbose:   *verbose,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var all []*Result
	var mu sync.Mutex

	// ---- mDNS discovery ----
	if cfg.UseMDNS {
		if cfg.Verbose {
			fmt.Println("[*] mDNS discovery for printers...")
		}
		mdnsResults := mdnsDiscover()
		mu.Lock()
		all = append(all, mdnsResults...)
		mu.Unlock()
	}

	// ---- Network scan ----
	if *target != "" {
		ips := expandTargets(*target)
		fmt.Printf("[*] Scanning %d hosts with %d workers\n", len(ips), cfg.Threads)

		results := make(chan *Result, len(ips))
		sem := make(chan struct{}, cfg.Threads)
		var wg sync.WaitGroup

		for _, ip := range ips {
			select {
			case <-ctx.Done():
				break
			default:
			}
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				r := scanHost(ctx, ip)
				if r != nil && (r.IsPrinter || len(r.OpenPorts) > 0) {
					results <- r
				}
			}(ip)
		}

		go func() { wg.Wait(); close(results) }()

		for r := range results {
			mu.Lock()
			all = append(all, r)
			mu.Unlock()
		}
	}

	// Merge mDNS results with scanned results by IP
	all = mergeResults(all)

	// Output
	outputResults(all)
}

// ---------------- Target expansion ----------------

func expandTargets(target string) []string {
	var ips []string
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			fmt.Println("Invalid CIDR:", err)
			os.Exit(1)
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
		}
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1]
		}
	} else {
		ips = append(ips, target)
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ---------------- Host scanner ----------------

func scanHost(ctx context.Context, ip string) *Result {
	r := &Result{
		IP:       ip,
		Banners:  map[string]string{},
		Services: map[string]string{},
		ScanTime: time.Now().Format(time.RFC3339),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// TCP port scan
	for _, port := range printerPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
			if err != nil {
				return
			}
			defer conn.Close()

			mu.Lock()
			r.OpenPorts = append(r.OpenPorts, port)
			mu.Unlock()

			banner := grabBanner(conn, port)
			if banner != "" {
				mu.Lock()
				r.Banners[strconv.Itoa(port)] = banner
				mu.Unlock()
			}
			if svc := serviceName(port); svc != "" {
				mu.Lock()
				r.Services[strconv.Itoa(port)] = svc
				mu.Unlock()
			}

			if port == 9100 || port == 515 || port == 631 || port == 9220 {
				mu.Lock()
				r.IsPrinter = true
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	// Sort ports
	sort.Ints(r.OpenPorts)

	// SNMP (UDP)
	snmp, mac, host, model, serial, fw := snmpQuery(ip)
	if len(snmp) > 0 {
		r.SNMP = snmp
		r.MAC = mac
		if host != "" {
			r.Hostname = host
		}
		r.Model = model
		r.Serial = serial
		r.Firmware = fw
		r.IsPrinter = true
	}

	// NetBIOS
	r.NetBIOS = netbiosQuery(ip)

	// SMB
	if containsPort(r.OpenPorts, 445) {
		r.SMB = smbProbe(ip)
		if r.SMB == "SMB-open" && r.IsPrinter {
			r.Findings = append(r.Findings, "SMB/445 open on printer – potential exposure")
		}
	}

	// IPP details
	if containsPort(r.OpenPorts, 631) {
		if ipp := ippQuery(ip); ipp != nil {
			r.IPP = ipp
			if v, ok := ipp["printer-make-and-model"]; ok {
				r.Model = v
			}
			if v, ok := ipp["printer-name"]; ok && r.Hostname == "" {
				r.Hostname = v
			}
			r.IsPrinter = true
		}
	}

	// PJL info (port 9100)
	if containsPort(r.OpenPorts, 9100) {
		r.PJL = pjlQuery(ip)
		r.IsPrinter = true
	}

	// LPD queue list (port 515)
	if containsPort(r.OpenPorts, 515) {
		r.LPDQueue = lpdQueueList(ip)
		r.IsPrinter = true
	}

	// SLP (port 427) discovery – parse service URLs
	if containsPort(r.OpenPorts, 427) {
		r.SLP = slpQuery(ip)
	}

	// HTTP printer identification
	for _, p := range []int{80, 8080, 631, 443, 8443} {
		if containsPort(r.OpenPorts, p) {
			if id := httpIdentify(ip, p); id != "" {
				if r.Model == "" {
					r.Model = id
				}
				r.IsPrinter = true
				break
			}
		}
	}

	// WSD probe
	if containsPort(r.OpenPorts, 3702) {
		if wsd := wsdProbe(ip); wsd != "" {
			r.WSD = wsd
			r.IsPrinter = true
		}
	}

	// Security findings
	if r.IsPrinter {
		if containsPort(r.OpenPorts, 23) {
			r.Findings = append(r.Findings, "Telnet/23 open – unencrypted admin")
		}
		if containsPort(r.OpenPorts, 21) {
			r.Findings = append(r.Findings, "FTP/21 open – check for anonymous access")
		}
		if containsPort(r.OpenPorts, 9100) && containsPort(r.OpenPorts, 80) {
			r.Findings = append(r.Findings, "Raw printing exposed without auth on 9100")
		}
	}

	return r
}

func containsPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

func serviceName(port int) string {
	switch port {
	case 9100:
		return "jetdirect/pjl"
	case 515:
		return "lpd"
	case 631:
		return "ipp"
	case 9220, 9221, 9222:
		return "hp-jetdirect"
	case 80:
		return "http"
	case 443:
		return "https"
	case 8080, 8443:
		return "http-alt"
	case 161:
		return "snmp"
	case 427:
		return "slp"
	case 137:
		return "netbios-ns"
	case 138:
		return "netbios-dgm"
	case 139:
		return "netbios-ssn"
	case 445:
		return "smb"
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 3702:
		return "wsd"
	}
	return ""
}

// ---------------- Banner grabbing ----------------

func grabBanner(conn net.Conn, port int) string {
	switch port {
	case 80, 8080, 443, 8443, 631:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PrinterScan/2.0\r\n\r\n")
	case 21:
		// FTP announces itself
	}
	reader := bufio.NewReader(conn)
	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	n, err := reader.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return sanitize(string(buf[:n]))
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}

// ---------------- SNMP ----------------

func snmpQuery(ip string) (map[string]string, string, string, string, string, string) {
	res := map[string]string{}
	var mac, host, model, serial, firmware string

	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: cfg.SNMPComm,
		Version:   gosnmp.Version2c,
		Timeout:   cfg.Timeout,
		Retries:   1,
	}
	if err := snmp.Connect(); err != nil {
		return res, mac, host, model, serial, firmware
	}
	defer snmp.Conn.Close()

	// OIDs of interest
	oids := map[string]string{
		"1.3.6.1.2.1.1.1.0":   "sysDescr",
		"1.3.6.1.2.1.1.3.0":   "sysUpTime",
		"1.3.6.1.2.1.1.5.0":   "sysName",
		"1.3.6.1.2.1.1.6.0":   "sysLocation",
		"1.3.6.1.2.1.1.4.0":   "sysContact",
		"1.3.6.1.2.1.2.2.1.6": "ifPhysAddress", // walk for MAC
		// Printer MIB
		"1.3.6.1.2.1.43.5.1.1.16.1": "printerSerialNumber",
		"1.3.6.1.2.1.43.5.1.1.17.1": "printerModel",
		"1.3.6.1.2.1.25.3.2.1.3.1":  "hrDeviceDescr",
	}

	var keys []string
	for k := range oids {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, oid := range keys {
		pkt, err := snmp.Get([]string{oid})
		if err != nil || pkt == nil {
			continue
		}
		for _, v := range pkt.Variables {
			val := snmpValue(v)
			if val == "" {
				continue
			}
			name := oids[oid]
			res[name] = val
			switch name {
			case "sysName":
				host = val
			case "sysDescr":
				if model == "" {
					model = val
				}
			case "printerModel", "hrDeviceDescr":
				model = val
			case "printerSerialNumber":
				serial = val
			}
		}
	}

	// Walk ifPhysAddress for MAC (first one that isn't zero)
	if err := snmp.Walk("1.3.6.1.2.1.2.2.1.6", func(pdu gosnmp.SnmpPDU) error {
		if b, ok := pdu.Value.([]byte); ok && len(b) == 6 {
			if !(b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0) {
				mac = strings.ToUpper(hex.EncodeToString(b))
				mac = insertColons(mac)
			}
		}
		return nil
	}); err != nil && cfg.Verbose {
		// ignore
	}

	// Walk hrDeviceDescr for firmware clues
	_ = snmp.Walk("1.3.6.1.2.1.1.1", func(pdu gosnmp.SnmpPDU) error {
		if firmware == "" {
			if s, ok := pdu.Value.(string); ok && strings.Contains(strings.ToLower(s), "firmware") {
				firmware = s
			}
		}
		return nil
	})

	if len(res) == 0 {
		return nil, "", "", "", "", ""
	}
	return res, mac, host, model, serial, firmware
}

func snmpValue(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		if b, ok := pdu.Value.([]byte); ok {
			return strings.TrimSpace(string(b))
		}
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32:
		return fmt.Sprintf("%v", pdu.Value)
	case gosnmp.TimeTicks:
		if t, ok := pdu.Value.(uint32); ok {
			return fmt.Sprintf("%ds", t/100)
		}
	}
	return fmt.Sprintf("%v", pdu.Value)
}

func insertColons(mac string) string {
	if len(mac) != 12 {
		return mac
	}
	var sb strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(mac[i : i+2])
	}
	return sb.String()
}

// ---------------- NetBIOS ----------------

func netbiosQuery(ip string) []string {
	conn, err := net.DialTimeout("udp", ip+":137", cfg.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	query := []byte{
		0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 'C', 'K',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 0x00,
		0x00, 0x21, 0x00, 0x01,
	}

	conn.SetDeadline(time.Now().Add(cfg.Timeout))
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return nil
	}

	numNames := int(buf[56])
	offset := 57
	var names []string
	for i := 0; i < numNames && offset+18 <= n; i++ {
		name := strings.TrimSpace(string(buf[offset : offset+15]))
		suffix := buf[offset+15]
		if name != "" && name != "\x00" && suffix == 0x00 {
			names = append(names, name)
		}
		offset += 18
	}
	return names
}

// ---------------- SMB ----------------

func smbProbe(ip string) string {
	conn, err := net.DialTimeout("tcp", ip+":445", cfg.Timeout)
	if err != nil {
		return "no"
	}
	defer conn.Close()

	probe := []byte{
		0x00, 0x00, 0x00, 0x85,
		0xFF, 'S', 'M', 'B', 0x72,
		0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x62, 0x00,
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '0', '0', '2', 0x00,
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '0', '0', 0x00,
		0x02, 'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ', 'P', 'R', 'O', 'G', 'R', 'A', 'M', ' ', '1', '.', '0', 0x00,
		0x02, 'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', 0x00,
	}
	conn.SetDeadline(time.Now().Add(cfg.Timeout))
	if _, err := conn.Write(probe); err != nil {
		return "probe-failed"
	}
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n < 8 {
		return "no-response"
	}
	if n > 8 && resp[4] == 0xFF && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B' {
		return "SMB-open"
	}
	return "filtered"
}

// ---------------- IPP ----------------

func ippQuery(ip string) map[string]string {
	body := buildIPPGetPrinterAttributes()
	url := fmt.Sprintf("http://%s:631/ipp/print", ip)
	client := &http.Client{Timeout: cfg.Timeout * 2}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/ipp")
	resp, err := client.Do(req)
	if err != nil {
		// try /printers
		url2 := fmt.Sprintf("http://%s:631/printers", ip)
		req2, _ := http.NewRequest("POST", url2, bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/ipp")
		resp, err = client.Do(req2)
		if err != nil {
			return nil
		}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return parseIPP(raw)
}

func buildIPPGetPrinterAttributes() []byte {
	// IPP/1.1 Get-Printer-Attributes
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(0x0200)) // version 2.0
	binary.Write(buf, binary.BigEndian, uint16(0x000B)) // Get-Printer-Attributes
	binary.Write(buf, binary.BigEndian, uint32(1))      // request-id
	buf.WriteByte(0x01)                                  // operation-attributes-tag
	writeIPPAttr(buf, 0x47, "attributes-charset", "utf-8")
	writeIPPAttr(buf, 0x48, "attributes-natural-language", "en")
	writeIPPAttr(buf, 0x45, "printer-uri", "ipp://localhost/ipp/print")
	buf.WriteByte(0x03) // end-of-attributes
	return buf.Bytes()
}

func writeIPPAttr(buf *bytes.Buffer, tag byte, name, value string) {
	buf.WriteByte(tag)
	binary.Write(buf, binary.BigEndian, uint16(len(name)))
	buf.WriteString(name)
	binary.Write(buf, binary.BigEndian, uint16(len(value)))
	buf.WriteString(value)
}

func parseIPP(raw []byte) map[string]string {
	if len(raw) < 8 {
		return nil
	}
	status := binary.BigEndian.Uint16(raw[2:4])
	if status >= 0x0400 {
		return nil
	}
	res := map[string]string{}
	i := 8
	// skip attributes-charset/natural-language groups
	for i < len(raw) {
		tag := raw[i]
		i++
		if tag == 0x03 {
			break
		}
		if tag == 0x04 || tag <= 0x0F {
			continue // delimiter tags
		}
		if i+2 > len(raw) {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(raw[i:]))
		i += 2
		if i+nameLen > len(raw) {
			break
		}
		name := string(raw[i : i+nameLen])
		i += nameLen
		if i+2 > len(raw) {
			break
		}
		valLen := int(binary.BigEndian.Uint16(raw[i:]))
		i += 2
		if i+valLen > len(raw) {
			break
		}
		val := raw[i : i+valLen]
		i += valLen
		if name != "" {
			res[name] = string(val)
		}
	}
	return res
}

// ---------------- PJL ----------------

func pjlQuery(ip string) map[string]string {
	conn, err := net.DialTimeout("tcp", ip+":9100", cfg.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Universal Exit + PJL INFO
	cmd := "\x1b%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n@PJL INFO CONFIG\r\n@PJL INFO VARIABLES\r\n\x1b%-12345X\r\n"
	conn.SetDeadline(time.Now().Add(cfg.Timeout * 3))
	conn.Write([]byte(cmd))

	res := map[string]string{}
	buf := make([]byte, 8192)
	total := 0
	deadline := time.Now().Add(cfg.Timeout * 3)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
			if total >= len(buf) {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if total == 0 {
		return nil
	}
	text := string(buf[:total])

	// Extract sections
	sections := []string{"ID", "STATUS", "CONFIG", "VARIABLES"}
	for _, s := range sections {
		marker := "@PJL INFO " + s
		idx := strings.Index(text, marker)
		if idx < 0 {
			continue
		}
		end := strings.Index(text[idx:], "\x0c") // form feed terminates
		var chunk string
		if end < 0 {
			chunk = text[idx:]
		} else {
			chunk = text[idx : idx+end]
		}
		// Trim to 500 chars
		chunk = strings.TrimSpace(chunk)
		if len(chunk) > 500 {
			chunk = chunk[:500] + "..."
		}
		res[s] = chunk
	}

	// Extract model from ID
	if id, ok := res["ID"]; ok {
		lines := strings.Split(id, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(strings.ToUpper(l), "MODEL:") {
				res["MODEL"] = strings.TrimSpace(strings.TrimPrefix(l, "MODEL:"))
			}
		}
	}

	return res
}

// ---------------- LPD ----------------

func lpdQueueList(ip string) []string {
	conn, err := net.DialTimeout("tcp", ip+":515", cfg.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send queue list command (0x03 = "send queue state (long)") + queue + blank
	conn.SetDeadline(time.Now().Add(cfg.Timeout * 2))
	conn.Write([]byte{0x03, ' ', ' ', '\n'})
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	// First byte is ack
	text := string(buf[1:n])
	var queues []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "no entries") {
			queues = append(queues, line)
		}
	}
	if len(queues) > 20 {
		queues = queues[:20]
	}
	return queues
}

// ---------------- SLP ----------------

func slpQuery(ip string) []string {
	// SLP is UDP/427; we send a service request for printer services
	conn, err := net.DialTimeout("udp", ip+":427", cfg.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Build a minimal SLP SrvRqst for service:printer
	// Version=2, Function=1 (SrvRqst), ...
	// Simplified: we just look for a response
	payload := []byte{
		0x02, 0x01, 0x00, 0x00, // version, function, length (placeholder)
		0x00, 0x00, 0x00, 0x00, // flags
		0x00, 0x00, 0x00, 0x00, // ext offset
		0x00, 0x00, 0x00, 0x01, // xid
		0x00, 0x02,             // lang len
		'e', 'n',
		0x00, 0x18, // string len (service:printer...)
	}
	svc := "service:printer.x.x"
	for _, c := range svc {
		payload = append(payload, byte(c))
	}
	// Pad
	binary.BigEndian.PutUint32(payload[4:8], uint32(len(payload)-8))

	conn.SetDeadline(time.Now().Add(cfg.Timeout))
	conn.Write(payload)
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 20 {
		return nil
	}
	return []string{fmt.Sprintf("SLP response %d bytes", n)}
}

// ---------------- WSD ----------------

func wsdProbe(ip string) string {
	// WS-Discovery is multicast, but some devices respond to directed unicast
	// Simplification: we check if HTTP endpoint /wsd/device responds
	url := fmt.Sprintf("http://%s/wsd/device", ip)
	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Get(url)
	if err == nil {
		resp.Body.Close()
		return "WSD endpoint reachable"
	}
	// Try WSD probe via UDP broadcast-style to the host
	return ""
}

// ---------------- HTTP printer ID ----------------

func httpIdentify(ip string, port int) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
	client := &http.Client{
		Timeout: cfg.Timeout * 2,
		Transport: &http.Transport{
			TLSClientConfig: insecureTLS(),
		},
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "PrinterScan/2.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	text := strings.ToLower(string(body))

	server := resp.Header.Get("Server")
	wwwAuth := resp.Header.Get("WWW-Authenticate")

	candidates := []string{}
	if server != "" {
		candidates = append(candidates, server)
	}
	keywords := map[string]string{
		"hp ":        "HP",
		"jetdirect":  "HP JetDirect",
		"canon":      "Canon",
		"epson":      "Epson",
		"brother":    "Brother",
		"xerox":      "Xerox",
		"lexmark":    "Lexmark",
		"ricoh":      "Ricoh",
		"kyocera":    "Kyocera",
		"konica":     "Konica Minolta",
		"minolta":    "Konica Minolta",
		"sharp":      "Sharp",
		"toshiba":    "Toshiba",
		"samsung":    "Samsung",
		"dell":       "Dell",
		"cups":       "CUPS",
		"printer":    "Printer",
		"ipp":        "IPP",
	}
	for kw, name := range keywords {
		if strings.Contains(text, kw) || strings.Contains(strings.ToLower(server), kw) {
			return name
		}
	}
	if wwwAuth != "" && strings.Contains(strings.ToLower(wwwAuth), "basic") {
		return "HTTP-Basic-Auth"
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// ---------------- mDNS ----------------

func mdnsDiscover() []*Result {
	results := map[string]*Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	services := []string{"_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"}

	for _, svc := range services {
		wg.Add(1)
		go func(service string) {
			defer wg.Done()
			entries := make(chan *mdns.ServiceEntry, 32)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			go func() {
				mdns.Lookup(service, entries)
				close(entries)
			}()

			for {
				select {
				case <-ctx.Done():
					return
				case e, ok := <-entries:
					if !ok {
						return
					}
					if e.AddrV4 == nil {
						continue
					}
					ip := e.AddrV4.String()
					mu.Lock()
					r, exists := results[ip]
					if !exists {
						r = &Result{
							IP:       ip,
							Banners:  map[string]string{},
							Services: map[string]string{},
							ScanTime: time.Now().Format(time.RFC3339),
						}
						results[ip] = r
					}
					r.MDNS = append(r.MDNS, fmt.Sprintf("%s (%s)", e.Name, service))
					r.IsPrinter = true
					if e.Host != "" {
						r.Hostname = strings.TrimSuffix(e.Host, ".")
					}
					for _, f := range e.InfoFields {
						kv := strings.SplitN(f, "=", 2)
						if len(kv) == 2 {
							switch strings.ToLower(kv[0]) {
							case "ty":
								r.Model = kv[1]
							case "product":
								if r.Model == "" {
									r.Model = kv[1]
								}
							case "usb_mdl", "usb_mfg":
								r.Model = kv[1]
							case "note", "location":
								r.Services["mdns-"+kv[0]] = kv[1]
							case "rp":
								r.Services["mdns-rp"] = kv[1]
							case "adminurl":
								r.Services["mdns-admin"] = kv[1]
							}
						}
					}
					mu.Unlock()
				}
			}
		}(svc)
	}
	wg.Wait()

	out := make([]*Result, 0, len(results))
	for _, r := range results {
		out = append(out, r)
	}
	return out
}

// ---------------- Result merging ----------------

func mergeResults(all []*Result) []*Result {
	byIP := map[string]*Result{}
	for _, r := range all {
		if existing, ok := byIP[r.IP]; ok {
			// Merge
			existing.OpenPorts = mergePorts(existing.OpenPorts, r.OpenPorts)
			if existing.Hostname == "" {
				existing.Hostname = r.Hostname
			}
			if existing.Model == "" {
				existing.Model = r.Model
			}
			if existing.MAC == "" {
				existing.MAC = r.MAC
			}
			if existing.SNMP == nil {
				existing.SNMP = r.SNMP
			}
			if existing.IPP == nil {
				existing.IPP = r.IPP
			}
			if existing.PJL == nil {
				existing.PJL = r.PJL
			}
			if existing.SMB == "" {
				existing.SMB = r.SMB
			}
			existing.IsPrinter = existing.IsPrinter || r.IsPrinter
			existing.MDNS = append(existing.MDNS, r.MDNS...)
			existing.Findings = append(existing.Findings, r.Findings...)
			for k, v := range r.Banners {
				if _, ok := existing.Banners[k]; !ok {
					existing.Banners[k] = v
				}
			}
			for k, v := range r.Services {
				if _, ok := existing.Services[k]; !ok {
					existing.Services[k] = v
				}
			}
			for _, n := range r.NetBIOS {
				if !containsStr(existing.NetBIOS, n) {
					existing.NetBIOS = append(existing.NetBIOS, n)
				}
			}
		} else {
			byIP[r.IP] = r
		}
	}
	out := make([]*Result, 0, len(byIP))
	for _, r := range byIP {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsPrinter != out[j].IsPrinter {
			return out[i].IsPrinter
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func mergePorts(a, b []int) []int {
	m := map[int]bool{}
	for _, p := range a {
		m[p] = true
	}
	for _, p := range b {
		m[p] = true
	}
	var out []int
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ---------------- Output ----------------

func outputResults(all []*Result) {
	var out io.Writer = os.Stdout
	if cfg.OutFile != "" {
		f, err := os.Create(cfg.OutFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot create output file:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	switch cfg.OutputFmt {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(all)
	case "csv":
		w := csv.NewWriter(out)
		w.Write([]string{
			"ip", "is_printer", "hostname", "model", "serial", "firmware",
			"mac", "open_ports", "netbios", "smb", "mdns", "findings",
		})
		for _, r := range all {
			w.Write([]string{
				r.IP,
				strconv.FormatBool(r.IsPrinter),
				r.Hostname,
				r.Model,
				r.Serial,
				r.Firmware,
				r.MAC,
				joinInts(r.OpenPorts),
				strings.Join(r.NetBIOS, "|"),
				r.SMB,
				strings.Join(r.MDNS, "|"),
				strings.Join(r.Findings, "|"),
			})
		}
		w.Flush()
	default:
		printText(out, all)
	}
}

func joinInts(s []int) string {
	var parts []string
	for _, n := range s {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}

func printText(w io.Writer, all []*Result) {
	printers := 0
	for _, r := range all {
		if r.IsPrinter {
			printers++
		}
	}
	fmt.Fprintln(w, strings.Repeat("═", 78))
	fmt.Fprintf(w, "  Found %d printer(s) / %d host(s)\n", printers, len(all))
	fmt.Fprintln(w, strings.Repeat("═", 78))

	for _, r := range all {
		marker := ""
		if r.IsPrinter {
			marker = " ★ PRINTER"
		}
		fmt.Fprintf(w, "\n┌─ %s%s\n", r.IP, marker)

		if r.Hostname != "" {
			fmt.Fprintf(w, "│  Hostname  : %s\n", r.Hostname)
		}
		if r.MAC != "" {
			fmt.Fprintf(w, "│  MAC       : %s\n", r.MAC)
		}
		if r.Model != "" {
			fmt.Fprintf(w, "│  Model     : %s\n", r.Model)
		}
		if r.Serial != "" {
			fmt.Fprintf(w, "│  Serial    : %s\n", r.Serial)
		}
		if r.Firmware != "" {
			fmt.Fprintf(w, "│  Firmware  : %s\n", r.Firmware)
		}
		if len(r.NetBIOS) > 0 {
			fmt.Fprintf(w, "│  NetBIOS   : %s\n", strings.Join(r.NetBIOS, ", "))
		}
		if r.SMB != "" {
			fmt.Fprintf(w, "│  SMB/445   : %s\n", r.SMB)
		}
		if r.WSD != "" {
			fmt.Fprintf(w, "│  WSD       : %s\n", r.WSD)
		}
		if len(r.MDNS) > 0 {
			fmt.Fprintf(w, "│  mDNS      : %s\n", strings.Join(r.MDNS, ", "))
		}
		if len(r.OpenPorts) > 0 {
			fmt.Fprintf(w, "│  Ports     : %v\n", r.OpenPorts)
		}

		if len(r.IPP) > 0 {
			fmt.Fprintf(w, "│  IPP:\n")
			for _, k := range sortedKeys(r.IPP) {
				fmt.Fprintf(w, "│    %s = %s\n", k, truncate(r.IPP[k], 100))
			}
		}
		if len(r.PJL) > 0 {
			fmt.Fprintf(w, "│  PJL:\n")
			for _, k := range sortedKeys(r.PJL) {
				fmt.Fprintf(w, "│    %s: %s\n", k, truncate(r.PJL[k], 200))
			}
		}
		if len(r.SNMP) > 0 {
			fmt.Fprintf(w, "│  SNMP:\n")
			for _, k := range sortedKeys(r.SNMP) {
				fmt.Fprintf(w, "│    %s = %s\n", k, truncate(r.SNMP[k], 120))
			}
		}
		if len(r.LPDQueue) > 0 {
			fmt.Fprintf(w, "│  LPD Queue : %s\n", strings.Join(r.LPDQueue, ", "))
		}
		if len(r.Banners) > 0 {
			fmt.Fprintf(w, "│  Banners:\n")
			var ports []string
			for p := range r.Banners {
				ports = append(ports, p)
			}
			sort.Strings(ports)
			for _, p := range ports {
				fmt.Fprintf(w, "│    [%s] %s\n", p, truncate(r.Banners[p], 150))
			}
		}
		if len(r.Findings) > 0 {
			fmt.Fprintf(w, "│  ⚠ Findings:\n")
			for _, f := range r.Findings {
				fmt.Fprintf(w, "│    - %s\n", f)
			}
		}
		fmt.Fprintln(w, "└─")
	}

	fmt.Fprintln(w, strings.Repeat("═", 78))
	fmt.Fprintf(w, "  Scan completed at %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintln(w, strings.Repeat("═", 78))
}

func sortedKeys(m map[string]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
