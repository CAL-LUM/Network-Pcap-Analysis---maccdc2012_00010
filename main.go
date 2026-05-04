package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// tshark runs a tshark command against the pcap and returns as a string
func tshark(pcap string, args ...string) string {
	out, _ := exec.Command("tshark", append([]string{"-r", pcap}, args...)...).CombinedOutput()
	return clip(strings.TrimSpace(string(out)), 50)
}

// clip limits output to max lines to keep reports readable
func clip(s string, max int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= max {
		return s
	}
	return strings.Join(append(lines[:max], fmt.Sprintf("... [%d lines omitted]", len(lines)-max)), "\n")
}

// fields builds the tshark field extraction arguments for tabular output
func fields(args ...string) []string {
	out := []string{"-T", "fields", "-E", "header=y", "-E", "separator=\t"}
	for _, a := range args {
		out = append(out, "-e", a)
	}
	return out
}

type section struct{ title, note, data string }

// report formats and writes a single CA report file
func report(path, title, refs string, sections []section) {
	var b strings.Builder
	bar := strings.Repeat("═", 78)
	thin := strings.Repeat("─", 78)

	// Write report header
	b.WriteString(fmt.Sprintf("%s\n  %s\n  %s\n  Generated: %s\n%s\n\n", bar, title, refs, time.Now().Format("2006-01-02 15:04:05"), bar))

	for _, s := range sections {
		b.WriteString(fmt.Sprintf("%s\n%s\n", strings.ToUpper(s.title), thin))
		if s.note != "" {
			b.WriteString(s.note + "\n" + thin + "\n")
		}
		// error handling
		if strings.TrimSpace(s.data) == "" {
			b.WriteString("  [no matching packets]\n")
		} else {
			for _, l := range strings.Split(s.data, "\n") {
				b.WriteString("  " + l + "\n")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString(bar + "\n")
	os.WriteFile(path, []byte(b.String()), 0644)
	fmt.Printf("  ✓ %s\n", path)
}

// ca1 extracts DNS zone transfer evidence (AXFR requests, responses, extracted hostnames)
func ca1(pcap, dir string) {
	fmt.Println("[CA1] DNS Zone Transfer")
	report(filepath.Join(dir, "CA1_DNS_Zone_Transfer.txt"),
		"CA1 - Unrestricted DNS Zone Transfer",
		"CWE200 T1590.002 RFC 5936",
		[]section{
			{"summary", "", "Attacker: 192.168.202.79  Victims: 192.168.{21,22,23,25,27,28}.25\nTool: Nmap dns-zone-transfer NSE Protocol: DNS UDP 53 (AXFR query type 252)\nImpact: All 6 zones returned. EMR, TicketsCAD, PA-AD hostnames exposed. Root cause of CA3 & CA4."},
			// Filter for AXFR query type 252 - the DNS zone transfer request
			{"axfr requests", "Attacker AXFR queries to each regional DNS server.",
				tshark(pcap, append([]string{"-Y", "dns.qry.type==252"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "dns.qry.name")...)...)},
			// Responses with >5 answers indicate a full zone was returned
			{"axfr responses - zone data returned", "DNS responses with >5 answers indicate fulfilled zone transfers.",
				tshark(pcap, append([]string{"-Y", "dns.flags.response==1 && dns.count.answers>5"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "dns.count.answers", "dns.resp.name")...)...)},
			// Extract hostname/IP pairs from zone transfer responses
			{"hostnames & ips extracted", "A records returned across all zone transfers.",
				tshark(pcap, append([]string{"-Y", "dns.flags.response==1 && dns.count.answers>5"}, fields("dns.resp.name", "dns.a")...)...)},
			// SMTP EHLO nmap.scanme.org confirms the attacker used Nmap
			{"tool attribution - nmap ehlo", "SMTP EHLO nmap.scanme.org fingerprints the attacker toolset.",
				tshark(pcap, append([]string{"-Y", "smtp contains \"nmap.scanme.org\""}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "smtp.req.parameter")...)...)},
		})
}

// ca2 extracts FreePBX admin session and SIP surveillance evidence
func ca2(pcap, dir string) {
	fmt.Println("[CA2] FreePBX VoIP Compromise")
	report(filepath.Join(dir, "CA2_FreePBX_VoIP_Compromise.txt"),
		"CA2 - FreePBX: Authenticated Admin Session & SIP Call Surveillance",
		"CWE-284 CWE-522 CVE-2012-0781 CVE-2012-0788 T1078",
		[]section{
			{"summary", "", "Attackers: 192.168.202.110 (HTTP) 192.168.202.76 (SIP) Victim: 192.168.229.156\nSoftware: Apache/2.2.3 + PHP/5.1.6 (both EOL) Ports: HTTP :80, SIP UDP :5060\nImpact: Pre-capture admin session confirmed. SIP SUBSCRIBE accepted, persistent ext.6001 surveillance."},
			// All HTTP traffic to the FreePBX admin panel
			{"http - admin panel traffic", "All HTTP to/from FreePBX server.",
				tshark(pcap, append([]string{"-Y", "http && ip.addr==192.168.229.156"}, fields("frame.number", "frame.time", "ip.src", "http.request.method", "http.request.uri", "http.response.code")...)...)},
			// 200 OK with set-cookie confirms an authenticated session was active
			{"authenticated session - http 200 + cookies", "200 OK responses confirming valid admin session cookie.",
				tshark(pcap, append([]string{"-Y", "http.response.code==200 && ip.addr==192.168.229.156"}, fields("frame.number", "frame.time", "ip.src", "http.response.code", "http.set_cookie")...)...)},
			// REGISTER rejected - attacker could not create a SIP extension
			{"sip register (rejected)", "Attacker attempted SIP registration - server rejected.",
				tshark(pcap, append([]string{"-Y", "sip.Method==\"REGISTER\" && ip.addr==192.168.229.156"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "sip.Method", "sip.Status-Code", "sip.to.user")...)...)},
			// SUBSCRIBE accepted - attacker now receives call state updates without re-authenticating
			{"sip subscribe (accepted)", "SUBSCRIBE accepted 200 OK - call surveillance established on ext.6001.",
				tshark(pcap, append([]string{"-Y", "sip.Method==\"SUBSCRIBE\" && ip.addr==192.168.229.156"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "sip.Method", "sip.Status-Code", "sip.to.user")...)...)},
			// NOTIFY confirms the server is actively pushing call events to the attacker
			{"sip notify - server pushing call state", "Server actively delivers real-time call updates to attacker.",
				tshark(pcap, append([]string{"-Y", "sip.Method==\"NOTIFY\" && ip.addr==192.168.229.156"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "sip.Method", "sip.to.user")...)...)},
		})
}

// ca3 extracts TicketsCAD RFI, credential abuse, and dispatch injection evidence
func ca3(pcap, dir string) {
	fmt.Println("[CA3] TicketsCAD Emergency Dispatch")
	report(filepath.Join(dir, "CA3_TicketsCAD_Dispatch.txt"),
		"CA3 - TicketsCAD: PHP RFI, Credential Abuse & Dispatch Record Injection",
		"CWE-98 CWE-200 CWE-522 CWE-79 CVE-2009-2265 T1190 T1505",
		[]section{
			{"summary", "", "Attacker: 192.168.202.102  |  Victim: 192.168.23.202  |  Protocol: HTTP :80\nSoftware: Apache/2.2.17 + PHP/5.3.5  |  1,844 HTTP requests observed\nImpact: Live dispatch records tampered. config.txt exposed. SQL errors disclose query structure."},
			// config.txt returned a 200 OK without any authentication
			{"config.txt - unauthenticated exposure", "Configuration file served without authentication.",
				tshark(pcap, append([]string{"-Y", "http.request.uri contains \"config\" && ip.addr==192.168.23.202"}, fields("frame.number", "frame.time", "ip.src", "http.request.uri", "http.response.code")...)...)},
			// URL-encoding in parameters indicates RFI attempts
			{"php rfi probes", "URL-encoded http:// in request URIs indicates RFI endpoint testing.",
				tshark(pcap, append([]string{"-Y", "http.request.uri contains \"http%3A\" && ip.addr==192.168.23.202"}, fields("frame.number", "frame.time", "ip.src", "http.request.uri")...)...)},
			// POST requests injecting attacker controlled content into dispatch records
			{"post requests - dispatch record injection", "POST submissions injecting attacker URLs into live dispatch fields.",
				tshark(pcap, append([]string{"-Y", "http.request.method==\"POST\" && ip.addr==192.168.23.202"}, fields("frame.number", "frame.time", "ip.src", "http.request.uri", "http.response.code")...)...)},
			// phpMyAdmin accessible without IP restriction - full DB access risk
			{"phpmyadmin access", "phpMyAdmin panel accessible across the network without IP restriction.",
				tshark(pcap, append([]string{"-Y", "http.request.uri contains \"phpmyadmin\" && ip.addr==192.168.23.202"}, fields("frame.number", "frame.time", "ip.src", "http.request.uri", "http.response.code")...)...)},
			// FCKEditor file upload exploit - 404 because PHP connector was absent
			{"fckeditor webshell attempt (cve-2009-2265)", "File upload exploitation attempt - 404 returned (PHP connector absent).",
				tshark(pcap, append([]string{"-Y", "http.request.uri contains \"FCKeditor\" && ip.addr==192.168.23.202"}, fields("frame.number", "frame.time", "ip.src", "http.request.uri", "http.response.code")...)...)},
		})
}

// ca4 extracts SMB null session, DCE/RPC enumeration, and pivot host evidence
func ca4(pcap, dir string) {
	fmt.Println("[CA4] SMB Null Session & Domain Controller")
	report(filepath.Join(dir, "CA4_SMB_Null_Session_DC.txt"),
		"CA4 - SMB Null Session & Active Directory Enumeration (PA-AD)",
		"CWE-306 CWE-284 T1021.002 T1003.006",
		[]section{
			{"summary", "", "Attacker: 192.168.202.110 + pivot 192.168.204.45  |  Victim: 192.168.28.25 (PA-AD)\nPorts: SMB TCP :445, RPC TCP :135  |  Vuln: RestrictAnonymous not set to 2\nImpact: IPC$ mounted anonymously. DRSUAPI exposed - DCSync possible with any domain credential."},
			// Blank smb.account + NT_STATUS_SUCCESS = unauthenticated null session accepted
			{"ipc$ null session mount", "Blank account + NT_STATUS_SUCCESS confirms unauthenticated IPC$ access.",
				tshark(pcap, append([]string{"-Y", "smb.path contains \"IPC\" && ip.addr==192.168.28.25"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "smb.path", "smb.nt_status", "smb.account")...)...)},
			// Full SMBv1 session overview to the domain controller
			{"smb traffic overview", "All SMBv1 frames to/from domain controller.",
				tshark(pcap, append([]string{"-Y", "smb && ip.addr==192.168.28.25"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "smb.cmd", "smb.nt_status")...)...)},
			// DRSUAPI UUID in DCE/RPC responses confirms DCSync attack surface is present
			{"dce/rpc - drsuapi exposure", "DRSUAPI presence enables DCSync - all NTLM hashes extractable as legitimate DC replication traffic.",
				tshark(pcap, append([]string{"-Y", "dcerpc && ip.addr==192.168.28.25"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "dcerpc.opnum", "dcerpc.cn_bind_to_uuid")...)...)},
		})
}

// ca5 extracts Cisco gateway SSH session and SNMP probe evidence
func ca5(pcap, dir string) {
	fmt.Println("[CA5] Cisco Gateway - SSHv1 & SNMP")
	report(filepath.Join(dir, "CA5_Cisco_Gateway_SSHv1_SNMP.txt"),
		"CA5 - Cisco Gateway: SSHv1 Session Establishment & SNMP Default String Probe",
		"CWE-798 CVE-2001-0572 T1021.004 T1046",
		[]section{
			{"summary", "", "Attacker: 192.168.202.110  |  Victim: 192.168.28.254 (Cisco gateway)\nPorts: SSH TCP :22, SNMP UDP :161  |  Banner: SSH-1.99-Cisco-1.25 (SSHv1/v2 dual mode)\nImpact: 1 session fully established via DH exchange. Commands encrypted - unrecoverable. Gateway controls all regional routing."},
			// ssh.protocol field reveals the server banner confirming SSHv1 support
			{"ssh version banner", "Server banner confirms SSHv1 support - cryptographically broken per RFC 4253.",
				tshark(pcap, append([]string{"-Y", "ssh && ip.addr==192.168.28.254"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "ssh.protocol")...)...)},
			// DH message codes confirm a full key exchange completed - session is encrypted
			{"diffie-hellman key exchange", "DH exchange confirms encrypted session established. Post-exchange commands unrecoverable.",
				tshark(pcap, append([]string{"-Y", "ssh.message_code && ip.addr==192.168.28.254"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "ssh.message_code")...)...)},
			// PSH+ACK packets carry actual data - confirms commands were actively issued
			{"ssh data packets (psh+ack)", "Encrypted data-carrying packets confirming active commands were issued.",
				tshark(pcap, append([]string{"-Y", "tcp.port==22 && ip.addr==192.168.28.254 && tcp.flags.push==1"}, fields("frame.number", "frame.time", "ip.src", "ip.dst", "tcp.len")...)...)},
		})
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func main() {
	fmt.Println("PCAP Critical Attacks - maccdc2012")

	// Default to pcap in the same directory as the binary; allow CLI override
	pcap := "maccdc2012_00010.pcap"
	if len(os.Args) > 1 {
		pcap = os.Args[1]
	} else if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), pcap); fileExists(p) {
			pcap = p
		}
	}

	if !fileExists(pcap) {
		fmt.Printf("ERROR: pcap not found: %s\nUsage: %s [path/to/capture.pcap]\n", pcap, os.Args[0])
		os.Exit(1)
	}

	// Create output directory if it doesn't exist
	outDir := "critical_attack_reports"
	os.MkdirAll(outDir, 0755)
	fmt.Printf("Pcap   : %s\nOutput : %s\n\n", pcap, outDir)

	start := time.Now()
	ca1(pcap, outDir)
	ca2(pcap, outDir)
	ca3(pcap, outDir)
	ca4(pcap, outDir)
	ca5(pcap, outDir)
	fmt.Printf("\nDone in %.1fs\n", time.Since(start).Seconds())
}
