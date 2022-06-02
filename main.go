package main

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var hexDigit = "0123456789abcdef"
var rIp = []string{"219.141.136.12", "202.106.50.1", "221.179.155.161", "202.96.209.133", "210.22.97.1", "211.136.112.200", "58.60.188.222", "210.21.196.6", "120.196.165.24"}
var rName = []string{"北京电信", "北京联通", "北京移动", "上海电信", "上海联通", "上海移动", "广州电信", "广州联通", "广州移动"}
var rAS = map[uint32]string{4134: "AS4134  电信163  [普通线路]", 4809: "AS4809  电信CN2  [优质线路]", 4837: "AS4837  联通169  [普通线路]", 9929: "AS9929  联通CUII [优质线路]", 9808: "AS9808  移动CMI  [普通线路]", 58453: "AS58453 移动CMI  [普通线路]"}

// IP holds the BGP origin information about a given IP address.
type IP struct {
	ASNum     uint32 `json:"as_num"`
	IP        string `json:"ip"`
	BGPPrefix string `json:"bgp_prefix"`
	Country   string `json:"country"`
	Registry  string `json:"registry"`
	Allocated string `json:"allocated"`
	ASName    string `json:"as_name"`
}

// ASN holds the description of a BGP ASN.
type ASN struct {
	ASNum     uint32 `json:"as_num"`
	Country   string `json:"country"`
	Registry  string `json:"registry"`
	Allocated string `json:"allocated"`
	ASName    string `json:"as_name"`
}

func reverseAddr(addr string) (net.IP, string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, "", fmt.Errorf("unrecognized address: %s", addr)
	}
	if v4 := ip.To4(); v4 != nil {
		buf := make([]byte, 0, net.IPv4len*4)
		// Add it, in reverse, to the buffer
		for i := len(v4) - 1; i >= 0; i-- {
			buf = strconv.AppendInt(buf, int64(v4[i]), 10)
			// Only append a trailing "." if this isn't the final octet
			if i > 0 {
				buf = append(buf, '.')
			}
		}
		return ip, string(buf), nil
	}

	buf := make([]byte, 0, net.IPv6len*4)
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF])
		buf = append(buf, '.')
		buf = append(buf, hexDigit[v>>4])
		if i > 0 {
			buf = append(buf, '.')
		}
	}
	return ip, string(buf), nil
}

// Parse the text output from the IP to ASN service and return an IP.
func parseOrigin(txt string) (IP, error) {
	fields := strings.Split(txt, "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	asn, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil && fields[0] != "NA" {
		return IP{}, errors.New("AS parsing failed")
	}

	return IP{
		ASNum:     uint32(asn),
		BGPPrefix: fields[1],
		Country:   fields[2],
		Registry:  fields[3],
		Allocated: fields[4],
	}, nil
}

func Resolver(host string) ([]string, error) {
	resolver := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: 1 * time.Second,
			}
			return dialer.DialContext(ctx, "tcp", "8.8.8.8:53")
		},
	}
	return resolver.LookupTXT(context.Background(), host)
}

// LookupIP queries Team Cymru's IP to ASN mapping service and returns BGP
// origin information about the IP.
func LookupIP(ip string) (IP, error) {
	parsedIP, rev, err := reverseAddr(ip)
	if err != nil {
		return IP{}, errors.New("reversing IP failed")
	}

	if parsedIP.IsPrivate() {
		return IP{}, nil
	}

	var zone string
	//parsedIP := net.ParseIP(ip)
	if v4 := parsedIP.To4(); v4 != nil {
		zone = "origin.asn.cymru.com"
	} else {
		zone = "origin6.asn.cymru.com"
	}

	recs, err := Resolver(fmt.Sprintf("%s.%s.", rev, zone))
	if err != nil {
		return IP{}, errors.New("DNS lookup failed")
	}

	origin, err := parseOrigin(recs[0])
	if err != nil {
		return IP{}, errors.New("parse failed")
	}
	origin.IP = ip
	if asn, err := LookupASN(fmt.Sprintf("AS%d", origin.ASNum)); err == nil {
		origin.ASName = asn.ASName
	}

	return origin, nil
}

// Parse the text output from the IP to ASN service and return an ASN.
func parseASN(txt string) (ASN, error) {
	fields := strings.Split(txt, "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	asn, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil && fields[0] != "NA" {
		return ASN{}, errors.New("AS parsing failed")
	}

	return ASN{
		ASNum:     uint32(asn),
		Country:   fields[1],
		Registry:  fields[2],
		Allocated: fields[3],
		ASName:    fields[4],
	}, nil
}

// LookupASN queries the IP to ASN service to fetch an AS description.
func LookupASN(asn string) (ASN, error) {
	if strings.ToLower(asn[0:2]) != "as" {
		asn = "AS" + asn
	}
	q := fmt.Sprintf("%s.asn.cymru.com.", asn)
	res, err := net.LookupTXT(q)
	if err != nil {
		return ASN{}, errors.New("DNS lookup failed")
	}
	as, err := parseASN(res[0])
	if err != nil {
		return ASN{}, errors.New("parse failed")
	}
	return as, nil
}

// DefaultConfig is the default configuration for Tracer.
var DefaultConfig = Config{
	Delay:    50 * time.Millisecond,
	Timeout:  500 * time.Millisecond,
	MaxHops:  30,
	Count:    1,
	Networks: []string{"ip4:icmp", "ip4:ip"},
}

// DefaultTracer is a tracer with DefaultConfig.
var DefaultTracer = &Tracer{
	Config: DefaultConfig,
}

// Config is a configuration for Tracer.
type Config struct {
	Delay    time.Duration
	Timeout  time.Duration
	MaxHops  int
	Count    int
	Networks []string
	Addr     *net.IPAddr
}

// Tracer is a traceroute tool based on raw IP packets.
// It can handle multiple sessions simultaneously.
type Tracer struct {
	Config

	once sync.Once
	conn *net.IPConn
	err  error

	mu   sync.RWMutex
	sess map[string][]*Session
	seq  uint32
}

// Trace starts sending IP packets increasing TTL until MaxHops and calls h for each reply.
func (t *Tracer) Trace(ctx context.Context, ip net.IP, h func(reply *Reply)) error {
	sess, err := t.NewSession(ip)
	if err != nil {
		return err
	}
	defer sess.Close()

	delay := time.NewTicker(t.Delay)
	defer delay.Stop()

	max := t.MaxHops
	for n := 0; n < t.Count; n++ {
		for ttl := 1; ttl <= t.MaxHops && ttl <= max; ttl++ {
			err = sess.Ping(ttl)
			if err != nil {
				return err
			}
			select {
			case <-delay.C:
			case r := <-sess.Receive():
				if max > r.Hops && ip.Equal(r.IP) {
					max = r.Hops
				}
				h(r)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if sess.isDone(max) {
		return nil
	}
	deadline := time.After(t.Timeout)
	for {
		select {
		case r := <-sess.Receive():
			if max > r.Hops && ip.Equal(r.IP) {
				max = r.Hops
			}
			h(r)
			if sess.isDone(max) {
				return nil
			}
		case <-deadline:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// NewSession returns new tracer session.
func (t *Tracer) NewSession(ip net.IP) (*Session, error) {
	t.once.Do(t.init)
	if t.err != nil {
		return nil, t.err
	}
	return newSession(t, shortIP(ip)), nil
}

func (t *Tracer) init() {
	for _, network := range t.Networks {
		t.conn, t.err = t.listen(network, t.Addr)
		if t.err != nil {
			continue
		}
		go t.serve(t.conn)
		return
	}
}

func (t *Tracer) listen(network string, laddr *net.IPAddr) (*net.IPConn, error) {
	conn, err := net.ListenIP(network, laddr)
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = raw.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Close closes listening socket.
// Tracer can not be used after Close is called.
func (t *Tracer) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
	}
}

func (t *Tracer) serve(conn *net.IPConn) error {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromIP(buf)
		if err != nil {
			return err
		}
		err = t.serveData(from.IP, buf[:n])
		if err != nil {
			continue
		}
	}
}

func (t *Tracer) serveData(from net.IP, b []byte) error {
	if from.To4() == nil {
		// TODO: implement ProtocolIPv6ICMP
		return errUnsupportedProtocol
	}
	now := time.Now()
	msg, err := icmp.ParseMessage(ProtocolICMP, b)
	if err != nil {
		return err
	}
	if msg.Type == ipv4.ICMPTypeEchoReply {
		echo := msg.Body.(*icmp.Echo)
		return t.serveReply(from, &packet{from, uint16(echo.ID), 1, now})
	}
	b = getReplyData(msg)
	if len(b) < ipv4.HeaderLen {
		return errMessageTooShort
	}
	switch b[0] >> 4 {
	case ipv4.Version:
		ip, err := ipv4.ParseHeader(b)
		if err != nil {
			return err
		}
		return t.serveReply(ip.Dst, &packet{from, uint16(ip.ID), ip.TTL, now})
	case ipv6.Version:
		ip, err := ipv6.ParseHeader(b)
		if err != nil {
			return err
		}
		return t.serveReply(ip.Dst, &packet{from, uint16(ip.FlowLabel), ip.HopLimit, now})
	default:
		return errUnsupportedProtocol
	}
}

func (t *Tracer) sendRequest(dst net.IP, ttl int) (*packet, error) {
	id := uint16(atomic.AddUint32(&t.seq, 1))
	b := newPacket(id, dst, ttl)
	req := &packet{dst, id, ttl, time.Now()}
	_, err := t.conn.WriteToIP(b, &net.IPAddr{IP: dst})
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (t *Tracer) addSession(s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil {
		t.sess = make(map[string][]*Session)
	}
	t.sess[string(s.ip)] = append(t.sess[string(s.ip)], s)
}

func (t *Tracer) removeSession(s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.sess[string(s.ip)]
	for i, it := range a {
		if it == s {
			t.sess[string(s.ip)] = append(a[:i], a[i+1:]...)
			return
		}
	}
}

func (t *Tracer) serveReply(dst net.IP, res *packet) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	a := t.sess[string(shortIP(dst))]
	for _, s := range a {
		s.handle(res)
	}
	return nil
}

// Session is a tracer session.
type Session struct {
	t  *Tracer
	ip net.IP
	ch chan *Reply

	mu     sync.RWMutex
	probes []*packet
}

// NewSession returns new session.
func NewSession(ip net.IP) (*Session, error) {
	return DefaultTracer.NewSession(ip)
}

func newSession(t *Tracer, ip net.IP) *Session {
	s := &Session{
		t:  t,
		ip: ip,
		ch: make(chan *Reply, 64),
	}
	t.addSession(s)
	return s
}

// Ping sends single ICMP packet with specified TTL.
func (s *Session) Ping(ttl int) error {
	req, err := s.t.sendRequest(s.ip, ttl+1)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.probes = append(s.probes, req)
	s.mu.Unlock()
	return nil
}

// Receive returns channel to receive ICMP replies.
func (s *Session) Receive() <-chan *Reply {
	return s.ch
}

// isDone returns true if session does not have unresponsed requests with TTL <= ttl.
func (s *Session) isDone(ttl int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.probes {
		if r.TTL <= ttl {
			return false
		}
	}
	return true
}

func (s *Session) handle(res *packet) {
	now := res.Time
	n := 0
	var req *packet
	s.mu.Lock()
	for _, r := range s.probes {
		if now.Sub(r.Time) > s.t.Timeout {
			continue
		}
		if r.ID == res.ID {
			req = r
			continue
		}
		s.probes[n] = r
		n++
	}
	s.probes = s.probes[:n]
	s.mu.Unlock()
	if req == nil {
		return
	}
	hops := req.TTL - res.TTL + 1
	if hops < 1 {
		hops = 1
	}
	select {
	case s.ch <- &Reply{
		IP:   res.IP,
		RTT:  res.Time.Sub(req.Time),
		Hops: hops,
	}:
	default:
	}
}

// Close closes tracer session.
func (s *Session) Close() {
	s.t.removeSession(s)
}

type packet struct {
	IP   net.IP
	ID   uint16
	TTL  int
	Time time.Time
}

func shortIP(ip net.IP) net.IP {
	if v := ip.To4(); v != nil {
		return v
	}
	return ip
}

func getReplyData(msg *icmp.Message) []byte {
	switch b := msg.Body.(type) {
	case *icmp.TimeExceeded:
		return b.Data
	case *icmp.DstUnreach:
		return b.Data
	case *icmp.ParamProb:
		return b.Data
	}
	return nil
}

var (
	errMessageTooShort     = errors.New("message too short")
	errUnsupportedProtocol = errors.New("unsupported protocol")
	errNoReplyData         = errors.New("no reply data")
)

func newPacket(id uint16, dst net.IP, ttl int) []byte {
	// TODO: reuse buffers...
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:  int(id),
			Seq: int(id),
		},
	}
	p, _ := msg.Marshal(nil)
	ip := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(p),
		TOS:      16,
		ID:       int(id),
		Dst:      dst,
		Protocol: ProtocolICMP,
		TTL:      ttl,
	}
	buf, err := ip.Marshal()
	if err != nil {
		return nil
	}
	return append(buf, p...)
}

// IANA Assigned Internet Protocol Numbers
const (
	ProtocolICMP     = 1
	ProtocolTCP      = 6
	ProtocolUDP      = 17
	ProtocolIPv6ICMP = 58
)

// Reply is a reply packet.
type Reply struct {
	IP   net.IP
	RTT  time.Duration
	Hops int
}

// Node is a detected network node.
type Node struct {
	IP  net.IP
	RTT []time.Duration
}

// Hop is a set of detected nodes.
type Hop struct {
	Nodes    []*Node
	Distance int
}

// Add adds node from r.
func (h *Hop) Add(r *Reply) *Node {
	var node *Node
	for _, it := range h.Nodes {
		if it.IP.Equal(r.IP) {
			node = it
			break
		}
	}
	if node == nil {
		node = &Node{IP: r.IP}
		h.Nodes = append(h.Nodes, node)
	}
	node.RTT = append(node.RTT, r.RTT)
	return node
}

// Trace is a simple traceroute tool using DefaultTracer.
func Trace(ip net.IP) ([]*Hop, error) {
	hops := make([]*Hop, 0, DefaultTracer.MaxHops)
	touch := func(dist int) *Hop {
		for _, h := range hops {
			if h.Distance == dist {
				return h
			}
		}
		h := &Hop{Distance: dist}
		hops = append(hops, h)
		return h
	}
	err := DefaultTracer.Trace(context.Background(), ip, func(r *Reply) {
		touch(r.Hops).Add(r)
	})
	if err != nil && err != context.DeadlineExceeded {
		return nil, err
	}
	sort.Slice(hops, func(i, j int) bool {
		return hops[i].Distance < hops[j].Distance
	})
	last := len(hops) - 1
	for i := last; i >= 0; i-- {
		h := hops[i]
		if len(h.Nodes) == 1 && ip.Equal(h.Nodes[0].IP) {
			continue
		}
		if i == last {
			break
		}
		i++
		node := hops[i].Nodes[0]
		i++
		for _, it := range hops[i:] {
			node.RTT = append(node.RTT, it.Nodes[0].RTT...)
		}
		hops = hops[:i]
		break
	}
	return hops, nil
}

// Main Trace
func trace(wg *sync.WaitGroup, i int) {
	defer wg.Done()
	hops, err := Trace(net.ParseIP(rIp[i]))
	if err != nil {
		log.Fatal(err)
		// return
	}
	for _, h := range hops {
		for _, n := range h.Nodes {
			ip, err := LookupIP(n.IP.String())
			if err != nil {
				// log.Fatal(err)
				continue
			}
			if ip.Country == "CN" && rAS[ip.ASNum] != "" {
				log.Printf("%v %-15s %-15s %-23s %dms\n", rName[i], rIp[i], n.IP.String(), rAS[ip.ASNum], n.RTT[0].Milliseconds())
				return
			}
		}
	}
}

func main() {
	var wg = sync.WaitGroup{}
	for i := range rIp {
		wg.Add(1)
		go trace(&wg, i)
	}
	wg.Wait()
}
