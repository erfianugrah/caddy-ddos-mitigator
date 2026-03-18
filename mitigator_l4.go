// Package ddosmitigator — Layer 4 connection handler.
//
// Registers as layer4.handlers.ddos_mitigator. Checks incoming TCP connections
// against the shared IP jail and force-drops jailed IPs with SetLinger(0) + RST,
// bypassing TIME_WAIT state accumulation.
//
// Runs pre-TLS in the caddy-l4 handler chain. Shares the same ipJail instance
// as the L7 handler via the package-level jail registry.
package ddosmitigator

import (
	"errors"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(DDOSMitigatorL4{})
}

// ─── Module Struct ──────────────────────────────────────────────────

// DDOSMitigatorL4 is the Layer 4 connection handler for DDoS mitigation.
// It checks incoming connections against the IP jail and force-drops
// jailed IPs before TLS handshake.
type DDOSMitigatorL4 struct {
	// JailFile is the path to the shared jail JSON file.
	// Must match the L7 handler's jail_file to share state.
	JailFile string `json:"jail_file,omitempty"`

	jail   *ipJail
	cidr   *cidrAggregator
	logger *zap.Logger
}

// ─── Caddy Module Interface ─────────────────────────────────────────

func (DDOSMitigatorL4) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.ddos_mitigator",
		New: func() caddy.Module { return new(DDOSMitigatorL4) },
	}
}

// ─── Provision ──────────────────────────────────────────────────────

func (m *DDOSMitigatorL4) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// Look up the shared jail from the registry (created by L7 handler).
	// If no L7 handler is configured, create a standalone jail.
	if m.JailFile != "" {
		m.jail = getOrCreateJail(m.JailFile)
		m.cidr = getCIDR(m.JailFile) // may be nil if L7 hasn't provisioned yet

		// Load entries from disk if the L7 handler hasn't done so already.
		if m.jail.Count() == 0 {
			if err := readJailFile(m.JailFile, m.jail); err != nil {
				m.logger.Warn("L4: failed to load jail file",
					zap.String("path", m.JailFile), zap.Error(err))
			}
		}
	} else {
		m.jail = newIPJail()
	}

	m.logger.Info("ddos_mitigator L4 provisioned",
		zap.String("jail_file", m.JailFile),
		zap.Int64("jail_entries", m.jail.Count()))

	return nil
}

// ─── Handle (Hot Path) ──────────────────────────────────────────────

// Handle checks the connection's remote IP against the jail. Jailed IPs
// get an immediate TCP RST via SetLinger(0). Clean connections pass to
// the next handler (typically TLS termination).
//
// Implements layer4.NextHandler (middleware pattern, receives next handler).
func (m *DDOSMitigatorL4) Handle(cx *layer4.Connection, next layer4.Handler) error {
	addr, ok := extractRemoteIP(cx.Conn.RemoteAddr())
	if !ok {
		m.logger.Debug("L4: could not extract remote IP, passing through",
			zap.String("remote_addr", cx.Conn.RemoteAddr().String()))
		return next.Handle(cx)
	}

	if m.jail.IsJailed(addr) || (m.cidr != nil && m.cidr.IsPromoted(addr)) {
		m.logger.Debug("L4 dropping jailed connection",
			zap.String("ip", addr.String()))
		return forceDropL4(cx)
	}

	return next.Handle(cx)
}

// ─── Force Drop ─────────────────────────────────────────────────────

// forceDropL4 severs a layer4 connection with TCP RST, bypassing TIME_WAIT.
func forceDropL4(cx *layer4.Connection) error {
	return forceDropConn(cx.Conn)
}

// forceDropConn sets SO_LINGER=0 and closes the connection, causing the
// kernel to send a TCP RST and immediately reclaim the file descriptor.
// Works by unwrapping through potential proxy_protocol / TLS wrappers.
func forceDropConn(conn net.Conn) error {
	// Unwrap to find the underlying *net.TCPConn
	inner := conn
	for {
		if u, ok := inner.(interface{ NetConn() net.Conn }); ok {
			inner = u.NetConn()
		} else {
			break
		}
	}

	if tcp, ok := inner.(*net.TCPConn); ok {
		// SO_LINGER=0: kernel discards buffers, sends RST, skips TIME_WAIT.
		// Go sets SOCK_NONBLOCK on all sockets, so this is non-blocking.
		_ = tcp.SetLinger(0)
		_ = tcp.Close()
	} else {
		// Fallback: graceful close for non-TCP (e.g. Unix sockets in tests)
		_ = conn.Close()
	}

	return errors.New("ddos_mitigator: connection dropped (L4)")
}

// ─── IP Extraction ──────────────────────────────────────────────────

// extractRemoteIP extracts a netip.Addr from a net.Addr.
// Handles *net.TCPAddr directly and falls back to parsing the string.
func extractRemoteIP(addr net.Addr) (netip.Addr, bool) {
	if ta, ok := addr.(*net.TCPAddr); ok {
		a, ok := netip.AddrFromSlice(ta.IP)
		if ok {
			return a.Unmap(), true
		}
		return netip.Addr{}, false
	}

	// Fallback: parse "host:port" string
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ─── Caddyfile Parsing ──────────────────────────────────────────────

// UnmarshalCaddyfile sets up the L4 handler from Caddyfile tokens.
// Used within a layer4 listener_wrappers block:
//
//	{
//	    servers {
//	        listener_wrappers {
//	            layer4 {
//	                route {
//	                    ddos_mitigator {
//	                        jail_file /data/waf/jail.json
//	                    }
//	                }
//	            }
//	        }
//	    }
//	}
func (m *DDOSMitigatorL4) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume handler name

	for d.NextBlock(0) {
		switch d.Val() {
		case "jail_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.JailFile = d.Val()
		default:
			return d.Errf("unknown ddos_mitigator L4 directive: %s", d.Val())
		}
	}
	return nil
}

// ─── Interface Guards ───────────────────────────────────────────────

var (
	_ caddy.Module          = (*DDOSMitigatorL4)(nil)
	_ caddy.Provisioner     = (*DDOSMitigatorL4)(nil)
	_ layer4.NextHandler    = (*DDOSMitigatorL4)(nil)
	_ caddyfile.Unmarshaler = (*DDOSMitigatorL4)(nil)
)
