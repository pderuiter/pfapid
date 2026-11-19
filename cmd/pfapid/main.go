// Command pfapid is a REST API for OpenBSD pf, split into two processes:
//
//   - the privileged process (root) loads the config, owns the anchor
//     files, the state store and every pfctl call. It runs under
//     pledge("stdio rpath wpath cpath fattr proc exec") with unveil limited
//     to pfctl, the anchor directory and the state directory.
//   - the network process (user _pfapid) terminates mTLS and serves HTTP.
//     It receives its certificates and client list over a socketpair and
//     runs under pledge("stdio inet") with nothing unveiled: it cannot open
//     a single file.
//
// The network process is the same binary, re-executed with PFAPID_CHILD=1
// and the socket on fd 3.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pderuiter/pfapid/internal/api"
	"github.com/pderuiter/pfapid/internal/config"
	"github.com/pderuiter/pfapid/internal/ipc"
	"github.com/pderuiter/pfapid/internal/pfctl"
	"github.com/pderuiter/pfapid/internal/priv"
	"github.com/pderuiter/pfapid/internal/sandbox"
	"github.com/pderuiter/pfapid/internal/store"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pki" {
		if err := runPKI(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return
	}
	cfgPath := flag.String("f", "/etc/pfapid.json", "configuration file")
	check := flag.Bool("n", false, "check the configuration and certificates, then exit")
	debug := flag.Bool("d", false, "debug logging")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	lvl := slog.LevelInfo
	if *debug {
		lvl = slog.LevelDebug
	}
	if os.Getenv("PFAPID_CHILD") == "1" {
		log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})).With("proc", "net")
		os.Exit(runNet(log))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})).With("proc", "priv")
	os.Exit(runPriv(log, *cfgPath, *check, *debug))
}

// readMaterial reads the certificate files named in the config. It runs at
// startup and whenever the network process asks for fresh material.
func readMaterial(c *config.Config) (api.Material, error) {
	var m api.Material
	var err error
	if m.CertPEM, err = os.ReadFile(c.TLS.Cert); err != nil {
		return m, err
	}
	if m.KeyPEM, err = os.ReadFile(c.TLS.Key); err != nil {
		return m, err
	}
	m.CAs = map[string][]byte{}
	for name, path := range c.TLS.CABundles() {
		if m.CAs[name], err = os.ReadFile(path); err != nil { // #nosec G304 -- operator-configured path
			return m, err
		}
	}
	return m, nil
}

// expiryWarning is logged when the server certificate is close to expiry.
const expiryWarning = 14 * 24 * time.Hour

func runPriv(log *slog.Logger, cfgPath string, check, debug bool) int {
	cfg, mat, ok := loadChecked(log, cfgPath)
	if !ok {
		return 1
	}
	if check {
		fmt.Println("configuration OK")
		return 0
	}
	if !sandbox.Supported {
		log.Error("pfapid only runs on OpenBSD")
		return 1
	}
	if os.Geteuid() != 0 {
		log.Error("the privileged process must start as root")
		return 1
	}
	uid, gid, ok := unprivileged(log, cfg.User)
	if !ok {
		return 1
	}
	srv, ok := newPrivServer(log, cfg)
	if !ok {
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := srv.Reconcile(ctx); err != nil {
		// Keep running: the API is how an operator fixes a bad object.
		log.Error("reconcile at startup was incomplete", "err", err)
	} else {
		log.Info("reconciled kernel and anchor files with the committed state")
	}

	mine, child, ok := startChild(log, cfg, mat, debug, uid, gid)
	if !ok {
		return 1
	}
	// Key material is no longer needed in this process.
	clear(mat.KeyPEM)

	if err := sandboxPriv(log, cfg); err != nil {
		_ = child.Process.Kill()
		return 1
	}
	log.Info("started", "version", version, "listen", cfg.Listen, "child_pid", child.Process.Pid)
	return supervise(ctx, log, cfg, mine, srv, child)
}

// loadChecked loads the configuration and the TLS material and checks the
// clients against the CA bundles.
func loadChecked(log *slog.Logger, cfgPath string) (*config.Config, api.Material, bool) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Error("configuration", "err", err)
		return nil, api.Material{}, false
	}
	mat, err := readMaterial(cfg)
	var trust *api.Trust
	if err == nil {
		trust, err = api.NewTrust(mat)
	}
	if err == nil {
		_, err = api.New(nil, cfg.Clients, trust, cfg.RateLimit, cfg.RateBurst, log) // checks clients against the CA bundles
	}
	if err != nil {
		log.Error("tls material or clients", "err", err)
		return nil, api.Material{}, false
	}
	if left := time.Until(trust.NotAfter); left < expiryWarning {
		log.Warn("server certificate expires soon", "not_after", trust.NotAfter)
	}
	return cfg, mat, true
}

// unprivileged resolves the user the network process runs as; it must not
// be root.
func unprivileged(log *slog.Logger, name string) (uint32, uint32, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		log.Error("unprivileged user", "user", name, "err", err)
		return 0, 0, false
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	if uid == 0 || gid == 0 {
		log.Error("the unprivileged user must not be root", "user", name)
		return 0, 0, false
	}
	return uint32(uid), uint32(gid), true
}

func newPrivServer(log *slog.Logger, cfg *config.Config) (*priv.Server, bool) {
	st, err := store.Open(cfg.StateDir)
	if err != nil {
		log.Error("state directory", "err", err)
		return nil, false
	}
	workDir := filepath.Join(cfg.StateDir, "work")
	runner := pfctl.Exec{Path: cfg.Pfctl, FileDirs: []string{cfg.AnchorDir, workDir}, MainFile: cfg.BaseRuleset}
	// QoS is enabled by listing queue interfaces in the policy.
	baseRuleset, queueFile, qosFile := "", "", ""
	if len(cfg.Policy.QueueInterfaces) > 0 {
		baseRuleset, queueFile, qosFile = cfg.BaseRuleset, cfg.QueueFile, cfg.QoSFile
	}
	srv, err := priv.New(priv.Config{
		Policy:         cfg.Policy,
		ConfirmTimeout: cfg.ConfirmTimeout.Duration,
		AnchorDir:      cfg.AnchorDir,
		IncludeFile:    cfg.IncludeFile,
		WorkDir:        workDir,
		BaseRuleset:    baseRuleset,
		QueueFile:      queueFile,
		QoSFile:        qosFile,
	}, runner, st, log)
	if err != nil {
		log.Error("privileged side", "err", err)
		return nil, false
	}
	return srv, true
}

// startChild re-executes pfapid as the unprivileged network process with
// a socketpair on fd 3 and sends it the bootstrap message.
func startChild(log *slog.Logger, cfg *config.Config, mat api.Material, debug bool, uid, gid uint32) (*os.File, *exec.Cmd, bool) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Error("socketpair", "err", err)
		return nil, nil, false
	}
	mine := os.NewFile(uintptr(fds[0]), "ipc")
	theirs := os.NewFile(uintptr(fds[1]), "ipc-child")
	exe, err := os.Executable()
	if err != nil || !filepath.IsAbs(exe) {
		log.Error("cannot determine own executable path; start pfapid with an absolute path", "err", err)
		return nil, nil, false
	}
	args := []string{exe}
	if debug {
		args = append(args, "-d")
	}
	child := &exec.Cmd{
		Path:       exe,
		Args:       args,
		Env:        []string{"PFAPID_CHILD=1", "TZ="},
		Stdout:     os.Stderr,
		Stderr:     os.Stderr,
		ExtraFiles: []*os.File{theirs},
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
		},
	}
	if err := child.Start(); err != nil {
		log.Error("starting the network process", "err", err)
		return nil, nil, false
	}
	_ = theirs.Close() // the child holds its copy
	clients, _ := json.Marshal(cfg.Clients)
	if err := ipc.SendBootstrap(mine, ipc.Bootstrap{
		Listen: cfg.Listen, TLS: mat, TLSReload: cfg.TLS.ReloadInterval.Duration,
		Clients: clients, RateLimit: cfg.RateLimit, RateBurst: cfg.RateBurst,
	}); err != nil {
		log.Error("bootstrap", "err", err)
		_ = child.Process.Kill()
		return nil, nil, false
	}
	return mine, child, true
}

// sandboxPriv unveils what the privileged process needs and pledges it.
// The TLS files stay readable for reloads. unveil(2) on a file is kept by
// name in its directory, so files replaced by rename (pfapid pki renew,
// Vault agent, spiffe-helper) are still covered. Errors are logged here.
func sandboxPriv(log *slog.Logger, cfg *config.Config) error {
	veil := []struct{ path, perms string }{
		{cfg.Pfctl, "x"},
		{cfg.AnchorDir, "rwc"},
		{filepath.Dir(cfg.IncludeFile), "rwc"},
		{cfg.StateDir, "rwc"},
		{cfg.BaseRuleset, "r"},
		{filepath.Dir(cfg.QueueFile), "rwc"},
		{filepath.Dir(cfg.QoSFile), "rwc"},
		{"/dev/null", "rw"},
		{cfg.TLS.Cert, "r"},
		{cfg.TLS.Key, "r"},
	}
	for _, path := range cfg.TLS.CABundles() {
		veil = append(veil, struct{ path, perms string }{path, "r"})
	}
	for _, u := range veil {
		if err := sandbox.Unveil(u.path, u.perms); err != nil {
			log.Error("unveil", "path", u.path, "err", err)
			return err
		}
	}
	if err := sandbox.Lock(); err != nil {
		log.Error("unveil lock", "err", err)
		return err
	}
	if err := sandbox.Pledge("stdio rpath wpath cpath fattr proc exec"); err != nil {
		log.Error("pledge", "err", err)
		return err
	}
	return nil
}

// supervise serves the network process's requests until a signal, the
// child exiting or the IPC failing.
func supervise(ctx context.Context, log *slog.Logger, cfg *config.Config, mine *os.File, srv *priv.Server, child *exec.Cmd) int {
	done := make(chan error, 2)
	go func() {
		done <- ipc.Serve(ctx, mine, srv, func() (api.Material, error) { return readMaterial(cfg) })
	}()
	go func() { done <- child.Wait() }()
	select {
	case <-ctx.Done():
		log.Info("shutting down")
		_ = child.Process.Signal(syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		_ = child.Process.Kill()
		return 0
	case err := <-done:
		log.Error("network process or ipc ended; exiting", "err", err)
		_ = child.Process.Kill()
		return 1
	}
}

func runNet(log *slog.Logger) int {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		log.Error("the network process must not run as root")
		return 1
	}
	conn := os.NewFile(3, "ipc")
	if conn == nil {
		log.Error("no ipc socket on fd 3")
		return 1
	}
	_ = time.Now().Local().String() // initialise time.Local before pledge (TZ is empty: UTC)
	bs, err := ipc.ReadBootstrap(conn)
	if err != nil {
		log.Error("bootstrap", "err", err)
		return 1
	}
	var clients []api.Client
	if err := json.Unmarshal(bs.Clients, &clients); err != nil {
		log.Error("clients", "err", err)
		return 1
	}
	trust, err := api.NewTrust(bs.TLS)
	bootSum := materialSum(bs.TLS)
	clear(bs.TLS.KeyPEM)
	if err != nil {
		log.Error("tls", "err", err)
		return 1
	}
	ln, err := net.Listen("tcp", bs.Listen)
	if err != nil {
		log.Error("listen", "addr", bs.Listen, "err", err)
		return 1
	}
	if err := sandbox.Unveil("/", ""); err != nil {
		log.Error("unveil", "err", err)
		return 1
	}
	if err := sandbox.Lock(); err != nil {
		log.Error("unveil lock", "err", err)
		return 1
	}
	if err := sandbox.Pledge("stdio inet"); err != nil {
		log.Error("pledge", "err", err)
		return 1
	}
	ic := ipc.NewClient(conn)
	srv, err := api.New(ic, clients, trust, bs.RateLimit, bs.RateBurst, log)
	if err != nil {
		log.Error("api", "err", err)
		return 1
	}
	if bs.TLSReload > 0 {
		go reloadTLS(log, ic, srv, bs.TLSReload, bootSum)
	}
	tc := srv.TLSConfig()
	hs := srv.HTTPServer(bs.Listen, tc)
	log.Info("listening", "addr", ln.Addr().String())
	err = hs.Serve(tls.NewListener(ln, tc))
	if !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		return 1
	}
	return 0
}

func materialSum(m api.Material) [32]byte {
	b, _ := json.Marshal(m)
	return sha256.Sum256(b)
}

// reloadTLS asks the privileged process for the TLS files every interval and
// switches to them when they changed. Bad material (a half-written file, a
// missing CA bundle) is logged and the current material stays in use.
func reloadTLS(log *slog.Logger, ic *ipc.Client, srv *api.Server, every time.Duration, last [32]byte) {
	for range time.Tick(every) {
		m, err := ic.TLSMaterial()
		if err != nil {
			log.Warn("tls reload: reading material", "err", err)
			continue
		}
		sum := materialSum(m)
		if sum == last {
			clear(m.KeyPEM)
			continue
		}
		t, err := api.NewTrust(m)
		clear(m.KeyPEM)
		if err == nil {
			err = srv.SetTrust(t)
		}
		if err != nil {
			log.Error("tls reload: new material refused, keeping the current one", "err", err)
			continue
		}
		last = sum
		log.Info("tls material reloaded", "server_cert_not_after", t.NotAfter, "ca_bundles", t.Bundles())
		if time.Until(t.NotAfter) < expiryWarning {
			log.Warn("server certificate expires soon", "not_after", t.NotAfter)
		}
	}
}
