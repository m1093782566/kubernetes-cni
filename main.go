package main

import (
	"flag"
	"os"

	"github.com/golang/glog"
	"github.com/kubernetes-cni/pkg/server"
)

func init() {
	flag.Set("logtostderr", "true")
}

var (
	//TODO default value need decide and maybe those args can be pass by environment instead of flag
	endpoint   = flag.String("endpoint", "unix://tmp/lw/cni.sock", "CNI endpoint")
	cniConfDir = flag.String("conf-dir", "/etc/cni/net.d", "the dir of the cni configfile")
	cniBinDir  = flag.String("bin-dir", "/opt/cni/bin", "the dir of the cni plugin binaries")
)

func main() {
	flag.Parse()

	handle()
	os.Exit(0)
}

func handle() {
	// init driver
	// TODO: add basic log
	cniDriver, err := server.NewCniDriver(*cniConfDir, *cniBinDir)
	if err != nil {
		glog.Errorf("Run cni driver failed, failed to validate args, err: %q", err)
	}

	// get server
	cniServer := server.NewCNIServer(cniDriver)

	s := server.NewNonBlockingGRPCServer()
	s.Start(*endpoint, cniServer)
	s.Wait()
}
