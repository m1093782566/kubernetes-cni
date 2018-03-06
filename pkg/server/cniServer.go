package server

import (
	"fmt"

	"github.com/golang/glog"
	cnipb "github.com/kubernetes-cni/pkg/api"
	"golang.org/x/net/context"
)

type DefaultCniServer struct {
	Driver *CniDriver
}

// GetSupportedVersion return all the cni version that this driver supported.
// TODO: how to do when plugins have different version
// TODO: change to check version support or not
func (cni *DefaultCniServer) SupportVersion(ctx context.Context, in *cnipb.SupportVersionRequest) (*cnipb.SupportVersionResponse, error) {
	glog.Infof("gRPC: SupportVersion")
	support := false
	if cni.Driver.SupportVersion(in.Version) {
		support = true
	}
	return &cnipb.SupportVersionResponse{support}, nil
}

// SetUpPod
// func/request/response
func (cni *DefaultCniServer) SetUpPod(ctx context.Context, in *cnipb.SetUpPodRequest) (*cnipb.SetUpPodResponse, error) {
	//TODO: need other check? check initialize, check version...
	glog.Infof("gRPC: SetUpPod")
	err := cni.Driver.SetUpPod(in.RuntimeInfo)
	if err != nil {
		return nil, err
	}
	// TODO: maybe need return create result: network info/success/
	return nil, nil
}

// tearDownPod
// request/response/func
func (cni *DefaultCniServer) TearDownPod(ctx context.Context, in *cnipb.TearDownPodRequest) (*cnipb.TearDownPodResponse, error) {
	//TODO: need other check? check initialize, check version...
	glog.Infof("gRPC: TearDownPod")
	err := cni.Driver.TearDownPod(in.RuntimeInfo)
	if err != nil {
		return nil, err
	}
	// TODO: maybe need return create result: network info/success/
	return nil, nil
	// TODO: need to check plugin capability.
}

func (cni *DefaultCniServer) Status(ctx context.Context, in *cnipb.StatusRequest) (*cnipb.StatusResponse, error) {
	glog.Infof("gRPC: Status")
	syncErr := cni.Driver.SyncNetworkConfig()
	checkErr := cni.Driver.CheckInitialized()
	if checkErr != nil {
		return nil, fmt.Errorf("cni driver is not initialized: %v", checkErr)
	}
	if syncErr != nil {
		return &cnipb.StatusResponse{false, cni.Driver.Capabilities}, nil
	}
	return &cnipb.StatusResponse{true, cni.Driver.Capabilities}, nil
}

func NewCNIServer(driver *CniDriver) *DefaultCniServer {
	return &DefaultCniServer{
		Driver: driver,
	}
}
