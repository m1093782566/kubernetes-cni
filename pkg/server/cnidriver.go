package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/containernetworking/cni/libcni"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/golang/glog"
	cnipb "github.com/kubernetes-cni/pkg/api"
)

const (
	DefaultCNIDir        = "/opt/cni/bin"
	DefaultNetDir        = "/etc/cni/net.d"
	VendorCNIDirTemplate = "/opt/%s/bin"
	// TODO: make this configurable?
	DefaultInterfaceName = "eth0"
	CapPortMapping       = "portMappings"
)

// TODO: fake version, this should in pb
type Version struct {
	major string
}

type Capabilities map[string]*cnipb.Empty

type CniDriver struct {
	sync.RWMutex
	// network config
	loNetwork      *cniNetwork
	defaultNetwork *cniNetwork

	//runtime config, passed by rpc
	runtimeConfig *libcni.RuntimeConf

	version *Version
	SupVers []*Version

	// dir
	cniPluginDir string
	cniConfigDir string

	Capabilities Capabilities

	// TODO: sync networkconfig period and make it configurable
}

type cniNetwork struct {
	name          string
	NetworkConfig *libcni.NetworkConfigList
	CNIConfig     libcni.CNI
}

type Empty struct {
}

// TODO: consider plugin with capability. e.g. portMap/bandwidth
func (cni *CniDriver) SetUpPod(runtimeInfo *cnipb.PodRuntimeInfo) error {
	// step1: build cni runtime conf
	// TODO: return portMap didn't created information
	rt, err := cni.buildRuntimeConfig(runtimeInfo)
	if err != nil {
		// TODO: In case don't have portMap capability
		if !strings.Contains(err.Error(), CapPortMapping) {
			return fmt.Errorf("Build runtimeConfig err: %v", err)
		}
	}

	// step2: add to network
	if cni.loNetwork != nil {
		// TODO: use this res
		if _, err := cni.addToNetwork(cni.loNetwork, rt); err != nil {
			glog.Errorf("Error while adding to cni lo network: %s", err)
			return err
		}
	}
	_, err = cni.addToNetwork(cni.getDefaultNetwork(), rt)
	if err != nil {
		glog.Errorf("Error while adding to cni network: %s", err)
		return err
	}

	return nil
}

func (cni *CniDriver) TearDownPod(runtimeInfo *cnipb.PodRuntimeInfo) error {
	// step1: get runtime conf
	rt, err := cni.buildRuntimeConfig(runtimeInfo)
	if err != nil {
		// TODO: In case don't have portMap capability
		if !strings.Contains(err.Error(), CapPortMapping) {
			return fmt.Errorf("Build runtimeConfig err: %v", err)
		}
	}
	// step2: delete networklist
	network := cni.getDefaultNetwork()
	glog.V(4).Infof("About to del CNI network %v (type=%v)", network.NetworkConfig.Name,
		network.NetworkConfig.Plugins[0].Network.Type)
	err = network.CNIConfig.DelNetworkList(network.NetworkConfig, rt)
	if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
		glog.Errorf("Error deleting network: %v", err)
		return err
	}
	return nil
}

func (cni *CniDriver) SupportVersion(version string) bool {
	for _, vs := range cni.SupVers {
		if vs.major == version {
			return true
		}
	}
	return false
}

func (cni *CniDriver) CheckInitialized() error {
	if cni.getDefaultNetwork() == nil {
		return fmt.Errorf("cni config uninitialized")
	}
	return nil
}

func (cni *CniDriver) addToNetwork(network *cniNetwork, runtimeInfo *libcni.RuntimeConf) (cnitypes.Result, error) {
	glog.V(4).Infof("About to add CNI network %v (type=%v)",
		network.NetworkConfig.Name, network.NetworkConfig.Plugins[0].Network.Type)
	res, err := network.CNIConfig.AddNetworkList(network.NetworkConfig, runtimeInfo)
	if err != nil {
		glog.Errorf("Error adding network: %v", err)
		return nil, err
	}
	return res, nil
}

func (cni *CniDriver) buildRuntimeConfig(runtimeInfo *cnipb.PodRuntimeInfo) (*libcni.RuntimeConf, error) {
	glog.V(4).Infof("Netns path: %v; Podns path: %v", runtimeInfo, runtimeInfo.Namespace)
	rt := &libcni.RuntimeConf{
		ContainerID: runtimeInfo.ContainerID,
		NetNS:       runtimeInfo.NetnsPath,
		IfName:      DefaultInterfaceName,
		Args: [][2]string{
			{"IgnoreUnknown", "1"},
			{"K8S_POD_NAMESPACE", runtimeInfo.Namespace},
			{"K8S_POD_NAME", runtimeInfo.Name},
			{"K8S_POD_INFRA_CONTAINER_ID", runtimeInfo.ContainerID},
		},
	}
	if runtimeInfo.PortMap == nil {
		return rt, nil
	}
	if _, contained := cni.Capabilities[CapPortMapping]; contained {
		rt.CapabilityArgs = map[string]interface{}{
			CapPortMapping: runtimeInfo.PortMap,
		}
		return rt, nil
	}
	return rt, fmt.Errorf("Required portMap but don't have capability of %q", CapPortMapping)
}

func (cni *CniDriver) SyncNetworkConfig() error {
	network, err := getDefaultCNINetwork(cni.cniConfigDir, cni.cniPluginDir)
	if err != nil {
		// TODO: mark last sync time/last sync result
		return fmt.Errorf("Unable to update cni config: %v", err)
	}
	cni.Lock()
	defer cni.Unlock()
	cni.defaultNetwork = network
	return nil
}

func (cni *CniDriver) getDefaultNetwork() *cniNetwork {
	cni.RLock()
	defer cni.RUnlock()
	return cni.defaultNetwork
}

func getCNICapabilities(network *cniNetwork) (Capabilities, error) {
	var caps Capabilities
	for _, plugin := range network.NetworkConfig.Plugins {
		if plugin.Network.Capabilities != nil {
			for cap, support := range plugin.Network.Capabilities {
				if support {
					caps[cap] = &cnipb.Empty{}
				}
			}
		}
	}
	if len(caps) == 0 {
		return nil, nil
	}
	return caps, nil
}

func NewCniDriver(netConfigDir, binDir string) (*CniDriver, error) {
	if binDir == "" {
		binDir = DefaultCNIDir
	}

	network, err := getDefaultCNINetwork(netConfigDir, binDir)
	if err != nil {
		return nil, fmt.Errorf("Unable to update cni config: %v", err)
	}

	caps, err := getCNICapabilities(network)
	if err != nil {
		return nil, fmt.Errorf("Unable to get cni capabilities: %v", err)
	}

	loNetwork, err := getLoNetwork(binDir)
	if err != nil {
		return nil, fmt.Errorf("Unable to get loopback network config: %v", err)
	}
	newCniDriver := &CniDriver{
		loNetwork:      loNetwork,
		defaultNetwork: network,
		// TODO: need to write real version
		version:      &Version{"0.1"},
		SupVers:      []*Version{{"0.1"}},
		cniPluginDir: binDir,
		cniConfigDir: netConfigDir,
		Capabilities: caps,
	}
	return newCniDriver, nil
}

// getDefaultCNINetwork to check  network config exist or not
// if exist, bootstrap network config file to cniNetwork
// it's a package of "libcni"
func getDefaultCNINetwork(netConfigDir, binDir string) (*cniNetwork, error) {
	if netConfigDir == "" {
		netConfigDir = DefaultNetDir
	}
	files, err := libcni.ConfFiles(netConfigDir, []string{".conf", ".conflist", ".json"})
	switch {
	case err != nil:
		return nil, err
	case len(files) == 0:
		return nil, fmt.Errorf("No networks found in %s", netConfigDir)
	}

	sort.Strings(files)
	for _, confFile := range files {
		var confList *libcni.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				glog.Warningf("Error loading CNI config list file %s: %v", confFile, err)
				continue
			}
		} else {
			conf, err := libcni.ConfFromFile(confFile)
			if err != nil {
				glog.Warningf("Error loading CNI config file %s: %v", confFile, err)
				continue
			}
			// Ensure the config has a "type" so we know what plugin to run.
			// Also catches the case where somebody put a conflist into a conf file.
			if conf.Network.Type == "" {
				glog.Warningf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", confFile)
				continue
			}

			confList, err = libcni.ConfListFromConf(conf)
			if err != nil {
				glog.Warningf("Error converting CNI config file %s to list: %v", confFile, err)
				continue
			}
		}
		if len(confList.Plugins) == 0 {
			glog.Warningf("CNI config list %s has no networks, skipping", confFile)
			continue
		}

		// TODO: check vendordir use case, to see is this specified in CNI specification
		vendorDir := fmt.Sprintf(VendorCNIDirTemplate, confList.Plugins[0].Network.Type)
		cninet := &libcni.CNIConfig{
			Path: []string{vendorDir, binDir},
		}
		if err := checkPlugin(confList.Plugins, cninet.Path); err != nil {
			return nil, fmt.Errorf("Can't find cni plugin in cni-bin-dir: %v", err)
		}
		network := &cniNetwork{name: confList.Name, NetworkConfig: confList, CNIConfig: cninet}
		return network, nil
	}
	return nil, fmt.Errorf("No valid networks found in %s", netConfigDir)
}

// getLoNetwork to get default loopback network
func getLoNetwork(binDir string) (*cniNetwork, error) {
	loConfig, err := libcni.ConfListFromBytes([]byte(`{
  "cniVersion": "0.2.0",
  "name": "cni-loopback",
  "plugins":[{
    "type": "loopback"
  }]
}`))
	if err != nil {
		// The hardcoded config above should always be valid and unit tests will
		// catch this
		panic(err)
	}
	loopBackDir := fmt.Sprintf(VendorCNIDirTemplate, "loopback")
	cninet := &libcni.CNIConfig{
		Path: []string{loopBackDir, binDir},
	}

	if err := checkPlugin(loConfig.Plugins, cninet.Path); err != nil {
		return nil, fmt.Errorf("Can't find \"loopback\" in cni-bin-dir: %v", err)
	}
	loNetwork := &cniNetwork{
		name:          "lo",
		NetworkConfig: loConfig,
		CNIConfig:     cninet,
	}

	return loNetwork, nil
}

// checkPlugin to make sure plugins are in the given paths
func checkPlugin(plugins []*libcni.NetworkConfig, paths []string) error {
	if len(plugins) == 0 {
		return fmt.Errorf("no plugin name provided")
	}

	if len(paths) == 0 {
		return fmt.Errorf("no paths provided")
	}

	pluginsNotExist, exist := []string{}, false
	for _, plugin := range plugins {
		for _, path := range paths {
			fullpath := filepath.Join(path, plugin.Network.Type)
			if fi, err := os.Stat(fullpath); err == nil && fi.Mode().IsRegular() {
				exist = true
			}
		}
		if !exist {
			pluginsNotExist = append(pluginsNotExist, plugin.Network.Type)
		}
	}
	if len(pluginsNotExist) == 0 {
		return nil
	}
	return fmt.Errorf("failed to find plugins %q in path %s", pluginsNotExist, paths)
}
