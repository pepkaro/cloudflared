package allregions

import (
	"fmt"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (ea *EdgeAddr) String() string {
	return fmt.Sprintf("%s-%s", ea.TCP, ea.UDP)
}

// clearProxyEnv unsets proxy env vars for the test so the DNS discovery path runs.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	keys := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"}
	saved := make(map[string]string)
	for _, k := range keys {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	t.Cleanup(func() {
		for _, k := range keys {
			if saved[k] != "" {
				os.Setenv(k, saved[k])
			}
		}
	})
}

func TestEdgeDiscovery(t *testing.T) {
	clearProxyEnv(t)

	mockAddrs := newMockAddrs(19, 2, 5)
	netLookupSRV = mockNetLookupSRV(mockAddrs)
	netLookupIP = mockNetLookupIP(mockAddrs)

	expectedAddrSet := map[string]bool{}
	for _, addrs := range mockAddrs.addrMap {
		for _, addr := range addrs {
			expectedAddrSet[addr.String()] = true
		}
	}

	l := zerolog.Nop()
	addrLists, err := edgeDiscovery(&l, "")
	assert.NoError(t, err)
	actualAddrSet := map[string]bool{}
	for _, addrs := range addrLists {
		for _, addr := range addrs {
			actualAddrSet[addr.String()] = true
		}
	}

	assert.Equal(t, expectedAddrSet, actualAddrSet)
}

func TestEdgeDiscoveryWithProxy(t *testing.T) {
	clearProxyEnv(t)

	// Set proxy env var to trigger proxy mode
	os.Setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
	defer os.Unsetenv("HTTPS_PROXY")

	l := zerolog.Nop()
	addrLists, err := edgeDiscovery(&l, "")
	require.NoError(t, err)
	require.Len(t, addrLists, 2, "should return 2 regions")

	// Verify each region has one address with a hostname set
	for i, addrs := range addrLists {
		require.Len(t, addrs, 1, "region %d should have 1 address", i)
		assert.NotEmpty(t, addrs[0].Hostname, "proxy mode should set Hostname")
		assert.Contains(t, addrs[0].Hostname, "argotunnel.com")
		assert.Contains(t, addrs[0].Hostname, "7844")
	}

	// Verify the two regions have different hostnames
	assert.NotEqual(t, addrLists[0][0].Hostname, addrLists[1][0].Hostname)
}

func TestEdgeDiscoveryWithoutProxy(t *testing.T) {
	clearProxyEnv(t)

	mockAddrs := newMockAddrs(19, 2, 5)
	netLookupSRV = mockNetLookupSRV(mockAddrs)
	netLookupIP = mockNetLookupIP(mockAddrs)

	l := zerolog.Nop()
	addrLists, err := edgeDiscovery(&l, "")
	require.NoError(t, err)

	// Verify no Hostname is set in direct mode
	for _, addrs := range addrLists {
		for _, addr := range addrs {
			assert.Empty(t, addr.Hostname, "direct mode should not set Hostname")
		}
	}
}
