package aztokenprovider

import (
	"testing"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureTokenProvider_getClientCertificateCredential(t *testing.T) {
	var settings = &azsettings.AzureSettings{
		Cloud: azsettings.AzurePublic,
	}

	defaultCredentials := func() *azcredentials.AzureClientCertificateCredentials {
		return &azcredentials.AzureClientCertificateCredentials{
			AzureCloud:      azsettings.AzurePublic,
			Authority:       "",
			TenantId:        "7dcf1d1a-4ec0-41f2-ac29-c1538a698bc4",
			ClientId:        "1af7c188-e5b6-4f96-81b8-911761bdd459",
			CertificatePath: "D:/golang-test/grafana-app-reg-cert_c1b2d70735094fe386ee6b1b9bfa6a3f.cer",
			CertificatePw:   "",
			CertificateExp:  "4/18/2025",
		}
	}

	t.Run("should return clientCertificateTokenRetriever with values", func(t *testing.T) {
		credentials := defaultCredentials()

		result, err := getClientCertTokenRetriever(settings, credentials)
		require.NoError(t, err)

		assert.IsType(t, &clientCertTokenRetriever{}, result)
		credential := (result).(*clientCertTokenRetriever)

		assert.Equal(t, "https://login.microsoftonline.com/", credential.cloudConf.ActiveDirectoryAuthorityHost)
		assert.Equal(t, "7dcf1d1a-4ec0-41f2-ac29-c1538a698bc4", credential.tenantId)
		assert.Equal(t, "1af7c188-e5b6-4f96-81b8-911761bdd459", credential.clientId)
		assert.Equal(t, "D:/golang-test/grafana-app-reg-cert_c1b2d70735094fe386ee6b1b9bfa6a3f.cer", credential.certPath)
	})

	t.Run("authority should selected based on cloud", func(t *testing.T) {
		credentials := defaultCredentials()
		credentials.AzureCloud = azsettings.AzureChina

		result, err := getClientCertTokenRetriever(settings, credentials)
		require.NoError(t, err)

		assert.IsType(t, &clientCertTokenRetriever{}, result)
		credential := (result).(*clientCertTokenRetriever)

		assert.Equal(t, "https://login.chinacloudapi.cn/", credential.cloudConf.ActiveDirectoryAuthorityHost)
	})

	t.Run("explicitly set authority should have priority over cloud", func(t *testing.T) {
		credentials := defaultCredentials()
		credentials.AzureCloud = azsettings.AzureChina
		credentials.Authority = "https://another.com/"

		result, err := getClientCertTokenRetriever(settings, credentials)
		require.NoError(t, err)

		assert.IsType(t, &clientCertTokenRetriever{}, result)
		credential := (result).(*clientCertTokenRetriever)

		assert.Equal(t, "https://another.com/", credential.cloudConf.ActiveDirectoryAuthorityHost)
	})

	t.Run("should fail with error if cloud is not supported", func(t *testing.T) {
		credentials := defaultCredentials()
		credentials.AzureCloud = "InvalidCloud"

		_, err := getClientCertTokenRetriever(settings, credentials)
		require.Error(t, err)
	})
}
