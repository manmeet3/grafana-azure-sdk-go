package aztokenprovider

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
)

type clientCertTokenRetriever struct {
	cloudConf      cloud.Configuration
	tenantId       string
	clientId       string
	certPath       string
	certPassword   string
	certExpiration string
	credential     azcore.TokenCredential // todo: add certificate expiration date as a parameter?
}

type certificates struct {
	certs []*x509.Certificate
	key   crypto.PrivateKey
}

func getClientCertTokenRetriever(settings *azsettings.AzureSettings, credentials *azcredentials.AzureClientCertificateCredentials) (TokenRetriever, error) {
	var authorityHost string

	if credentials.Authority != "" {
		// Use AAD authority endpoint configured in credentials
		authorityHost = credentials.Authority
	} else {
		// Resolve cloud settings for the given cloud name
		cloudSettings, err := settings.GetCloud(credentials.AzureCloud)
		if err != nil {
			return nil, err
		}
		authorityHost = cloudSettings.AadAuthority
	}

	return &clientCertTokenRetriever{
		cloudConf: cloud.Configuration{
			ActiveDirectoryAuthorityHost: authorityHost,
			Services:                     map[cloud.ServiceName]cloud.ServiceConfiguration{},
		},
		tenantId:       credentials.TenantId,
		clientId:       credentials.ClientId,
		certPath:       credentials.CertificatePath,
		certPassword:   credentials.CertificatePw,
		certExpiration: credentials.CertificateExp,
	}, nil
}

func (c *clientCertTokenRetriever) GetCacheKey(grafanaMultiTenantId string) string {
	return fmt.Sprintf("azure|clientcertficiate|%s|%s|%s|%s|%s", c.cloudConf.ActiveDirectoryAuthorityHost, c.tenantId, c.clientId, hashSecret(c.certPath), grafanaMultiTenantId)
}

func (c *clientCertTokenRetriever) Init() error {
	options := azidentity.ClientCertificateCredentialOptions{}
	options.Cloud = c.cloudConf
	// read and create an array of x509 certificates
	var certificates certificates = readCertificateFromPath(c.certPath, c.certPassword)
	if credential, err := azidentity.NewClientCertificateCredential(c.tenantId, c.clientId, certificates.certs, certificates.key, &options); err != nil {
		return err
	} else {
		c.credential = credential
		return nil
	}
}

// Empty implementation
func (c *clientCertTokenRetriever) GetExpiry() *time.Time {
	expDate, error := time.Parse("01/02/2006", c.certExpiration) // this specific date seems to be used for formatting date strings

	if error != nil {
		fmt.Sprintf("failed to parse certificate %s expiration date: %v", c.certPath, error)
		return nil
	}
	return &expDate
}

func readCertificateFromPath(certPath string, password string) certificates {
	data, _ := os.ReadFile(certPath)
	certs, key, err := azidentity.ParseCertificates(data, []byte(password))
	if err != nil {
		fmt.Sprintf("failed to parse %s: %v", certPath, err)
	}
	return certificates{certs: certs, key: key}
}

func (c *clientCertTokenRetriever) GetAccessToken(ctx context.Context, scopes []string) (*AccessToken, error) {
	accessToken, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
	if err != nil {
		return nil, err
	}

	return &AccessToken{Token: accessToken.Token, ExpiresOn: accessToken.ExpiresOn}, nil
}
