package azsettings

import (
	"fmt"
)

type AzureCloudInfo struct {
	Name        string
	DisplayName string
}

type AzureCloudSettings struct {
	Name         string
	DisplayName  string
	AadAuthority string
	Properties   map[string]string
}

var predefinedClouds = []*AzureCloudSettings{
	{
		Name:         AzurePublic,
		DisplayName:  "Azure",
		AadAuthority: "https://login.microsoftonline.com/",
		Properties: map[string]string{
			"azureDataExplorerSuffix": ".kusto.windows.net",
			"logAnalytics":            "https://api.loganalytics.io",
			"portal":                  "https://portal.azure.com",
			"prometheusResourceId":    "https://prometheus.monitor.azure.com",
			"resourceManager":         "https://management.azure.com",
		},
	},
	{
		Name:         AzureChina,
		DisplayName:  "Azure China",
		AadAuthority: "https://login.chinacloudapi.cn/",
		Properties: map[string]string{
			"azureDataExplorerSuffix": ".kusto.chinacloudapi.cn",
			"logAnalytics":            "https://api.loganalytics.azure.cn",
			"portal":                  "https://portal.azure.cn",
			"prometheusResourceId":    "https://prometheus.monitor.azure.cn",
			"resourceManager":         "https://management.chinacloudapi.cn",
		},
	},
	{
		Name:         AzureUSGovernment,
		DisplayName:  "Azure US Government",
		AadAuthority: "https://login.microsoftonline.us/",
		Properties: map[string]string{
			"azureDataExplorerSuffix": ".kusto.usgovcloudapi.net",
			"logAnalytics":            "https://api.loganalytics.us",
			"portal":                  "https://portal.azure.us",
			"prometheusResourceId":    "https://prometheus.monitor.azure.us",
			"resourceManager":         "https://management.usgovcloudapi.net",
		},
	},
}

// msingh todo: add a function to read config and append AGC clouds to predefinedClouds list

func (*AzureSettings) GetCloud(cloudName string) (*AzureCloudSettings, error) {
	clouds := getClouds()

	for _, cloud := range clouds {
		if cloud.Name == cloudName {
			return cloud, nil
		}
	}

	return nil, fmt.Errorf("the Azure cloud '%s' is not supported", cloudName)
}

// Returns all clouds configured on the instance, including custom clouds if any
func (*AzureSettings) Clouds() []AzureCloudInfo {
	clouds := getClouds()
	return mapCloudInfo(clouds)
}

// Returns only the custom clouds configured on the instance
func (*AzureSettings) CustomClouds() []AzureCloudInfo {
	clouds := getCustomClouds()
	return mapCloudInfo(clouds)
}

func mapCloudInfo(clouds []*AzureCloudSettings) []AzureCloudInfo {
	results := make([]AzureCloudInfo, 0, len(clouds))
	for _, cloud := range clouds {
		results = append(results, AzureCloudInfo{
			Name:        cloud.Name,
			DisplayName: cloud.DisplayName,
		})
	}

	return results
}

func getClouds() []*AzureCloudSettings {
	if clouds := getCustomClouds(); len(clouds) > 0 {
		allClouds := append(clouds, predefinedClouds...)
		return allClouds
	}

	return predefinedClouds
}

func getCustomClouds() []*AzureCloudSettings {
	// Configuration of Azure clouds not yet supported
	return nil
}
