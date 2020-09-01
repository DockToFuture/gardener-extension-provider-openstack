// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package infrastructure

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/utils/openstack/clientconfig"
)

// OpenstackClient used to perform openstack operations
type OpenstackClient struct {
	AuthURL          string
	DomainName       string
	FloatingPoolName string
	Password         string
	Region           string
	TenantName       string
	UserName         string
	ProviderClient   *gophercloud.ProviderClient
	NeutronClient    *gophercloud.ServiceClient
	//NeutronClient    *gophercloud.ServiceClient
}

// NewOpenstackClient creates an openstack struct
func NewOpenstackClient(authURL, domainName, floatingPoolName, password, region, tenantName, username string) (*OpenstackClient, error) {

	openstackClient := &OpenstackClient{
		AuthURL:          authURL,
		DomainName:       domainName,
		FloatingPoolName: floatingPoolName,
		Password:         password,
		Region:           region,
		TenantName:       tenantName,
		UserName:         username,
	}

	providerClient, err := openstackClient.createProviderClient()
	if err != nil {
		return nil, err
	}

	neutronClient, err := openstackClient.createNeutronClient()
	if err != nil {
		return nil, err
	}

	openstackClient.ProviderClient = providerClient
	openstackClient.NeutronClient = neutronClient

	return openstackClient, nil
}

// createOpenStackClient creates and authenticates a base OpenStack client
func (o *OpenstackClient) createProviderClient() (*gophercloud.ProviderClient, error) {
	config := &tls.Config{}
	config.InsecureSkipVerify = false

	// caCert, ok := d.CloudConfig.Data[v1alpha1.OpenStackCACert]
	// if !ok {
	// 	caCert = nil
	// }

	// caCertPool := x509.NewCertPool()
	// caCertPool.AppendCertsFromPEM([]byte(caCert))
	// config.RootCAs = caCertPool

	// clientCert, ok := d.CloudConfig.Data[v1alpha1.OpenStackClientCert]
	// if ok {
	// 	clientKey, ok := d.CloudConfig.Data[v1alpha1.OpenStackClientKey]
	// 	if ok {
	// 		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
	// 		if err != nil {
	// 			return nil, err
	// 		}
	// 		config.Certificates = []tls.Certificate{cert}
	// 		config.BuildNameToCertificate()
	// 	} else {
	// 		return nil, fmt.Errorf("%s missing in secret", v1alpha1.OpenStackClientKey)
	// 	}
	// }

	clientOpts := new(clientconfig.ClientOpts)
	authInfo := &clientconfig.AuthInfo{
		AuthURL:     strings.TrimSpace(string(o.AuthURL)),
		Username:    strings.TrimSpace(string(o.UserName)),
		Password:    strings.TrimSpace(string(o.Password)),
		DomainName:  strings.TrimSpace(string(o.DomainName)),
		ProjectName: strings.TrimSpace(string(o.TenantName)),
		//DomainID:       strings.TrimSpace(string(domainID)),
		//ProjectID:      strings.TrimSpace(string(tenantID)),
		//UserDomainName: strings.TrimSpace(string(userDomainName)),
		//UserDomainID:   strings.TrimSpace(string(userDomainID)),
	}
	clientOpts.AuthInfo = authInfo

	fmt.Printf("1")

	ao, err := clientconfig.AuthOptions(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create client auth options: %+v", err)
	}

	fmt.Println("5")

	provider, err := openstack.NewClient(ao.IdentityEndpoint)
	if err != nil {
		return nil, err
	}

	// Set UserAgent
	provider.UserAgent.Prepend("Infrastructure Test Controller")

	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: config}
	provider.HTTPClient = http.Client{
		Transport: transport,
	}

	// if klog.V(6) {
	// 	provider.HTTPClient.Transport = &client.RoundTripper{
	// 		Rt:     provider.HTTPClient.Transport,
	// 		Logger: &logger{},
	// 	}
	// }

	err = openstack.Authenticate(provider, *ao)
	if err != nil {
		return nil, err
	}

	fmt.Println("10")

	return provider, nil
}

// createNeutronClient is used to create a Nova client
func (o *OpenstackClient) createNovaClient() (*gophercloud.ServiceClient, error) {
	return openstack.NewComputeV2(o.ProviderClient, gophercloud.EndpointOpts{
		Region:       strings.TrimSpace(o.Region),
		Availability: gophercloud.AvailabilityPublic,
	})
}

// createNeutronClient is used to create a Neutron client
func (o *OpenstackClient) createNeutronClient() (*gophercloud.ServiceClient, error) {
	return openstack.NewNetworkV2(o.ProviderClient, gophercloud.EndpointOpts{
		Region:       o.Region,
		Availability: gophercloud.AvailabilityPublic,
	})
}
