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
	"context"
	"encoding/json"
	"flag"
	"path/filepath"
	"time"

	openstackinstall "github.com/gardener/gardener-extension-provider-openstack/pkg/apis/openstack/install"
	openstackv1alpha1 "github.com/gardener/gardener-extension-provider-openstack/pkg/apis/openstack/v1alpha1"
	"github.com/gardener/gardener-extension-provider-openstack/pkg/controller/infrastructure"
	"github.com/gardener/gardener-extension-provider-openstack/pkg/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"

	//. "github.com/gardener/gardener-extension-provider-openstack/test/integration/infrastructure"
	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/operation/common"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	routerName = "shoot--core--openstack-infra"
	vpcCIDR    = "10.250.0.0/16"
)

var (
	authURL          = flag.String("auth-url", "", "Authrization URL for openstack")
	domainName       = flag.String("domain-name", "", "Domain name for openstack")
	floatingPoolName = flag.String("floating-pool-name", "", "Floating pool name for creating router")
	// floatingPoolSubnetName = flag.String("floating-pool-subnet-name", "", "Floating subnet pool name for creating router")
	password   = flag.String("password", "", "Password for openstack")
	region     = flag.String("region", "", "Openstack region")
	tenantName = flag.String("tenant-name", "", "Tenant name for openstack")
	userName   = flag.String("user-name", "", "User name for openstack")
)

func validateFlags() {
	if len(*authURL) == 0 {
		panic("--auth-url flag is not specified")
	}
	if len(*domainName) == 0 {
		panic("--domain-name flag is not specified")
	}
	if len(*floatingPoolName) == 0 {
		panic("--floating-pool-name is not specified")
	}
	// if len(*floatingPoolSubnetName) == 0 {
	// 	panic("--floating-pool-subnet-name is not specified")
	// }
	if len(*password) == 0 {
		panic("--password flag is not specified")
	}
	if len(*region) == 0 {
		panic("--region flag is not specified")
	}
	if len(*tenantName) == 0 {
		panic("--tenant-name flag is not specified")
	}
	if len(*userName) == 0 {
		panic("--user-name flag is not specified")
	}
}

var _ = Describe("Infrastructure tests", func() {

	var (
		ctx    = context.Background()
		logger *logrus.Entry

		testEnv   *envtest.Environment
		mgrCancel context.CancelFunc
		c         client.Client

		decoder runtime.Decoder

		openstackClient *OpenstackClient

		internalChartsPath string
	)

	BeforeSuite(func() {
		flag.Parse()
		validateFlags()

		internalChartsPath = openstack.InternalChartsPath
		repoRoot := filepath.Join("..", "..", "..")
		openstack.InternalChartsPath = filepath.Join(repoRoot, openstack.InternalChartsPath)

		// enable manager logs
		logf.SetLogger(zap.LoggerTo(GinkgoWriter, true))

		log := logrus.New()
		log.SetOutput(GinkgoWriter)
		logger = logrus.NewEntry(log)

		By("starting test environment")
		testEnv = &envtest.Environment{
			UseExistingCluster: pointer.BoolPtr(true),
			CRDInstallOptions: envtest.CRDInstallOptions{
				Paths: []string{
					filepath.Join(repoRoot, "example", "20-crd-cluster.yaml"),
					filepath.Join(repoRoot, "example", "20-crd-infrastructure.yaml"),
				},
			},
		}

		cfg, err := testEnv.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())

		By("setup manager")
		mgr, err := manager.New(cfg, manager.Options{})
		Expect(err).NotTo(HaveOccurred())

		Expect(extensionsv1alpha1.AddToScheme(mgr.GetScheme())).To(Succeed())
		Expect(openstackinstall.AddToScheme(mgr.GetScheme())).To(Succeed())

		Expect(infrastructure.AddToManager(mgr)).To(Succeed())

		var mgrContext context.Context
		mgrContext, mgrCancel = context.WithCancel(ctx)

		By("start manager")
		go func() {
			err := mgr.Start(mgrContext.Done())
			Expect(err).NotTo(HaveOccurred())
		}()

		c = mgr.GetClient()
		Expect(c).NotTo(BeNil())

		decoder = serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder()

		flag.Parse()
		validateFlags()

		openstackClient, err = NewOpenstackClient(*authURL, *domainName, *floatingPoolName, *password, *region, *tenantName, *userName)
		Expect(err).NotTo(HaveOccurred())

	})

	AfterSuite(func() {
		defer func() {
			By("stopping manager")
			mgrCancel()
		}()

		By("running cleanup actions")
		framework.RunCleanupActions()

		By("stopping test environment")
		Expect(testEnv.Stop()).To(Succeed())

		openstack.InternalChartsPath = internalChartsPath
	})

	Context("with infrastructure that requests new private network", func() {
		AfterEach(func() {
			framework.RunCleanupActions()
		})

		It("should successfully create and delete", func() {
			providerConfig := newProviderConfig(nil) //&openstackv1alpha1.Router{ID: routerName}
			cloudProfileConfig := newCloudProfileConfig(openstackClient.Region, openstackClient.AuthURL)
			namespace, err := generateNamespaceName()
			Expect(err).NotTo(HaveOccurred())

			err = runTest(ctx, logger, c, namespace, providerConfig, decoder, openstackClient, cloudProfileConfig)

			Expect(err).NotTo(HaveOccurred())
		})
	})

	// Context("with infrastructure that uses existing vpc", func() {
	// 	AfterEach(func() {
	// 		framework.RunCleanupActions()
	// 	})

	// 	It("should successfully create and delete", func() {
	// 		namespace, err := generateNamespaceName()
	// 		Expect(err).NotTo(HaveOccurred())

	// 		By("setup openstack client")
	// 		openstackClient, err = NewOpenstackClient(*authURL, *domainName, *floatingPoolName, *password, *region, *tenantName, *userName)
	// 		Expect(err).NotTo(HaveOccurred())

	// 		networkName := namespace
	// 		cloudRouterName := networkName + "-cloud-router"

	// 		err = prepareNewNetwork(ctx, logger, networkName, cloudRouterName, openstackClient)
	// 		Expect(err).NotTo(HaveOccurred())

	// 		var cleanupHandle framework.CleanupActionHandle
	// 		cleanupHandle = framework.AddCleanupAction(func() {
	// 			err := teardownNetwork(ctx, logger, networkName, cloudRouterName, openstackClient)
	// 			Expect(err).NotTo(HaveOccurred())

	// 			framework.RemoveCleanupAction(cleanupHandle)
	// 		})

	// 		// providerConfig := newProviderConfig(&openstackv1alpha1.VPC{
	// 		// 	Name: networkName,
	// 		// 	CloudRouter: &openstackv1alpha1.CloudRouter{
	// 		// 		Name: cloudRouterName,
	// 		// 	},
	// 		// })

	// 		providerConfig := newProviderConfig(&openstackv1alpha1.Router{
	// 			// ID: "",
	// 		})

	// 		err = runTest(ctx, logger, c, namespace, providerConfig, decoder, openstackClient})
	// 		Expect(err).NotTo(HaveOccurred())
	// 	})
	// })

})

func runTest(
	ctx context.Context,
	logger *logrus.Entry,
	c client.Client,
	namespaceName string,
	providerConfig *openstackv1alpha1.InfrastructureConfig,
	decoder runtime.Decoder,
	openstackClient *OpenstackClient,
	cloudProfileConfig *openstackv1alpha1.CloudProfileConfig,
) error {
	var (
		namespace                 *corev1.Namespace
		cluster                   *extensionsv1alpha1.Cluster
		infra                     *extensionsv1alpha1.Infrastructure
		infrastructureIdentifiers infrastructureIdentifiers
	)

	var cleanupHandle framework.CleanupActionHandle
	cleanupHandle = framework.AddCleanupAction(func() {
		By("delete infrastructure")
		Expect(client.IgnoreNotFound(c.Delete(ctx, infra))).To(Succeed())

		By("wait until infrastructure is deleted")
		err := common.WaitUntilExtensionCRDeleted(
			ctx,
			c,
			logger,
			func() extensionsv1alpha1.Object { return &extensionsv1alpha1.Infrastructure{} },
			"Infrastructure",
			infra.Namespace,
			infra.Name,
			10*time.Second,
			16*time.Minute,
		)
		Expect(err).NotTo(HaveOccurred())

		By("verify infrastructure deletion")
		verifyDeletion(ctx, openstackClient, infrastructureIdentifiers)

		Expect(client.IgnoreNotFound(c.Delete(ctx, namespace))).To(Succeed())
		Expect(client.IgnoreNotFound(c.Delete(ctx, cluster))).To(Succeed())

		framework.RemoveCleanupAction(cleanupHandle)
	})

	By("create namespace for test execution")
	namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}
	if err := c.Create(ctx, namespace); err != nil {
		return err
	}

	cloudProfileConfigJSON, err := json.Marshal(&cloudProfileConfig)
	if err != nil {
		return err
	}

	cloudprofile := gardenerv1beta1.CloudProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: gardenerv1beta1.SchemeGroupVersion.String(),
			Kind:       "CloudProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
		Spec: gardenerv1beta1.CloudProfileSpec{
			ProviderConfig: &runtime.RawExtension{
				Raw: cloudProfileConfigJSON,
			},
		},
	}

	cloudProfileJSON, err := json.Marshal(&cloudprofile)
	if err != nil {
		return err
	}

	By("create cluster")
	cluster = &extensionsv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
		Spec: extensionsv1alpha1.ClusterSpec{
			CloudProfile: runtime.RawExtension{
				Raw: cloudProfileJSON,
			},
		},
	}
	if err := c.Create(ctx, cluster); err != nil {
		return err
	}

	By("deploy cloudprovider secret into namespace")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cloudprovider",
			Namespace: namespaceName,
		},
		Data: map[string][]byte{
			openstack.AuthURL:    []byte(*authURL),
			openstack.DomainName: []byte(*domainName),
			openstack.Password:   []byte(*password),
			openstack.Region:     []byte(*region),
			openstack.TenantName: []byte(*tenantName),
			openstack.UserName:   []byte(*userName),
		},
	}
	if err := c.Create(ctx, secret); err != nil {
		return err
	}

	By("create infrastructure")
	infra, err = newInfrastructure(namespaceName, providerConfig)
	if err != nil {
		return err
	}

	if err := c.Create(ctx, infra); err != nil {
		return err
	}

	By("wait until infrastructure is created")
	if err := common.WaitUntilExtensionCRReady(
		ctx,
		c,
		logger,
		func() runtime.Object { return &extensionsv1alpha1.Infrastructure{} },
		"Infrastucture",
		infra.Namespace,
		infra.Name,
		10*time.Second,
		30*time.Second,
		16*time.Minute,
		nil,
	); err != nil {
		return err
	}

	By("decode infrastucture status")
	if err := c.Get(ctx, client.ObjectKey{Namespace: infra.Namespace, Name: infra.Name}, infra); err != nil {
		return err
	}

	providerStatus := &openstackv1alpha1.InfrastructureStatus{}
	if _, _, err := decoder.Decode(infra.Status.ProviderStatus.Raw, nil, providerStatus); err != nil {
		return err
	}

	By("verify infrastructure creation")
	infrastructureIdentifiers = verifyCreation(ctx, openstackClient, infra, providerStatus, providerConfig, pointer.StringPtr(vpcCIDR))

	return nil
}

func newProviderConfig(router *openstackv1alpha1.Router) *openstackv1alpha1.InfrastructureConfig {
	return &openstackv1alpha1.InfrastructureConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: openstackv1alpha1.SchemeGroupVersion.String(),
			Kind:       "InfrastructureConfig",
		},
		FloatingPoolName: *floatingPoolName,
		Networks: openstackv1alpha1.Networks{
			Router:  router,
			Workers: vpcCIDR,
			// Internal: pointer.StringPtr("10.250.112.0/22"),
			// FlowLogs: &openstackv1alpha1.FlowLogs{
			// 	AggregationInterval: pointer.StringPtr("INTERVAL_5_SEC"),
			// 	FlowSampling:        pointer.Float32Ptr(0.2),
			// 	Metadata:            pointer.StringPtr("INCLUDE_ALL_METADATA"),
			// },
		},
	}
}

func newCloudProfileConfig(region string, authURL string) *openstackv1alpha1.CloudProfileConfig {
	return &openstackv1alpha1.CloudProfileConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: openstackv1alpha1.SchemeGroupVersion.String(),
			Kind:       "CloudProfileConfig",
		},
		KeyStoneURLs: []openstackv1alpha1.KeyStoneURL{
			openstackv1alpha1.KeyStoneURL{
				Region: region,
				URL:    authURL,
			},
		},
	}
}

func newInfrastructure(namespace string, providerConfig *openstackv1alpha1.InfrastructureConfig) (*extensionsv1alpha1.Infrastructure, error) {
	const sshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcSZKq0lM9w+ElLp9I9jFvqEFbOV1+iOBX7WEe66GvPLOWl9ul03ecjhOf06+FhPsWFac1yaxo2xj+SJ+FVZ3DdSn4fjTpS9NGyQVPInSZveetRw0TV0rbYCFBTJuVqUFu6yPEgdcWq8dlUjLqnRNwlelHRcJeBfACBZDLNSxjj0oUz7ANRNCEne1ecySwuJUAz3IlNLPXFexRT0alV7Nl9hmJke3dD73nbeGbQtwvtu8GNFEoO4Eu3xOCKsLw6ILLo4FBiFcYQOZqvYZgCb4ncKM52bnABagG54upgBMZBRzOJvWp0ol+jK3Em7Vb6ufDTTVNiQY78U6BAlNZ8Xg+LUVeyk1C6vWjzAQf02eRvMdfnRCFvmwUpzbHWaVMsQm8gf3AgnTUuDR0ev1nQH/5892wZA86uLYW/wLiiSbvQsqtY1jSn9BAGFGdhXgWLAkGsd/E1vOT+vDcor6/6KjHBm0rG697A3TDBRkbXQ/1oFxcM9m17RteCaXuTiAYWMqGKDoJvTMDc4L+Uvy544pEfbOH39zfkIYE76WLAFPFsUWX6lXFjQrX3O7vEV73bCHoJnwzaNd03PSdJOw+LCzrTmxVezwli3F9wUDiBRB0HkQxIXQmncc1HSecCKALkogIK+1e1OumoWh6gPdkF4PlTMUxRitrwPWSaiUIlPfCpQ== your_email@example.com"

	providerConfigJSON, err := json.Marshal(&providerConfig)
	if err != nil {
		return nil, err
	}

	return &extensionsv1alpha1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "infrastructure",
			Namespace: namespace,
		},
		Spec: extensionsv1alpha1.InfrastructureSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: openstack.Type,
				ProviderConfig: &runtime.RawExtension{
					Raw: providerConfigJSON,
				},
			},
			SecretRef: corev1.SecretReference{
				Name:      "cloudprovider",
				Namespace: namespace,
			},
			Region:       *region,
			SSHPublicKey: []byte(sshPublicKey),
		},
	}, nil
}

func generateNamespaceName() (string, error) {
	suffix, err := gardenerutils.GenerateRandomStringFromCharset(5, "0123456789abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		return "", err
	}

	return "openstack-infra-it--" + suffix, nil
}

func prepareNewNetwork(ctx context.Context, logger *logrus.Entry, networkName string, routerName string, openstackClient *OpenstackClient) error {

	// network := &compute.Network{
	// 	Name:                  networkName,
	// 	AutoCreateSubnetworks: false,
	// 	RoutingConfig: &compute.NetworkRoutingConfig{
	// 		RoutingMode: "REGIONAL",
	// 	},
	// 	ForceSendFields: []string{"AutoCreateSubnetworks"},
	// }
	// networkOp, err := computeService.Networks.Insert(project, network).Context(ctx).Do()
	// if err != nil {
	// 	return err
	// }
	// logger.Infof("Waiting until network '%s' is created...", networkName)
	// if err := waitForOperation(ctx, project, computeService, networkOp); err != nil {
	// 	return err
	// }

	// router := &compute.Router{
	// 	Name:    routerName,
	// 	Network: networkOp.TargetLink,
	// }
	// routerOp, err := computeService.Routers.Insert(project, *region, router).Context(ctx).Do()
	// if err != nil {
	// 	return err
	// }
	// logger.Infof("Waiting until router '%s' is created...", routerName)
	// if err := waitForOperation(ctx, project, computeService, routerOp); err != nil {
	// 	return err
	// }

	return nil
}

func teardownNetwork(ctx context.Context, logger *logrus.Entry, networkName string, routerName string, openstackClient *OpenstackClient) error {

	/*
		routerOp, err := computeService.Routers.Delete(project, *region, routerName).Context(ctx).Do()
		if err != nil {
			return err
		}

		logger.Infof("Waiting until router '%s' is deleted...", routerName)
		if err := waitForOperation(ctx, project, computeService, routerOp); err != nil {
			return err
		}

		networkOp, err := computeService.Networks.Delete(project, networkName).Context(ctx).Do()
		if err != nil {
			return err
		}

		logger.Infof("Waiting until network '%s' is deleted...", networkName)
		if err := waitForOperation(ctx, project, computeService, networkOp); err != nil {
			return err
		}
	*/

	return nil
}

// func waitForOperation(ctx context.Context, project string, computeService *compute.Service, op *compute.Operation) error {
// 	return wait.PollUntil(5*time.Second, func() (bool, error) {
// 		var (
// 			currentOp *compute.Operation
// 			err       error
// 		)

// 		if op.Region != "" {
// 			region := getResourceNameFromSelfLink(op.Region)
// 			currentOp, err = computeService.RegionOperations.Get(project, region, op.Name).Context(ctx).Do()
// 		} else {
// 			currentOp, err = computeService.GlobalOperations.Get(project, op.Name).Context(ctx).Do()
// 		}

// 		if err != nil {
// 			return false, err
// 		}
// 		return currentOp.Status == "DONE", nil
// 	}, ctx.Done())
// }

// func getResourceNameFromSelfLink(link string) string {
// 	parts := strings.Split(link, "/")
// 	return parts[len(parts)-1]
// }

type infrastructureIdentifiers struct {
	networkID *string
}

func verifyCreation(
	ctx context.Context,
	openstackClient *OpenstackClient,
	infra *extensionsv1alpha1.Infrastructure,
	infraStatus *openstackv1alpha1.InfrastructureStatus,
	providerConfig *openstackv1alpha1.InfrastructureConfig,
	cidr *string,
) (infrastructureIdentifier infrastructureIdentifiers) {
	// network
	net, err := networks.Get(openstackClient.NetworkingClient, infraStatus.Networks.ID).Extract()
	Expect(err).NotTo(HaveOccurred())
	infrastructureIdentifier.networkID = &net.ID

	// subnets

	// subnetNodes, err := computeService.Subnetworks.Get(project, *region, infra.Namespace+"-nodes").Context(ctx).Do()
	// Expect(err).NotTo(HaveOccurred())
	// Expect(subnetNodes.Network).To(Equal(network.SelfLink))
	// Expect(subnetNodes.IpCidrRange).To(Equal(providerConfig.Networks.Workers))
	// Expect(subnetNodes.LogConfig.Enable).To(BeTrue())
	// Expect(subnetNodes.LogConfig.AggregationInterval).To(Equal("INTERVAL_5_SEC"))
	// Expect(subnetNodes.LogConfig.FlowSampling).To(Equal(float64(0.2)))
	// Expect(subnetNodes.LogConfig.Metadata).To(Equal("INCLUDE_ALL_METADATA"))

	// subnetInternal, err := computeService.Subnetworks.Get(project, *region, infra.Namespace+"-internal").Context(ctx).Do()
	// Expect(err).NotTo(HaveOccurred())
	// Expect(subnetInternal.Network).To(Equal(network.SelfLink))
	// Expect(subnetInternal.IpCidrRange).To(Equal("10.250.112.0/22"))

	// // router

	// router, err := computeService.Routers.Get(project, *region, infra.Namespace+"-cloud-router").Context(ctx).Do()
	// Expect(err).NotTo(HaveOccurred())
	// Expect(router.Network).To(Equal(network.SelfLink))
	// Expect(router.Nats).To(HaveLen(1))

	// routerNAT := router.Nats[0]
	// Expect(routerNAT.Name).To(Equal(infra.Namespace + "-cloud-nat"))
	// Expect(routerNAT.NatIpAllocateOption).To(Equal("AUTO_ONLY"))
	// Expect(routerNAT.SourceSubnetworkIpRangesToNat).To(Equal("LIST_OF_SUBNETWORKS"))
	// Expect(routerNAT.MinPortsPerVm).To(Equal(int64(2048)))
	// Expect(routerNAT.LogConfig.Enable).To(BeTrue())
	// Expect(routerNAT.LogConfig.Filter).To(Equal("ERRORS_ONLY"))
	// Expect(routerNAT.Subnetworks).To(HaveLen(1))
	// Expect(routerNAT.Subnetworks[0].Name).To(Equal(subnetNodes.SelfLink))
	// Expect(routerNAT.Subnetworks[0].SourceIpRangesToNat).To(Equal([]string{"ALL_IP_RANGES"}))

	// // firewalls

	// allowInternalAccess, err := computeService.Firewalls.Get(project, infra.Namespace+"-allow-internal-access").Context(ctx).Do()
	// Expect(err).NotTo(HaveOccurred())

	// Expect(allowInternalAccess.Network).To(Equal(network.SelfLink))
	// Expect(allowInternalAccess.SourceRanges).To(Equal([]string{"10.0.0.0/8"}))
	// Expect(allowInternalAccess.Allowed).To(ConsistOf([]*compute.FirewallAllowed{
	// 	{
	// 		IPProtocol: "icmp",
	// 	},
	// 	{
	// 		IPProtocol: "ipip",
	// 	},
	// 	{
	// 		IPProtocol: "tcp",
	// 		Ports:      []string{"1-65535"},
	// 	},
	// 	{
	// 		IPProtocol: "udp",
	// 		Ports:      []string{"1-65535"},
	// 	},
	// }))

	// allowExternalAccess, err := computeService.Firewalls.Get(project, infra.Namespace+"-allow-external-access").Context(ctx).Do()
	// Expect(err).NotTo(HaveOccurred())

	// Expect(allowExternalAccess.Network).To(Equal(network.SelfLink))
	// Expect(allowExternalAccess.SourceRanges).To(Equal([]string{"0.0.0.0/0"}))
	// Expect(allowExternalAccess.Allowed).To(ConsistOf([]*compute.FirewallAllowed{
	// 	{
	// 		IPProtocol: "tcp",
	// 		Ports:      []string{"80", "443"},
	// 	},
	// }))

	// allowHealthChecks, err := computeService.Firewalls.Get(project, infra.Namespace+"-allow-health-checks").Context(ctx).Do()
	// Expect(err).NotTo(HaveOccurred())

	// Expect(allowHealthChecks.Network).To(Equal(network.SelfLink))
	// Expect(allowHealthChecks.SourceRanges).To(ConsistOf([]string{
	// 	"35.191.0.0/16",
	// 	"209.85.204.0/22",
	// 	"209.85.152.0/22",
	// 	"130.211.0.0/22",
	// }))
	// Expect(allowHealthChecks.Allowed).To(ConsistOf([]*compute.FirewallAllowed{
	// 	{
	// 		IPProtocol: "tcp",
	// 		Ports:      []string{"30000-32767"},
	// 	},
	// 	{
	// 		IPProtocol: "udp",
	// 		Ports:      []string{"30000-32767"},
	// 	},
	// }))
	return infrastructureIdentifier
}

func verifyDeletion(
	ctx context.Context,
	openstackClient *OpenstackClient,
	infrastructureIdentifier infrastructureIdentifiers,
) {
	// network
	_, err := networks.Get(openstackClient.NetworkingClient, *infrastructureIdentifier.networkID).Extract()
	Expect(err).To(BeNotFoundError())

	/*
		// subnets

		_, err = computeService.Subnetworks.Get(project, *region, infra.Namespace+"-nodes").Context(ctx).Do()
		Expect(err).To(BeNotFoundError())

		_, err = computeService.Subnetworks.Get(project, *region, infra.Namespace+"-internal").Context(ctx).Do()
		Expect(err).To(BeNotFoundError())

		// router

		if providerConfig.Networks.VPC == nil || providerConfig.Networks.VPC.CloudRouter == nil {
			_, err = computeService.Routers.Get(project, *region, infra.Namespace+"-cloud-router").Context(ctx).Do()
			Expect(err).To(BeNotFoundError())
		}

		// firewalls

		_, err = computeService.Firewalls.Get(project, infra.Namespace+"-allow-internal-access").Context(ctx).Do()
		Expect(err).To(BeNotFoundError())

		_, err = computeService.Firewalls.Get(project, infra.Namespace+"-allow-external-access").Context(ctx).Do()
		Expect(err).To(BeNotFoundError())

		_, err = computeService.Firewalls.Get(project, infra.Namespace+"-allow-health-checks").Context(ctx).Do()
		Expect(err).To(BeNotFoundError())
	*/
}
