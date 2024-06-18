package util

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/red-hat-storage/ocs-operator/v4/services"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	// Name of existing public key which is used ocs-operator
	onboardingValidationPublicKeySecretName  = "onboarding-ticket-key"
	onboardingValidationPrivateKeySecretName = "onboarding-private-key"
	storageClusterName                       = "ocs-storagecluster"
)

// GenerateOnboardingToken generates a token valid for a duration of "tokenLifetimeInHours".
// The token content is predefined and signed by the private key which'll be read from supplied "privateKeyPath".
func GenerateOnboardingToken(tokenLifetimeInHours int, privateKeyPath string) (string, error) {
	tokenExpirationDate := time.Now().
		Add(time.Duration(tokenLifetimeInHours) * time.Hour).
		Unix()

	payload, err := json.Marshal(services.OnboardingTicket{
		ID:             uuid.New().String(),
		ExpirationDate: tokenExpirationDate,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal the payload: %v", err)
	}

	encodedPayload := base64.StdEncoding.EncodeToString(payload)
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(payload)
	if err != nil {
		return "", fmt.Errorf("failed to hash onboarding token payload: %v", err)
	}

	privateKey, err := readAndDecodePrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to read and decode private key: %v", err)
	}

	msgHashSum := msgHash.Sum(nil)
	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, msgHashSum)
	if err != nil {
		return "", fmt.Errorf("failed to sign private key: %v", err)
	}

	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s", encodedPayload, encodedSignature), nil
}

func readAndDecodePrivateKey() (*rsa.PrivateKey, error) {
	cl, err := newClient()
	if err != nil {
		klog.Exitf("failed to create client: %v", err)
	}
	ctx := context.Background()
	operatorNamespace, err := GetOperatorNamespace()
	if err != nil {
		klog.Exitf("unable to get operator namespace: %v", err)
	}

	privateSecret := &corev1.Secret{}
	privateSecret.Name = onboardingValidationPrivateKeySecretName
	privateSecret.Namespace = operatorNamespace
	err = cl.Get(ctx, types.NamespacedName{Namespace: operatorNamespace}, privateSecret)
	if err != nil && !kerrors.IsNotFound(err) {
		klog.Exitf("failed to delete private secret: %v", err)
	}

	Block, _ := pem.Decode(privateSecret.Data["key"])
	privateKey, err := x509.ParsePKCS1PrivateKey(Block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	return privateKey, nil
}

func newClient() (client.Client, error) {
	klog.Info("Setting up k8s client")
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	config, err := config.GetConfig()
	if err != nil {
		return nil, err
	}
	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return k8sClient, nil
}
