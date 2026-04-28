package main

import (
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"

	ctrl "sigs.k8s.io/controller-runtime"

	"example.com/secret-cert-controller/controllers"
)

func main() {
	ctrl.SetLogger(klogr.New())
	klog.Info("Starting secret-cert-controller...")

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	klog.Info("Kubernetes schemes registered successfully")

	klog.Info("Creating controller manager...")
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		klog.Errorf("Failed to create controller manager: %v", err)
		os.Exit(1)
	}
	klog.Info("Controller manager created successfully")

	klog.Info("Setting up SecretReconciler...")
	if err = (&controllers.SecretReconciler{
		Client: mgr.GetClient(),
		Scheme: scheme,
	}).SetupWithManager(mgr); err != nil {
		klog.Errorf("Failed to setup SecretReconciler: %v", err)
		os.Exit(1)
	}
	klog.Info("SecretReconciler setup completed successfully")

	klog.Info("Starting controller manager...")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		klog.Errorf("Failed to start controller manager: %v", err)
		os.Exit(1)
	}
	
	klog.Info("Controller manager stopped gracefully")
}
