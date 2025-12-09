# Ephemeral Container Lab Exercises

## 🎯 **Overview**

This document provides comprehensive lab exercises for testing ephemeral container vulnerabilities in Kubernetes environments. These exercises are designed to help security professionals understand and test ephemeral container attack vectors.

## 📋 **Lab Prerequisites**

- Kubernetes cluster with ephemeral containers enabled
- kubectl configured and working
- KubeShadow tool installed
- Basic understanding of Kubernetes security concepts

## 🚀 **Exercise 1: Basic Ephemeral Container Access**

### **Objective**
Test basic ephemeral container functionality and identify security risks.

### **Steps**
1. Deploy the target pod:
   ```bash
   kubectl apply -f modules/lab/manifests/11-ephemeral-attack-scenarios.yaml
   ```

2. List pods in the ephemeral-attack-lab namespace:
   ```bash
   kubectl get pods -n ephemeral-attack-lab
   ```

3. Test ephemeral container access:
   ```bash
   kubectl debug ephemeral-target-pod -n ephemeral-attack-lab -it --image=alpine:latest --target=target-container
   ```

4. Run KubeShadow recon to detect vulnerabilities:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab
   ```

### **Expected Results**
- Ephemeral container should be created successfully
- KubeShadow should detect security vulnerabilities
- Access to target container should be possible

## 🔍 **Exercise 2: Privileged Ephemeral Container Exploitation**

### **Objective**
Test privileged ephemeral container attacks and host access.

### **Steps**
1. Deploy the privileged ephemeral pod:
   ```bash
   kubectl apply -f modules/lab/manifests/11-ephemeral-attack-scenarios.yaml
   ```

2. Create a privileged ephemeral container:
   ```bash
   kubectl debug privileged-ephemeral-pod -n ephemeral-attack-lab -it --image=alpine:latest --privileged --target=privileged-container
   ```

3. Test host access from ephemeral container:
   ```bash
   # Inside the ephemeral container
   ls /host
   cat /host/etc/passwd
   ps aux
   ```

4. Run KubeShadow recon to detect privileged access:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab
   ```

### **Expected Results**
- Privileged ephemeral container should have host access
- KubeShadow should detect privileged container vulnerabilities
- Host filesystem should be accessible

## 🐳 **Exercise 3: Docker Socket Access via Ephemeral Containers**

### **Objective**
Test Docker socket access through ephemeral containers.

### **Steps**
1. Deploy the Docker socket pod:
   ```bash
   kubectl apply -f modules/lab/manifests/11-ephemeral-attack-scenarios.yaml
   ```

2. Create ephemeral container with Docker socket access:
   ```bash
   kubectl debug docker-socket-ephemeral-pod -n ephemeral-attack-lab -it --image=alpine:latest --target=docker-socket-container
   ```

3. Test Docker socket access:
   ```bash
   # Inside the ephemeral container
   apk add --no-cache docker
   docker ps
   docker images
   ```

4. Run KubeShadow recon to detect Docker socket access:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab
   ```

### **Expected Results**
- Docker socket should be accessible
- KubeShadow should detect Docker socket vulnerabilities
- Docker commands should work from ephemeral container

## 🔓 **Exercise 4: Cgroup Escape via Ephemeral Containers**

### **Objective**
Test cgroup escape techniques using ephemeral containers.

### **Steps**
1. Deploy the cgroup escape pod:
   ```bash
   kubectl apply -f modules/lab/manifests/11-ephemeral-attack-scenarios.yaml
   ```

2. Create ephemeral container for cgroup escape:
   ```bash
   kubectl debug cgroup-escape-ephemeral-pod -n ephemeral-attack-lab -it --image=alpine:latest --target=cgroup-escape-container
   ```

3. Test cgroup escape:
   ```bash
   # Inside the ephemeral container
   cat /host/proc/1/cgroup
   ls /host/sys/fs/cgroup
   ```

4. Run KubeShadow recon to detect cgroup vulnerabilities:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab
   ```

### **Expected Results**
- Cgroup information should be accessible
- KubeShadow should detect cgroup escape vulnerabilities
- Host process information should be visible

## 🎯 **Exercise 5: Comprehensive Security Assessment**

### **Objective**
Perform comprehensive security assessment of ephemeral container vulnerabilities.

### **Steps**
1. Deploy all ephemeral attack scenarios:
   ```bash
   kubectl apply -f modules/lab/manifests/11-ephemeral-attack-scenarios.yaml
   ```

2. Run comprehensive KubeShadow scan:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab --comprehensive
   ```

3. Test multiple attack vectors:
   ```bash
   # Test privileged access
   kubectl debug privileged-ephemeral-pod -n ephemeral-attack-lab -it --image=alpine:latest --privileged
   
   # Test Docker socket access
   kubectl debug docker-socket-ephemeral-pod -n ephemeral-attack-lab -it --image=alpine:latest
   
   # Test cgroup escape
   kubectl debug cgroup-escape-ephemeral-pod -n ephemeral-attack-lab -it --image=alpine:latest
   ```

4. Analyze results and document findings:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab --output report.json
   ```

### **Expected Results**
- All ephemeral container vulnerabilities should be detected
- Comprehensive security report should be generated
- Multiple attack vectors should be identified

## 🛡️ **Exercise 6: Defense and Mitigation**

### **Objective**
Implement security controls to mitigate ephemeral container risks.

### **Steps**
1. Create Pod Security Policy:
   ```yaml
   apiVersion: policy/v1beta1
   kind: PodSecurityPolicy
   metadata:
     name: ephemeral-security-policy
   spec:
     privileged: false
     allowPrivilegeEscalation: false
     requiredDropCapabilities:
       - ALL
     volumes:
       - 'configMap'
       - 'emptyDir'
       - 'projected'
       - 'secret'
       - 'downwardAPI'
       - 'persistentVolumeClaim'
   ```

2. Create Network Policy:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: ephemeral-network-policy
     namespace: ephemeral-attack-lab
   spec:
     podSelector: {}
     policyTypes:
     - Ingress
     - Egress
     ingress:
     - from:
       - namespaceSelector:
           matchLabels:
             name: ephemeral-attack-lab
     egress:
     - to:
       - namespaceSelector:
           matchLabels:
             name: ephemeral-attack-lab
   ```

3. Test security controls:
   ```bash
   kubectl apply -f ephemeral-security-policy.yaml
   kubectl apply -f ephemeral-network-policy.yaml
   ```

4. Verify controls are working:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab
   ```

### **Expected Results**
- Security policies should be enforced
- Network policies should restrict traffic
- KubeShadow should detect improved security posture

## 📊 **Exercise 7: Monitoring and Detection**

### **Objective**
Implement monitoring and detection for ephemeral container attacks.

### **Steps**
1. Enable audit logging:
   ```bash
   kubectl create configmap audit-policy --from-file=audit-policy.yaml
   ```

2. Monitor ephemeral container creation:
   ```bash
   kubectl get events -n ephemeral-attack-lab --watch
   ```

3. Test detection capabilities:
   ```bash
   # Create ephemeral container
   kubectl debug ephemeral-target-pod -n ephemeral-attack-lab -it --image=alpine:latest
   
   # Check audit logs
   kubectl logs -n kube-system -l component=kube-apiserver
   ```

4. Run KubeShadow with monitoring:
   ```bash
   ./kubeshadow recon --namespace ephemeral-attack-lab --monitor
   ```

### **Expected Results**
- Audit logs should capture ephemeral container creation
- Events should be generated for security violations
- Monitoring should detect suspicious activity

## 🧹 **Cleanup**

### **Steps**
1. Remove ephemeral containers:
   ```bash
   kubectl delete pod ephemeral-target-pod -n ephemeral-attack-lab
   kubectl delete pod privileged-ephemeral-pod -n ephemeral-attack-lab
   kubectl delete pod docker-socket-ephemeral-pod -n ephemeral-attack-lab
   kubectl delete pod cgroup-escape-ephemeral-pod -n ephemeral-attack-lab
   ```

2. Remove namespace:
   ```bash
   kubectl delete namespace ephemeral-attack-lab
   ```

3. Remove security policies:
   ```bash
   kubectl delete psp ephemeral-security-policy
   kubectl delete networkpolicy ephemeral-network-policy -n ephemeral-attack-lab
   ```

## 📝 **Lab Report Template**

### **Vulnerabilities Found**
- [ ] Privileged ephemeral containers
- [ ] Docker socket access
- [ ] Cgroup escape
- [ ] Host filesystem access
- [ ] Process namespace escape
- [ ] Network access
- [ ] Resource abuse

### **Security Controls Tested**
- [ ] Pod Security Policies
- [ ] Network Policies
- [ ] RBAC restrictions
- [ ] Audit logging
- [ ] Monitoring

### **Recommendations**
1. Disable privileged ephemeral containers
2. Restrict Docker socket access
3. Implement network segmentation
4. Enable audit logging
5. Monitor ephemeral container usage
6. Use least privilege principles
7. Regular security assessments

## 🎓 **Learning Objectives**

After completing these exercises, you should understand:
- How ephemeral containers work in Kubernetes
- Security risks associated with ephemeral containers
- Attack vectors and exploitation techniques
- Defense and mitigation strategies
- Monitoring and detection methods
- Best practices for ephemeral container security

## 🔗 **Additional Resources**

- [Kubernetes Ephemeral Containers Documentation](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [KubeShadow Documentation](../README.md)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)