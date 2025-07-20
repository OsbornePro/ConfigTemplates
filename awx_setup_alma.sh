#!/bin/bash
# NOT WORKING YET
#
#
# This script contains the commands I used to setup AWX on Alma Linux 10 server
#Linux toborALMA.osbornepro.com 6.12.0-55.20.1.el10_0.x86_64 #1 SMP PREEMPT_DYNAMIC Tue Jul  8 14:26:52 EDT 2025 x86_64 GNU/Linux
#NAME="AlmaLinux"
#VERSION="10.0 (Purple Lion)"
#ID="almalinux"
#ID_LIKE="rhel centos fedora"
#VERSION_ID="10.0"
#PLATFORM_ID="platform:el10"
#PRETTY_NAME="AlmaLinux 10.0 (Purple Lion)"
#ANSI_COLOR="0;34"
#LOGO="fedora-logo-icon"
#CPE_NAME="cpe:/o:almalinux:almalinux:10::baseos"
#HOME_URL="https://almalinux.org/"
#DOCUMENTATION_URL="https://wiki.almalinux.org/"
#VENDOR_NAME="AlmaLinux"
#VENDOR_URL="https://almalinux.org/"
#BUG_REPORT_URL="https://bugs.almalinux.org/"
#
#ALMALINUX_MANTISBT_PROJECT="AlmaLinux-10"
#ALMALINUX_MANTISBT_PROJECT_VERSION="10.0"
#REDHAT_SUPPORT_PRODUCT="AlmaLinux"
#REDHAT_SUPPORT_PRODUCT_VERSION="10.0"
#SUPPORT_END=2035-06-01

# CREATE THE USER ACCOUNT TO USE 
sudo useradd -m -d /var/lib/ansible ansible-user
SUDO_GROUP=$(sudo grep -E '^%[a-zA-Z0-9_-]+\s+ALL=\(ALL(:ALL)?\)\s+ALL' /etc/sudoers | awk '{print $1}' | sed 's/^%//')
SUDO_GROUP=${SUDO_GROUP:-wheel}
sudo usermod -aG "$SUDO_GROUP" ansible-user
echo 123Sup3rStr0ngP455w0rdY0uN33dToCh4ng3321 | sudo passwd --stdin ansible-user
sudo tee /var/lib/ansible/.bashrc > /dev/null << 'EOF'
export PATH=$PATH:/usr/local/bin
export KUBECONFIG=$HOME/.kube/config
EOF
sudo chown -R ansible-user:ansible-user /var/lib/ansible
sudo -u ansible-user -i
source ~/.bashrc
mkdir ~/.ssh
touch ~/.ssh/authorized_keys
ssh-keygen -t ed25519 -f ~/.ssh/ansible_key
grep -qxFf ~/.ssh/ansible_key.pub ~/.ssh/authorized_keys || cat ~/.ssh/ansible_key.pub >> ~/.ssh/authorized_keys


# SET SELINUX TO PERMISSIVE UNTIL SETUP COMPLETES
sudo setenforce 0
getenforce


# INSTALL REQUIREMENTS
sudo dnf -y install tar git
sudo -i
cd /usr/local/bin
curl -sfL https://get.k3s.io | sh -
curl -s https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh | bash
exit
sudo chown root:root /usr/local/bin/kustomize
sudo chmod 755 /usr/local/bin/kustomize
/usr/local/bin/kubectl version


# CREATE KUSTOMIZATION CONFIG LOCATIONS
mkdir -p ~/.kube
cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chmod 600 ~/.kube/config
chown $(id -u):$(id -g) ~/.kube/config


# CONFIGURE KUSTOMIZATION
cat << 'EOF' > kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  # Find the latest tag here: https://github.com/ansible/awx-operator/releases
  - github.com/ansible/awx-operator/config/default?ref=1.1.4
  
# Set the image tags to match the git version from above
images:
  - name: quay.io/ansible/awx-operator
    newTag: 1.1.4

# Specify a custom namespace in which to install AWX
namespace: awx
EOF
kustomize build . | kubectl apply -f -
kustomize edit fix --vars


# VERIFY AWX POD IS RUNNING BEFORE CONTINUING
if kubectl get pods -n awx | grep -q "awx-operator-controller-manager.*Running"; then
    echo "AWX Operator is running. Proceeding to create awx-demo.yaml."
    cat << 'EOF' > awx-demo.yaml
---
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: awx
spec:
  service_type: nodeport
  nodeport_port: 30080
  #projects_persistence: true
  #projects_storage_class: rook-ceph
  #projects_storage_size: 10Gi
EOF

    echo "awx-demo.yaml created successfully."
else
    echo "AWX operator is not running correctly. Troubleshoot the failure of the command 'kubectl get pods -n awx'."
    exit 1
fi

# OVERWRITE kustomization.yaml FILE TO ACCOMDATE ABOVE
kubectl delete awx awx -n awx
kustomize build . | kubectl delete -f -
cat << 'EOF' > awx-demo.yaml
---
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: awx
spec:
  service_type: nodeport
  nodeport_port: 30080
  #projects_persistence: true
  #projects_storage_class: rook-ceph
  #projects_storage_size: 10Gi
EOF

cat << 'EOF' > kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  # Find the latest tag here: https://github.com/ansible/awx-operator/releases
  - github.com/ansible/awx-operator/config/default?ref=1.1.4
  - awx-demo.yaml

# Set the image tags to match the git version from above
images:
  - name: quay.io/ansible/awx-operator
    newTag: 1.1.4

# Specify a custom namespace in which to install AWX
namespace: awx
EOF

kubectl config set-context --current --namespace=awx
kustomize build . | kubectl apply -f -
echo "Waiting for AWX operator to complete playbook"
NAMESPACE="awx"
DEPLOYMENT="awx-operator-controller-manager"
CONTAINER="awx-manager"
PATTERN="PLAY RECAP"
# Get the pod name (assuming single pod for deployment)
# Monitor logs manually using this command
#kubectl logs -f deployments/awx-operator-controller-manager -c awx-manager
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=awx-operator-controller-manager -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD_NAME" ]; then
  echo "ERROR: AWX operator pod not found in namespace $NAMESPACE"
  exit 1
fi
# Tail logs until the pattern is found, then exit
kubectl logs -n $NAMESPACE -f $POD_NAME -c $CONTAINER | while IFS= read -r line; do
  echo "$line"
  if echo "$line" | grep -q "$PATTERN"; then
    echo "Detected '$PATTERN' in logs, continuing..."
    pkill -P $$ kubectl # kill the kubectl logs tail
    break
  fi
done
echo "Completed succesfully! Verify below output"
echo "
# You should see something like:"
echo "----------------------------------------------------------------------------------------------"
echo "#NAME                                               READY   STATUS    RESTARTS      AGE"
echo "#awx-postgres-13-0                                  1/1     Running   2 (43h ago)   4d4h"
echo "#awx-67d97b57d9-hdtqb                               4/4     Running   8 (43h ago)   4d4h"
echo "#awx-operator-controller-manager-78c7c99946-7dcm9   2/2     Running   8 (43h ago)   4d5h"
echo "----------------------------------------------------------------------------------------------"

echo "Your results are below"
echo "----------------------------------------------------------------------------------------------"
kubectl get pods -n awx
echo "----------------------------------------------------------------------------------------------"

# GET THE TEMP PASSWORD
echo "AWX should now be accessible at https://$($hostname):30080"
kubectl get secret awx-demo-admin-password -o jsonpath=”{.data.password}” | base64 --decode
echo "Username is 'admin'"
