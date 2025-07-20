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

# Run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] This script must be run as root. Exiting."
    exit 1
fi

set -e  # Exit immediately on any error
set -o pipefail  # Catch errors in piped commands

# SET SELINUX TO PERMISSIVE UNTIL SETUP COMPLETES
setenforce 0

# DISABLE FIREWALL SO CONTAINERS CAN TALK ON SETUP
firewall-cmd --add-port=30080/tcp --permanent
firewall-cmd --reload

# CREATE THE USER ACCOUNT TO USE 
USERNAME="ansible-user"
USER_HOME="/var/lib/ansible"
USER_PASSWORD="123Sup3rStr0ngP455w0rdY0uN33dToCh4ng3321"

# Check if the user already exists
if id "$USERNAME" &>/dev/null; then
    echo "[INFO] User '$USERNAME' already exists. Skipping creation."
else
    echo "[INFO] Creating user '$USERNAME'"

    # Create the user with specified home directory
    useradd -m -d "$USER_HOME" "$USERNAME"

    # Detect the main sudo group
    SUDO_GROUP=$(grep -E '^%[a-zA-Z0-9_-]+\s+ALL=\(ALL(:ALL)?\)\s+ALL' /etc/sudoers | awk '{print $1}' | sed 's/^%//')
    SUDO_GROUP=${SUDO_GROUP:-wheel}

    # Add user to sudo group
    usermod -aG "$SUDO_GROUP" "$USERNAME"

    # Set password for the user
    echo "$USER_PASSWORD" | sudo passwd --stdin "$USERNAME"

    # Add useful environment variables to .bashrc
    sudo -u $USERNAME tee "$USER_HOME/.bashrc" > /dev/null << 'EOF'
export PATH=$PATH:/usr/local/bin
export KUBECONFIG=$HOME/.kube/config
EOF

    chown -R "$USERNAME:$USERNAME" "$USER_HOME"
    echo "[INFO] User '$USERNAME' created and configured."
fi

# Now configure SSH keys only if not already set up
sudo -u "$USERNAME" bash <<'EOSU'
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/ansible_key ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/ansible_key -N ""
fi

# Ensure the public key is in authorized_keys
grep -qxFf ~/.ssh/ansible_key.pub ~/.ssh/authorized_keys 2>/dev/null || cat ~/.ssh/ansible_key.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
EOSU


# INSTALL REQUIREMENTS
echo "[QUESTION] Which container engine do you want to install?"
echo "1) Podman"
echo "2) Docker"
read -rp "Enter 1 or 2: " choice

# Install common dependencies
dnf -y install tar git python3 python3-pip

if [ "$choice" == "1" ]; then
    dnf -y install podman
    /bin/podman --version
    usermod --add-subuids 100000-165535 --add-subgids 100000-165535 ansible-user
    sudo -u ansible-user bash <<'EOF'
mkdir -p ~/.config/containers
mkdir -p ~/.local/share/containers
EOF

elif [ "$choice" == "2" ]; then
    dnf install -y dnf-plugins-core
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io
    systemctl enable --now docker
    /usr/bin/docker --version

else
    echo "[ERROR] Invalid choice. Exiting."
    exit 1
fi

# Install K3s
echo "[INFO] Installing k3s"
curl -sfL https://get.k3s.io | sudo sh -

# Download and install kustomize
echo "[INFO] Installing kustomize"
KUSTOMIZE_INSTALL_DIR="/usr/local/bin"
TMP_DIR=$(mktemp -d)
curl -s https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh | bash -s -- "$TMP_DIR"
mv "$TMP_DIR"/kustomize "$KUSTOMIZE_INSTALL_DIR"
chown root:root "$KUSTOMIZE_INSTALL_DIR/kustomize"
chmod 755 "$KUSTOMIZE_INSTALL_DIR/kustomize"
rm -rf -- "$TMP_DIR"

# CREATE KUSTOMIZATION CONFIG LOCATIONS
sudo -u "$USERNAME" mkdir -p "$(eval echo ~$USERNAME)/.kube"
cp /etc/rancher/k3s/k3s.yaml "$(eval echo ~$USERNAME)/.kube/config"
chmod 600 "$(eval echo ~$USERNAME)/.kube/config"
chown $(id -u "$USERNAME"):$(id -g "$USERNAME") "$(eval echo ~$USERNAME)/.kube/config"


# Create a systemd drop-in override directory for k3s
mkdir -p /etc/systemd/system/k3s.service.d

# Write the override file to set the kubeconfig permissions
cat > /etc/systemd/system/k3s.service << 'EOF'
[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
Wants=network-online.target
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Type=notify
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-/etc/systemd/system/k3s.service.env
KillMode=process
Delegate=yes
User=root
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=/bin/sh -xc '! /usr/bin/systemctl is-enabled --quiet nm-cloud-setup.service 2>/dev/null'
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s server --write-kubeconfig-mode 644
EOF

# Reload systemd manager config to pick up changes
systemctl daemon-reexec
systemctl daemon-reload

# Restart k3s to apply the new ExecStart
systemctl restart k3s

# Optional: Show the status of k3s to confirm it restarted cleanly
systemctl status k3s --no-pager


# CONFIGURE KUSTOMIZATION
# Create a kustomization.yaml file for deploying the AWX Operator
cat << 'EOF' > kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  # Refers to a specific release tag of the AWX Operator's kustomize configs
  - github.com/ansible/awx-operator/config/default?ref=1.1.4

images:
  - name: quay.io/ansible/awx-operator
    newTag: 1.1.4

namespace: awx
EOF

# Create the namespace if it doesn't exist
sudo -u ansible-user /usr/local/bin/kubectl create namespace awx --dry-run=client -o yaml | sudo -u ansible-user /usr/local/bin/kubectl apply -f -

# Build and apply the configuration using kustomize
sudo -u ansible-user /usr/local/bin/kustomize build . | sudo -u ansible-user /usr/local/bin/kubectl apply -f -


# VERIFY AWX POD IS RUNNING BEFORE CONTINUING
ATTEMPTS=0
MAX_ATTEMPTS=30
while ! sudo -u ansible-user /usr/local/bin/kubectl get pods -n awx | grep "awx-operator-controller-manager" | grep -q "Running"; do
    sleep 2
    ((ATTEMPTS++))
    echo "[WAITING]  …retry $ATTEMPTS of $MAX_ATTEMPTS"

    if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
        echo "[ERROR]  AWX operator did not start within expected time."
        exit 1
    fi
done
echo "[INFO]  AWX Operator is running. Proceeding to create awx-demo.yaml."

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

echo "[INFO]  awx-demo.yaml created successfully."


# OVERWRITE kustomization.yaml FILE TO ACCOMDATE ABOVE
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

sudo -u ansible-user /usr/local/bin/kubectl config set-context --current --namespace=awx
sudo -u ansible-user /usr/local/bin/kustomize build . | sudo -u ansible-user /usr/local/bin/kubectl apply -f -
NAMESPACE="awx"
DEPLOYMENT="awx-operator-controller-manager"
CONTAINER="awx-manager"
PATTERN="PLAY RECAP"
POD_NAME=$(sudo -u ansible-user /usr/local/bin/kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=awx-operator-controller-manager -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD_NAME" ]; then
    echo "[ERROR] AWX operator pod not found in namespace $NAMESPACE"
    exit 1
fi

echo "[INFO] Waiting for pod $POD_NAME to be Ready..."
sudo -u ansible-user /usr/local/bin/kubectl wait --namespace="$NAMESPACE" --for=condition=Ready pod/"$POD_NAME" --timeout=120s

echo "[INFO] Monitoring logs for AWX lifecycle trigger ('$PATTERN')..."
sudo -u ansible-user /usr/local/bin/kubectl logs -n "$NAMESPACE" -f "$POD_NAME" -c "$CONTAINER" | while IFS= read -r line; do
    echo "$line"
    if echo "$line" | grep -q "$PATTERN"; then
        echo "Detected '$PATTERN' in logs, continuing..."
        pkill -P $$ /usr/local/bin/kubectl
        break
    fi
done

echo " You should see something like:"
echo "----------------------------------------------------------------------------------------------"
echo "#NAME                                               READY   STATUS    RESTARTS      AGE"
echo "#awx-postgres-13-0                                  1/1     Running   2 (43h ago)   4d4h"
echo "#awx-67d97b57d9-hdtqb                               4/4     Running   8 (43h ago)   4d4h"
echo "#awx-operator-controller-manager-78c7c99946-7dcm9   2/2     Running   8 (43h ago)   4d5h"
echo "----------------------------------------------------------------------------------------------"

echo "Your results are below"
echo "----------------------------------------------------------------------------------------------"
sudo -u ansible-user /usr/local/bin/kubectl get pods -n awx
echo "----------------------------------------------------------------------------------------------"

# GET THE TEMP PASSWORD
echo "[INFO] AWX should now be accessible at https://$(hostname):30080"
sudo -u ansible-user /usr/local/bin/kubectl get secret awx-demo-admin-password -o jsonpath="{.data.password}" | base64 --decode
echo "[INFO] Username is 'admin'"
