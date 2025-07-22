#!/bin/bash
# NOT WORKING YET
# Documentation: https://ansible.readthedocs.io/projects/awx-operator/en/latest/installation/basic-install.html
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

# SET FIREWALL RULE TO ALLOW ACCESS TO AWX 
firewall-cmd --add-port=30080/tcp --permanent &>/dev/null 
firewall-cmd --reload &>/dev/null


# CREATE THE USER ACCOUNT TO USE 
USERNAME="ansible-user"
USER_HOME="/var/lib/ansible"
USER_PASSWORD="123Sup3rStr0ngP455w0rdY0uN33dToCh4ng3321"
NAMESPACE="awx"
DEPLOYMENT="awx-operator-controller-manager"
CONTAINER="awx-manager"
PATTERN="ok =69"
AWX_DIR="/opt/awx-operator"
KUSTOMIZE_INSTALL_DIR="/usr/local/bin"
KUBECONFIG_PATH="$(eval echo ~$USERNAME)/.kube/config"
SUDO_GROUP=$(grep -E '^%[a-zA-Z0-9_-]+\s+ALL=\(ALL(:ALL)?\)\s+ALL' /etc/sudoers | awk '{print $1}' | sed 's/^%//')

# Ensure /opt exists and is writable
echo "[INFO]  Creating the awx-operator directory"
mkdir -p "$AWX_DIR"
chown -R ${USERNAME}:${USERNAME} "$AWX_DIR"
cd $AWX_DIR

# Clone the repo
if [ ! -d "$AWX_DIR/.git" ]; then
    echo "[INFO]  Cloning the awx-operator repo"
    git clone https://github.com/ansible/awx-operator.git "$AWX_DIR" &>/dev/null
fi
git fetch --tags &>/dev/null
LATEST_TAG=$(git tag --sort=-v:refname | grep -E '^([0-9]+\.){2}[0-9]+$' | head -n 1)
if [[ -z "$LATEST_TAG" ]]; then
  echo "[ERROR]  LATEST_TAG is not set." >&2
  exit 1
fi
echo "[INFO]  Setting version tag to ${LATEST_TAG}"
export VERSION="${LATEST_TAG}"
git checkout "tags/${LATEST_TAG}" &>/dev/null
chown -R ${USERNAME}:${USERNAME} "$AWX_DIR"

# Check if the user already exists
if id "$USERNAME" &>/dev/null; then
    echo "[INFO]  User '$USERNAME' already exists. Skipping creation."
else
    echo "[INFO]  Creating user '$USERNAME'"
    # Create the user with specified home directory
    useradd -m -d "$USER_HOME" "$USERNAME"
    # Detect the main sudo group
    SUDO_GROUP=${SUDO_GROUP:-wheel}
    # Add user to sudo group
    usermod -aG "$SUDO_GROUP" "$USERNAME"
    # Set password for the user
    echo "$USER_PASSWORD" | sudo passwd --stdin "$USERNAME"
    # Add useful environment variables to .bashrc
    sudo -u $USERNAME tee "$USER_HOME/.bashrc" > /dev/null <<EOF
export PATH=$PATH:/usr/local/bin
export KUBECONFIG=$HOME/.kube/config
EOF
    chown -R "$USERNAME:$USERNAME" "$USER_HOME"
    echo "[INFO]  User '$USERNAME' created and configured."
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
#echo "[ANSR]  Which container engine do you want to install?"
#printf "\t\t1) Podman\n"
#printf "\t\t2) Docker\n"
#read -rp "Enter 1 or 2: " choice
choice=1
# Install common dependencies
PACKAGES=(tar git python3 python3-pip)
for pkg in "${PACKAGES[@]}"; do
    if ! dnf list installed "$pkg" &>/dev/null; then
        echo "[INFO]  Installing $pkg"
        dnf -y install "$pkg"
    else
        echo "[SKIP]  $pkg already installed."
    fi
done

if [ "$choice" == "1" ]; then
    if ! command -v podman &>/dev/null; then
        echo "[INFO]  Installing podman"
        dnf -y install podman &>/dev/null
        echo "[INFO] Installed podman version $(/bin/podman version)"
    else
        echo "[SKIP]  podman version $(/bin/podman --version) already installed."
    fi
    usermod --add-subuids 100000-165535 --add-subgids 100000-165535 ansible-user
    sudo -u ansible-user mkdir -p "$(eval echo ~$USERNAME)/.config/containers" "$(eval echo ~$USERNAME)/.local/share/containers"

elif [ "$choice" == "2" ]; then
    if ! command -v docker &>/dev/null; then
        echo "[INFO]  Installing Docker dependencies"
        dnf install -y dnf-plugins-core &>/dev/null
        echo "[INFO]  Adding Docker repo"
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo &>/dev/null
        echo "[INFO]  Installing Docker"
        dnf install -y docker-ce docker-ce-cli containerd.io &>/dev/null
        systemctl enable --now docker &>/dev/null
    else
        echo "[SKIP] Docker already installed."
    fi
    echo "[INFO] Docker version: $(/usr/bin/docker --version)"

else
    echo "[ERROR] Invalid choice. Exiting."
    exit 1
fi

# Install K3s if not installed already
if ! command -v /usr/local/bin/k3s &>/dev/null; then
    echo "[INFO]  k3s not found. Installing."
    if ! curl -sfL https://get.k3s.io | sudo sh - >/dev/null; then
        echo "[ERROR]  k3s installation failed." >&2
        exit 1
    fi
else
    echo "[SKIP]  k3s already installed."
fi

# Download and install kustomize
if command -v /usr/local/bin/kustomize >/dev/null 2>&1 && [ "$(dirname "$(command -v /usr/local/bin/kustomize)")" = "$KUSTOMIZE_INSTALL_DIR" ]; then
    echo "[INFO]  Kustomize already installed at $KUSTOMIZE_INSTALL_DIR/kustomize"
else
    echo "[INFO]  Installing kustomize"
    TMP_DIR=$(mktemp -d)
    curl -s https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh | bash -s -- "$TMP_DIR" &>/dev/null
    mv "$TMP_DIR"/kustomize "$KUSTOMIZE_INSTALL_DIR"
    chown root:root "$KUSTOMIZE_INSTALL_DIR/kustomize"
    chmod 755 "$KUSTOMIZE_INSTALL_DIR/kustomize"
    rm -rf -- "$TMP_DIR"
fi

# CREATE KUSTOMIZATION CONFIG LOCATIONS
echo "[INFO]  Setting the expected kube permissions"
sudo -u "$USERNAME" mkdir -p "$(eval echo ~$USERNAME)/.kube"
cp /etc/rancher/k3s/k3s.yaml "$(eval echo ~$USERNAME)/.kube/config"
chmod 600 "$(eval echo ~$USERNAME)/.kube/config"
chown $(id -u "$USERNAME"):$(id -g "$USERNAME") "$(eval echo ~$USERNAME)/.kube/config"


# Write the override file to set the kubeconfig permissions
echo "[INFO]  Creating the k3s.service file with expected values"
cat > /etc/systemd/system/k3s.service <<EOF
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
echo "[INFO]  Reloading systemctl daemon"
systemctl daemon-reexec
systemctl daemon-reload
systemctl restart k3s


# Create a kustomization.yaml file for deploying the AWX Operator
echo "[INFO]  Creating the kustomization.yaml file"
cat <<EOF > ${AWX_DIR}/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  # Find the latest tag here: https://github.com/ansible/awx-operator/releases
  - github.com/ansible/awx-operator/config/default?ref=${LATEST_TAG}

# Set the image tags to match the git version from above
images:
  - name: quay.io/ansible/awx-operator
    newTag: ${LATEST_TAG}

# Specify a custom namespace in which to install AWX
namespace: awx
EOF

echo "[INFO]  Create the awx namespace if it doesn't exist"
NAMESPACE_RESULT=$(sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl create namespace awx --dry-run=client -o yaml | sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl apply -f -)
echo "[INFO]  Namespace result: ${NAMESPACE_RESULT}"
echo "[INFO]  Build and apply the configuration using kustomize"
cd $AWX_DIR
sudo -u ansible-user /usr/local/bin/kustomize build "${AWX_DIR}" | sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl apply -f - &>/dev/null


# VERIFY AWX POD IS RUNNING BEFORE CONTINUING
sleep 5
echo "[INFO]  Check if any awx-operator pod exists before entering loop"
if ! sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl get pods -n awx | grep -q "awx-operator-controller-manager"; then
    echo "[ERROR]  No awx-operator pod found." >&2
    exit 1
fi

# Wait for the AWX Operator pod to exist and reach 'Running' status
echo "[INFO]  Waiting for AWX Operator pod to be Running"
while true; do
    POD_PHASE=$(sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl get pods -n awx -l control-plane=controller-manager -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "NotFound")
    if [[ "$POD_PHASE" == "Running" ]]; then
        echo "[INFO]  AWX Operator pod is Running."
        break
    fi
    ((ATTEMPTS++))
    echo "[WAITING] Attempt $ATTEMPTS/$MAX_ATTEMPTS at $(date +%T) - Current phase: $POD_PHASE"
    if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
        echo "[ERROR]  AWX Operator pod did not reach Running state in time. It is in a $POD_PHASE state." >&2
        exit 1
    fi
    sleep 2
done
echo "[INFO]  AWX Operator is running. Creating file awx-demo.yaml."
sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl create namespace awx 2&>/dev/null || echo "[INFO]  Namespace awx exists"
sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl create secret generic awx-admin-password --namespace awx --from-literal=password='SuperStrongPassword123!' 2&>/dev/null || echo "[INFO]  Secret already created"

cat <<EOF > ${AWX_DIR}/awx-demo.yaml
---
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: awx
  namespace: awx
spec:
  service_type: nodeport
  nodeport_port: 30080
  ingress_type: none
  admin_user: admin
  no_log: false
EOF

echo "[INFO]  awx-demo.yaml created successfully. Applying it to kustomization"
APPLY_YAML_RESULT=$(sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl apply -f ${AWX_DIR}/awx-demo.yaml)
echo "[INFO]  Update kustomization with awx result: ${APPLY_YAML_RESULT}"


echo "[INFO]  Apply the required awx-operator permissions."
cat <<EOF > ${AWX_DIR}/awx-operator-permissions.yaml
---
# awx-operator-permissions.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: awx-operator-permissions
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: awx-operator
subjects:
  - kind: ServiceAccount
    name: awx-operator-controller-manager
    namespace: awx
EOF
chown $(id -u "$USERNAME"):$(id -g "$USERNAME") ${AWX_DIR}/awx-operator-permissions.yaml
sudo -u ansible-user KUBECONFIG="$(eval echo ~$USERNAME)/.kube/config" /usr/local/bin/kubectl apply -f ${AWX_DIR}/awx-operator-permissions.yaml &>/dev/null

echo "[INFO]  Set the default namespace for the current kubernetes context to awx"
chown root:root /etc/rancher/k3s/k3s.yaml
chmod 600 /etc/rancher/k3s/k3s.yaml
CONTEXT_RESULT=$(sudo -u ansible-user KUBECONFIG="$(eval echo ~$USERNAME)/.kube/config" /usr/local/bin/kubectl config set-context --current --namespace=awx || echo "[ERROR]  Failed to set the namespace context")
echo "[INFO]  Set Default Context Result: ${CONTEXT_RESULT}"

echo "[INFO]  Applying updates to the kustomize build"
sudo -u ansible-user /usr/local/bin/kustomize build ${AWX_DIR} | sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl apply -f - &>/dev/null
POD_NAME=""
ATTEMPTS=0
MAX_ATTEMPTS=30
echo "[INFO]  Waiting for AWX operator pod to appear."
while [[ -z "$POD_NAME" && $ATTEMPTS -lt $MAX_ATTEMPTS ]]; do
    POD_NAME=$(sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl get pods -n "$NAMESPACE" -l control-plane=controller-manager -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [[ -z "$POD_NAME" ]]; then
        echo "[WAIT]  Attempt $((ATTEMPTS+1))/$MAX_ATTEMPTS - Pod not ready yet"
        sleep 2
        ((ATTEMPTS++))
    fi
done

if [[ -z "$POD_NAME" ]]; then
    echo "[ERROR]  AWX operator pod not found in namespace $NAMESPACE after waiting."
    exit 1
fi

echo "[INFO]  Waiting for pod $POD_NAME to be Ready"
sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl wait --namespace="$NAMESPACE" --for=condition=Ready pod/"$POD_NAME" --timeout=120s &>/dev/null

echo "[INFO]  Monitoring logs for AWX lifecycle trigger '$PATTERN'"
sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl logs -n "$NAMESPACE" -f "$POD_NAME" -c "$CONTAINER" | while IFS= read -r line; do
    if echo "$line" | grep -q "$PATTERN"; then
        echo "Detected '$PATTERN' in logs, continuing"
        pkill -P $$ /usr/local/bin/kubectl &>/dev/null
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
sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl get pods -n awx
echo "----------------------------------------------------------------------------------------------"

# GET THE TEMP PASSWORD
echo "[INFO] AWX should now be accessible at https://$(hostname):30080"
sudo -u ansible-user env KUBECONFIG="$KUBECONFIG_PATH" /usr/local/bin/kubectl get secret awx-demo-admin-password -o jsonpath="{.data.password}" | base64 --decode
echo "[INFO] Username is 'admin'"
