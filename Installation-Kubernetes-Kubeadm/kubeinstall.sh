servers=("master" "worker1" "worker2")
for server in "${servers[@]}"; do
    echo "Setting hostname for $server"
    ssh $server "sudo hostnamectl set-hostname $server"
    echo "Setting swapp for $server"
    ssh $server "swapoff -a; sed -i '/swap/d' /etc/fstab; mount -a"
    echo "Setting modules for $server"
	  ssh $server "cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF"
    echo "Check modules for $server"
    ssh $server "sudo modprobe overlay; sudo modprobe br_netfilter"
    echo "Setting sysctl for $server"
    ssh $server "cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF"
    echo "Check sysctl for $server"
    ssh $server "sysctl --system" 
    echo "Install containerd on $node"
    ssh $node "apt update -y; apt install containerd -y; mkdir -p /etc/containerd/; systemctl enable --now containerd; systemctl start containerd; containerd config default | sudo tee /etc/containerd/config.toml"
    echo "Set SystemdCGroup on $node"
    ssh $node "sed -e 's/SystemdCgroup = false/SystemdCgroup = true/g' -i /etc/containerd/config.toml && systemctl restart containerd"
    echo "Install dependencies on $node"
    ssh $node "apt update -y; apt install apt-transport-https ca-certificates curl -y"
    echo "Download pubkey on $node"
    ssh $node "curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg"
    echo "add repo kube on $node"
    ssh $node "echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list;"
    echo "install kube $node"
    ssh $node "apt-get update -y; apt-get install -y kubelet kubeadm kubectl; apt-mark hold kubelet kubeadm kubectl"
    echo "Starting kubelet"
    ssh $node "systemctl enable --now kubelet; systemctl start kubelet"
done
