### How To
- To using this script, first u must config the file /etc/hosts on controlplane node/master node
```
vim /etc/hosts
```
- Setup ssh pubkey to remote all node without password
```
ssh-keygen -t rsa
ssh-copy-id $node
```
- give permission execute to the script
```
chmod +x kubeinstall.sh
```