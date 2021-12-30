### Background
Security is a highly dynamic topic with ever changing threats and priorities. Newsworthy topics ranging from fortune 500 companies like [Garmin](https://www.wired.com/story/garmin-ransomware-hack-warning) paying $10 million in ransom for ransomware attacks to supply chain attacks such as [Solarwinds](https://www.cnet.com/news/solarwinds-hack-officially-blamed-on-russia-what-you-need-to-know) are ever-present. 

Security is becoming harder as the velocity of deployments is accelerating. The [Synopsis 2020 Open Source Security Risk Analysis Report](https://webcache.googleusercontent.com/search?q=cache:yUCraGVAdw8J:https://www.synopsys.com/content/dam/synopsys/sig-assets/reports/2020-ossra-report.pdf+&cd=1&hl=en&ct=clnk&gl=us) revealed that 99% of audited code bases contained open source, and within those codebases 75% of vulnerabilities were left unpatched, creating risk. Incorporating security checks into each step of the build and deployment process is vital to identify security defects before they hit production.

Your company CTO is worried about what your engineering team is doing to harden and monitor the company's new microservice application against malicious threat actors and payloads. You’ve completed the exercies in the course and have a baseline understanding of how to approach this. In response to the CTOs concerns students will threat model, build and harden a microservices environment based on what they learned from the exercises.

### Goal 
You will be presented with the challenge to build a secure Microservice environment, threat modeling and hardening the container image, run-time environment and application itself. For purposes of the project, you will be instructed to use a secure base opensuse image, covering considerations for the importance of using trustworthy base images and verifing the baselein. You will be provided with instructions to build, harden, ship and run an environment analogous to the company's new microservice application, simplified for project purposes. In the project you will define and build a new environment from the ground-up. 

In a real-world scenario, you may have an existing envrionment that needs to be hardened or may decided to re-build parts or all net-new, regardless, the tools and techniques in the project are directly applicable. The beauty of microservices vs a monolith architecture is that all core components (image, container, run-time, application) are abstracted allowed for isolation boundaries and iterative development. In the real-world, you could chose to harden and redeploy all base-images as one project phase and tackle docker container security, kubernetes hardening and the software composition anaylsis, as individual project phases. The best approach is to bake these requirements and security hardening into the build and deploy process. In an enterprise setting, much of this can be enforced with security units test via CI/CD prior to deployment. Hardening the base-image and baking security into the CI/CD is beyond the scope of this project and course, however please reference the [additional considerations](https://github.com/udacity/nd064-c3-Microservices-Security-project-starter/tree/master/starter#additional-considerations) section for more on this. 

For the project, once the Microservice environment is hardened and provisioned, we will configure [sysdig Falco](https://github.com/falcosecurity/falco) to perform run-time monitoring on the node, sending logs to a Grafana node for visualization. To demonstrate to the CTO that the company can respond to a real security event, you will then simulate a [tabletop cyber exercise](https://www.fireeye.com/mandiant/tabletop-exercise.html) by running a script to introduce an unknown binary from the starter code that will disrupt the environment! 

No stress, you have tools and security incident response knowledge to respond ;) Your goal will be to evaluate Grafana to determine what the unknown binary is, contain and remediate the environment, write an incident response report and present it to the CTO. There will be a few hidden easter eggs, see if you can find them for extra credit. 

### Project Instructions

Follow the steps/instructions in the Udacity classroom to complete and submit the project.
SSH for RKE:
https://rancher.com/docs/rke/latest/en/config-options/
`ssh_agent_auth: true`
```
$ eval "$(ssh-agent -s)"
Agent pid 3975
$ ssh-add /home/user/.ssh/id_rsa
Enter passphrase for /home/user/.ssh/id_rsa:
Identity added: /home/user/.ssh/id_rsa (/home/user/.ssh/id_rsa)
$ echo $SSH_AUTH_SOCK
/tmp/ssh-118TMqxrXsEx/agent.3974
```
https://www.vagrantup.com/docs/provisioning/file
https://www.cyberciti.biz/faq/how-to-use-ssh-agent-for-authentication-on-linux-unix/
ssh-add -l
ssh-add -L
man ssh-add

https://stackoverflow.com/questions/32314257/vagrant-up-failing-because-the-name-already-exists
 find **/node1
cd "/Users/mommy/VirtualBox VMs"
find . -type f -name "Leap*" -print
find . -type f -name "Leap*" -delete
rm -r -f Leap-15.2_16*
rm -r -f "/Users/mommy/VirtualBox VMs/node1"
/Users/mommy/codebase/pythonProjects/nd064-c3-microservices-security-project-starter/starter

(base) mommy@Mommys-iMac starter % vsc  
Host node1
  HostName 127.0.0.1
  User root
  Port 2222
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  PasswordAuthentication no
  IdentityFile /Users/mommy/codebase/pythonProjects/nd064-c3-microservices-security-project-starter/starter/.vagrant/machines/node1/virtualbox/private_key
  IdentitiesOnly yes
  LogLevel FATAL

eval "$(ssh-agent -s)" //Agent pid 1616
(base) mommy@Mommys-iMac starter % rke --version
rke version v1.3.3
`ssh-copy-id -i ~/.ssh/id_rsa root@192.168.50.101` did not work
rerun eval ... //pid 1796
ssh-add /root/.ssh/id_rsa
ssh-add -l
ssh-add
(base) mommy@Mommys-iMac starter % ssh-add /home/mommy/.ssh/id_rsa
/home/mommy/.ssh/id_rsa: No such file or directory
(base) mommy@Mommys-iMac starter % `ssh-add`   
Enter passphrase for /Users/mommy/.ssh/id_rsa: 
Identity added: /Users/mommy/.ssh/id_rsa (/Users/mommy/.ssh/id_rsa)
validated with fingerprints `ssh-add -l` and public key `ssh-add -L`
(base) mommy@Mommys-iMac starter % ssh-add -L
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFgA8ieKpxlw5rVqInxdIAdoAuXnimtSCmihKkYfxSqT0ymHgkM4vtxNqmuw8/BEyMU4+iHQZt1U5t9kNWmNXh1nPmvWZvZKPpqogTAKcf4dY6CWLpRLlwQyHXzIVIORubG6pCrdCWze+1yFDz9lIAWP6mbXMlTeHwv+4Pl5huVbedjtLQCKJsvgkpOO0ObSbN5YzUFueddIayX4mu5bNOaIKE1HYaZ3uhNdmAN1MRA/i/w3b7hwgPZOjs4muWgrhVKy8m8IKxfxlYdeomlXPiB2aovdZnqfN23L7+k+t4/ms+l6w5MkFi1Fg5wXL+QaHnKDx76lsZcjLxUan0+ZmJ /Users/mommy/.ssh/id_rsa

(base) mommy@Mommys-iMac starter % echo $SSH_AUTH_SOCK
/var/folders/19/40gs9bcd5kjd61yfdy6f875w0000gn/T//ssh-B1kuat3AaAax/agent.1795

ssh-copy-id -i ~/.ssh/id_rsa root@192.168.50.101 //timedout

(base) mommy@Mommys-iMac starter % vagrant ssh
Have a lot of fun...
localhost:~ # ls ~/.ssh
authorized_keys
localhost:~ # cat ~/.ssh/authorized_keys 
//the above output is the same as `cat /root/.ssh/authorized_keys` and `cat /home/rke/.ssh/authorized_keys `, 
different from `localhost:~ # cat /home/vagrant/.ssh/authorized_keys`:
//this time vagrant ssh automatically get root access ?
https://jhooq.com/vagrant-copy-public-key/
ssh -i /Users/mommy/codebase/pythonProjects/nd064-c3-microservices-security-project-starter/starter/.vagrant/machines/node1/virtualbox/private_key -o PasswordAuthentication=no vagrant@127.0.0.1 -p 3150

adding .pub worked:
localhost:~ # ls -lart ~/.ssh/
total 16
drwx------ 5 root root 4096 Dec 27 19:36 ..
-rw------- 1 root root  389 Dec 27 19:36 authorized_keys
-rw-r--r-- 1 root root  405 Dec 27 19:37 id_rsa.pub
drwx------ 2 root root 4096 Dec 27 19:37 .
localhost:~ # cat ~/.ssh/id_rsa.pub

localhost:~ # cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,62F1C4C183AF0E29CD5F574CBD2BBF57
localhost:~ # cat /home/rke/.ssh/id_rsa
cat: /home/rke/.ssh/id_rsa: No such file or directory
localhost:~ # exit
cat ~/.ssh/id_rsa //matches host private key


(base) mommy@Mommys-iMac starter % rke up
INFO[0000] Running RKE version: v1.3.3                  
INFO[0000] Initiating Kubernetes cluster                
INFO[0000] [certificates] GenerateServingCertificate is disabled, checking if there are unused kubelet certificates 
INFO[0000] [certificates] Generating admin certificates and kubeconfig 
INFO[0000] Successfully Deployed state file at [./cluster.rkestate] 
INFO[0000] Building Kubernetes cluster                  
INFO[0000] [dialer] Setup tunnel for host [192.168.50.101] 
WARN[0225] Failed to set up SSH tunneling for host [192.168.50.101]: Can't retrieve Docker Info: error during connect: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/info": Unable to access node with address [192.168.50.101:22] using SSH. Please check if the node is up and is accepting SSH connections or check network policies and firewall rules. Error: dial tcp 192.168.50.101:22: connect: operation timed out 
WARN[0225] Removing host [192.168.50.101] from node lists 
FATA[0225] Cluster must have at least one etcd plane host: failed to connect to the following etcd host(s) [192.168.50.101]

initially: only vagrant; did `cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys`:
localhost:~ # cat /root/.ssh/authorized_keys 
root has host private ssh key; rke and vagrant does not have private key id_rsa.

https://stackoverflow.com/questions/112396/how-do-i-remove-the-passphrase-for-the-ssh-key-without-having-to-create-a-new-ke
$ ssh-keygen -p

restart; at commit dccfddcf8b1ce44cca117e15576cfdded42e1de0 ; authorized key not the public key; 

ssh -i /Users/mommy/codebase/pythonProjects/nd064-c3-microservices-security-project-starter/starter/.vagrant/machines/node1/virtualbox/private_key -o PasswordAuthentication=no vagrant@192.168.50.101 //timedout

ssh-copy-id -i ~/.ssh/id_rsa vagrant@192.168.50.101

https://github.com/SUSE-Rancher-Community/local-setup-of-rancher-with-rke

ssh-keygen -t rsa -b 2048 //en saved in /Users/mommy/.ssh/nd064_rsa.
Your public key has been saved in /Users/mommy/.ssh/nd064_rsa.pub.
sudo ssh-copy-id -i ~/.ssh/nd064_rsa vagrant@192.168.50.101
config.ssh.private_key_path 
https://stackoverflow.com/questions/61837844/vagrant-custom-ssh-key-authentication-failure
https://devops.stackexchange.com/questions/1237/how-do-i-configure-ssh-keys-in-a-vagrant-multi-machine-setup

1. 
vagrant up
2. 
ssh-copy-id -i ~/.ssh/id_rsa root@192.168.56.4
3. 
rke remove //since/if using the same host to spin up rke again; otherwise: FATA[0228] [controlPlane] Failed to upgrade Control Plane: [[[controlplane] Error getting node node1:  "node1" not found]] 
rke up
export KUBECONFIG=kube_config_cluster.yml
kubectl --kubeconfig kube_config_cluster.yml get nodes
kubectl get nodes -o wide  
//
NAME    STATUS   ROLES                      AGE     VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION             CONTAINER-RUNTIME
node1   Ready    controlplane,etcd,worker   4h27m   v1.20.4   10.0.2.15     <none>        openSUSE Leap 15.2   5.3.18-lp152.106-default   docker://20.10.9-ce

kubectl get all --all-namespaces -o wide

kubectl --kubeconfig kube_config_cluster.yml get po -A
kubectl get po -A
 
kubectl describe po calico-node-sqwtz -n kube-system 
kubectl describe  po calico-kube-contrlolres-84cdfc98bd-p7lgz -n kube-system 
//  `  Normal   Scheduled               24m                   default-scheduler  Successfully assigned kube-system/calico-kube-controllers-84cdfc98bd-p7lgz to node1`
`Warning  NetworkNotReady         11m (x7 over 12m)    kubelet            network is not ready: runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady message:docker: network plugin is not ready: cni config uninitialized`
//CrashLoopBackOff
kubectl edit -n kube-system daemonset.apps/calico-node 
//1 to 60 ; on kubectl get po -A: Unable to connect to the server: net/http: request canceled (Client.Timeout exceeded while awaiting headers); back to 2
kubectl edit -n kube-system deployment.apps/calico-kube-controllers
per https://stackoverflow.com/questions/69190171/calico-kube-controllers-and-calico-node-are-not-ready-crashloopbackoff
kubectl describe po calico-kube-controllers-84cdfc98bd-p7lgz -n kube-system //`  Warning  Unhealthy       3h38m (x13 over 3h40m)  kubelet  Liveness probe failed: unknown shorthand flag: 'l' in -l`
kubectl replace -f /var/folders/19/40gs9bcd5kjd61yfdy6f875w0000gn/T/kubectl-edit-wid9m.yaml
reboot by `vagrant reload` per https://stackoverflow.com/questions/48190928/kubernetes-pod-remains-in-containercreating-status
fix calico-kube-controller restarting and not ready issue by setting livenss and readiness timeout to 60s AND changing -l to -r per error: https://issueexplorer.com/issue/projectcalico/calico/4935
followed by `vagrant reload`: after that: get po shows 6 prometheus pods in default, instead of 1 earllier when nginx-ingress-controller was not ready; nginx-ingress-controller-tr6zl
4. 
helm version //3.7.1
5.  flaco driver
ssh root@192.168.56.4
inside vm:
per official Falco guide : https://falco.org/docs/getting-started/installation/#suse
rpm --import https://falco.org/repo/falcosecurity-3672BA8F.asc
curl -s -o /etc/zypp/repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
6.  falco header
zypper -n dist-upgrade
zypper -n install kernel-default-devel-$(uname -r | sed s/\-default//g)
exit

//still "kernel-default-devel-5.3.18-lp152.106"
zypper -n install kernel-default-devel 
$(uname -r | sed s/\-default//g) //5.3.18-lp152.106
//compare: localhost:~ # uname -a
Linux localhost 5.3.18-lp152.106-default #1 SMP Mon Nov 22 08:38:17 UTC 2021 (52078fe) x86_64 x86_64 x86_64 GNU/Linux

vagrant halt node1 //doing "reboot" inside vm damaged node1
zypper -n install kernel-default-devel //(7/7) Installing: kernel-default-devel-5.3.18-lp152.106.1.x86_64 
//NOT DO: zypper -n install falco //driver installed on vm directly
exit
7. 
//vagrant halt node1 //doing "reboot" inside vm damaged node1
vagrant reload
8. out on host, per https://knowledge.udacity.com/questions/758648 and https://github.com/prometheus-community/helm-charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 
//already exists on host
helm repo update
helm install prometheus prometheus-community/kube-prometheus-stack --kubeconfig kube_config_cluster.yml 
//kube-prometheus-stack has been installed. Check its status by running:
  kubectl --namespace default get pods -l "release=prometheus"
//not `kubectl --kubeconfig kube_config_cluster.yml --namespace default get pods -l "release=prometheus-operator-1619828194"` ?
kubectl --kubeconfig kube_config_cluster.yml --namespace default port-forward prometheus-kube-prometheus-operator-7c64864bb7-qfcjx 9090
//E1230 09:55:14.208365    7307 portforward.go:400] an error occurred forwarding 9090 -> 9090: error forwarding port 9090 to pod 79044df970ddaeb143e03939114a2a90b49fdb535bd506cb3d29b2f573d8267f, uid : exit status 1: 2021/12/30 15:55:11 socat[8457] E connect(5, AF=2 127.0.0.1:9090, 16): Connection refused
9. falco ds
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install --kubeconfig kube_config_cluster.yml falco falcosecurity/falco --set falco.grpc.enabled=true --set falco.grpcOutput.enabled=true
per https://github.com/falcosecurity/charts/tree/master/falco#grpc-over-unix-socket-default
//falco not ready ??
try `vagrant halt`, `vagrant up` again: falco ready
kubectl --kubeconfig kube_config_cluster.yml get ds falco -o yaml | grep serviceAcc
falco-5d2ct //falco-29ddb
kubectl --kubeconfig kube_config_cluster.yml exec -it falco-5d2ct -- /bin/bash //
echo $KUBECONFIG //kube_config_cluster.yml
kubectl exec -it falco-29ddb -- /bin/bash //auth error
falco --help
cat /etc/falco/falco.yaml
10.  falco exporter per https://github.com/falcosecurity/charts/tree/master/falco-exporter
helm install --kubeconfig kube_config_cluster.yml falco-exporter --set serviceMonitor.enabled=true falcosecurity/falco-exporter

 try deleting pod to get it ready:
 (base) mommy@Mommys-iMac starter % kubectl delete po --grace-period=0 --force   -n kube-system calico-kube-controllers-84cdfc98bd-j8w7v

 deleting the pod does no automatically regenerate the pod. ??
 try rerun falco: helm install --kubeconfig kube_config_cluster.yml falco falcosecurity/falco --set falco.grpc.enabled=true --set falco.grpcOutput.enabled=true

had to remove first:
zypper rm falco

localhost:~ # uname -a
Linux localhost 5.3.18-lp152.106-default #1 SMP Mon Nov 22 08:38:17 UTC 2021 (52078fe) x86_64 x86_64 x86_64 GNU/Linux

then reinstall: zypper -n install //TODO: install from host

set memory to 4096 and repeat

11. hack
kubectl --kubeconfig kube_config_cluster.yml exec -it falco-29ddb -- /bin/bash
adduser evil_hacker
cat /etc/shadow > /dev/null
nc -l 8080
./falco_metrics.sh

kubectl --kubeconfig kube_config_cluster.yml logs -f falco-29ddb | grep -A 2 adduser 
kubectl --kubeconfig kube_config_cluster.yml logs -f falco-29ddb | grep 'nc\|\/etc\/shadow\|adduser' 
https://falco.org/docs/rules/
container.id != host and proc.name = bash

12. Grafana
kubectl --kubeconfig kube_config_cluster.yml --namespace default port-forward prometheus-grafana-f87bfb777-c998s 3000
kubectl --kubeconfig kube_config_cluster.yml port-forward --namespace default falco-exporter-j2m2x 9376

kubectl --kubeconfig kube_config_cluster.yml --namespace default port-forward prometheus-prometheus-kube-prometheus-prometheus-0 9090
//`E1230 18:38:38.363046   12299 portforward.go:400]`

`The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?` 
redo: `export KUBECONFIG=kube_config_cluster.yml`

(base) mommy@Mommys-iMac starter % kubectl describe servicemonitor falco-exporter
Name:         falco-exporter
Namespace:    default
Labels:       app.kubernetes.io/instance=falco-exporter
              app.kubernetes.io/managed-by=Helm
              app.kubernetes.io/name=falco-exporter
              app.kubernetes.io/version=0.6.0
              helm.sh/chart=falco-exporter-0.6.3
Annotations:  meta.helm.sh/release-name: falco-exporter
              meta.helm.sh/release-namespace: default
API Version:  monitoring.coreos.com/v1
Kind:         ServiceMonitor
Metadata:
  Creation Timestamp:  2021-12-30T21:35:40Z
  Generation:          1
  Managed Fields:
    API Version:  monitoring.coreos.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:metadata:
        f:annotations:
          .:
          f:meta.helm.sh/release-name:
          f:meta.helm.sh/release-namespace:
        f:labels:
          .:
          f:app.kubernetes.io/instance:
          f:app.kubernetes.io/managed-by:
          f:app.kubernetes.io/name:
          f:app.kubernetes.io/version:
          f:helm.sh/chart:
      f:spec:
        .:
        f:endpoints:
        f:selector:
          .:
          f:matchLabels:
            .:
            f:app.kubernetes.io/instance:
            f:app.kubernetes.io/name:
    Manager:         helm
    Operation:       Update
    Time:            2021-12-30T21:35:40Z
  Resource Version:  13906
  UID:               693a025e-51c9-4eb1-abf7-0335b07ff0bc
Spec:
  Endpoints:
    Port:  metrics
  Selector:
    Match Labels:
      app.kubernetes.io/instance:  falco-exporter
      app.kubernetes.io/name:      falco-exporter
Events:                            <none>

kubectl --kubeconfig kube_config_cluster.yml edit prometheus prometheus-kube-prometheus-prometheus
kubectl --kubeconfig kube_config_cluster.yml apply -f manual_service_monitor_falco_exporter.yml