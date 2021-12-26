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

### Notes
Follow points in https://knowledge.udacity.com/questions/762346 to modify Vagrantfile and cluster.yml
vagrant up at starter/: ...SSH address: 127.0.0.1:2222
    node1: SSH username: vagrant
    node1: SSH auth method: private key
    ...node1: Created symlink /etc/systemd/system/multi-user.target.wants/docker.service → /usr/lib/systemd/system/docker.service.

per https://stackoverflow.com/questions/28471542/cant-ssh-to-vagrant-vms-using-the-insecure-private-key-vagrant-1-7-2: 
ssh -i .vagrant/machines/default/virtualbox/private_key -p 2222 vagrant@localhost //no item in /Users/mommy/codebase/pythonProjects/nd064-c3-microservices-security-project-starter/starter/.vagrant/machines/node1
config.ssh.insert_key = false
set default as vm name; comment out node1 in cluster.yml; on vagrant up: SSH address: 127.0.0.1:2222
    node1: SSH username: vagrant
    node1: SSH auth method: private key

ls .vagrant/machines/node1/virtualbox/ //lot of: screenshot
rke up: 
-rw-r--r--   1 mommy  staff  166 Dec 25 17:32 box_meta
(base) mommy@Mommys-iMac starter % rke up
INFO[0000] Running RKE version: v1.3.3                  
INFO[0000] Initiating Kubernetes cluster                
INFO[0000] [certificates] GenerateServingCertificate is disabled, checking if there are unused kubelet certificates 
INFO[0000] [certificates] Generating Kubernetes API server certificates 
INFO[0000] [certificates] Generating admin certificates and kubeconfig 
INFO[0000] [certificates] Generating kube-etcd-192-168-50-101 certificate and key 
INFO[0000] Successfully Deployed state file at [./cluster.rkestate] 
INFO[0000] Building Kubernetes cluster                  
INFO[0000] [dialer] Setup tunnel for host [192.168.50.101] 
WARN[0000] Failed to set up SSH tunneling for host [192.168.50.101]: Can't retrieve Docker Info: error during connect: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/info": Failed to dial ssh using address [192.168.50.101:22]: Error configuring SSH: ssh: this private key is passphrase protected 
WARN[0000] Removing host [192.168.50.101] from node lists 
FATA[0000] Cluster must have at least one etcd plane host: failed to connect to the following etcd host(s) [192.168.50.101] 

cp -p /vagrant/.vagrant/machines/node1/virtualbox/private_key /home/vagrant/.ssh/id_rsa
cp -p /vagrant/.vagrant.d/insecure_private_key  /home/vagrant/.ssh/id_rsa

% `vagrant ssh-config` //get /Users/mommy/.vagrant.d/insecure_private_key
cp -p /Users/mommy/.vagrant.d/insecure_private_key /home/vagrant/.ssh/id_rsa
cp public and private keys to vm: then it seems to work:
(base) mommy@Mommys-iMac starter % ssh vagrant@192.168.56.4
The authenticity of host '192.168.56.4 (192.168.56.4)' can't be established.
ECDSA key fingerprint is SHA256:M6URlMC/bCRDYaJtQB+RS332g7QkWwkyGhJ7hNTW774.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.4' (ECDSA) to the list of known hosts.
Last login: Sun Dec 26 01:16:16 2021 from 192.168.56.1
Have a lot of fun... 
but is it necessary?

ssh-copy-id -i ~/.vagrant.d/insecure_private_key vagrant@192.168.56.4
`cat ~/.ssh/config` //  IdentityFile ~/.ssh/aws-codecommit_rsa
`vagrant ssh-config >> ~/.ssh/config` then repeat
zsh: command not found: nmap
brew install nmap
nmap 192.168.56.4 per https://knowledge.udacity.com/questions/729899

(base) mommy@Mommys-iMac starter % ssh-copy-id -f -i ~/.ssh/id_rsa vagrant@192.168.56.4
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/Users/mommy/.ssh/id_rsa.pub"

Number of key(s) added:        1

Now try logging into the machine, with:   "ssh 'vagrant@192.168.56.4'"
and check to make sure that only the key(s) you wanted were added.

