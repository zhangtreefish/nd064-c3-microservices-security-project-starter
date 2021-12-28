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
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9UOszqhL05yZcDG8qMxMVCw1ETjo1p3pzbxDbJsifJjU1RHFmR37Hq0MrYm8ioCjwddPuA4s4M0G/uOP/iaWmqzOHgsS3YNIbf1+6Ie+rgU0FFuBJdKvk/jxNAhk0pWRWvEHQpvdC7e6lrB4Z4GHUWz+EO5yyPO5axhQCerYuJyZjJAEvl0flQhwfClAcqnFs6AOVThPa014T+pSakYs56/dOx5W6rbN/qZTWKZ6HjQ3xqzRP53hTFySqyLsYrqFtgQvDinShqi7D3s99A7fuHWg0uKDHjYvAvDUUeU7HI5eVlE7cH6b27fIBe1l0MCdhK8DVATzIleJs5/Ce/5GR vagrant 
//the above output is the same as `cat /root/.ssh/authorized_keys` and `cat /home/rke/.ssh/authorized_keys `, 
different from `localhost:~ # cat /home/vagrant/.ssh/authorized_keys`:
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key`
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
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFgA8ieKpxlw5rVqInxdIAdoAuXnimtSCmihKkYfxSqT0ymHgkM4vtxNqmuw8/BEyMU4+iHQZt1U5t9kNWmNXh1nPmvWZvZKPpqogTAKcf4dY6CWLpRLlwQyHXzIVIORubG6pCrdCWze+1yFDz9lIAWP6mbXMlTeHwv+4Pl5huVbedjtLQCKJsvgkpOO0ObSbN5YzUFueddIayX4mu5bNOaIKE1HYaZ3uhNdmAN1MRA/i/w3b7hwgPZOjs4muWgrhVKy8m8IKxfxlYdeomlXPiB2aovdZnqfN23L7+k+t4/ms+l6w5MkFi1Fg5wXL+QaHnKDx76lsZcjLxUan0+ZmJ mommy@Mommys-iMac.local

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
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQ3Z945k4R3FDdydUmUhGFkKNCwiwBxXMFAbWRWPAdsisz6c+dt9yZxL0A5zBFpaHuIjSfrq8ylnN8yJmsenxPY7Tm9RszqeAKM/91Teu8MXbCROsN9VUmFp4jFREd9ktKtFzzrl0gjKDU8WEyRpFUEIYJmZSKdZdAMBh47lTH9BG78v5x/xytHjN4HWolgagRqALBGqqFiWY6OBKi5YXzLtaSb443RGVL24+jLppsxI0GJ700l4f+kqp8AIOPR7mqC21keawG60sYT+sbhS/eM8wOitto9YuzpJh5GxVmLhVaLdnqgBywGbr/u4qPvc9HrfBwwID32T6UVLq7ms4t vagrant
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFgA8ieKpxlw5rVqInxdIAdoAuXnimtSCmihKkYfxSqT0ymHgkM4vtxNqmuw8/BEyMU4+iHQZt1U5t9kNWmNXh1nPmvWZvZKPpqogTAKcf4dY6CWLpRLlwQyHXzIVIORubG6pCrdCWze+1yFDz9lIAWP6mbXMlTeHwv+4Pl5huVbedjtLQCKJsvgkpOO0ObSbN5YzUFueddIayX4mu5bNOaIKE1HYaZ3uhNdmAN1MRA/i/w3b7hwgPZOjs4muWgrhVKy8m8IKxfxlYdeomlXPiB2aovdZnqfN23L7+k+t4/ms+l6w5MkFi1Fg5wXL+QaHnKDx76lsZcjLxUan0+ZmJ mommy@Mommys-iMac.local
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