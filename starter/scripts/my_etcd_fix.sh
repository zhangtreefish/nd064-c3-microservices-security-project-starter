cd /var/lib/etcd
groupadd --gid 52034 etcd
useradd --comment "etcd service account" --uid 52034 --gid 52034 etcd
chown etcd:etcd /var/lib/etcd
docker run --pid=host -v /etc/passwd:/etc/passwd -v /etc/group:/etc/group -v /etc:/node/etc:ro -v /var:/node/var:ro -ti rancher/security-scan:v0.2.2 bash
