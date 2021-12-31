sudo zypper install git 
echo $(git version)

git clone https://github.com/aquasecurity/docker-bench.git
cd docker-bench
go build -o docker-bench 
./docker-bench --help 