sudo zypper addrepo https://download.opensuse.org/repositories/devel:languages:go/openSUSE_Leap_15.2/devel:languages:go.repo
sudo zypper refresh
sudo zypper install go1.15
echo $(go version)