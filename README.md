
# Ncsist Project -  Docker II - Ncsis_Oscap_Docker_GUI

## openscap - docker scan 安裝文件
### 在CentOS上安裝Docker
+ Start by updating your system packages and install the required dependencies
```  bash
sudo yum update
sudo yum install yum-utils device-mapper-persistent-data lvm2
```
+ Run the following command which will add the Docker stable repository to your system
``` bash
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
```
+ Install the latest version of Docker CE (Community Edition) using yum by typing
``` bash
sudo yum -y install docker-ce
```
+ Once the Docker package is installed, start the Docker daemon and enable it to automatically start at boot time
``` bash
sudo systemctl start docker
sudo systemctl enable docker
```
+ To verify that the Docker service is running type
``` bash
sudo systemctl status docker
```
### 使用python2並安裝atomic
+ 安裝pip
``` bash
sudo yum -y install python-pip
```
+ Pip docker package
``` bash
sudo pip install docker
```
+ 安裝atomic
``` bash
sudo yum -y install atomic
```
### 安裝oscap-docekr
+ 安裝oscap-docekr
``` bash
sudo yum install openscap-utils
```
+ 安裝 scap security guide
``` bash
sudo yum install scap-security-guide
```

## openscap - docker scan 使用文件
+ 使用CVE掃描Docker
``` bash
oscap-docker <image/container>[-cve] <image/container identifier> <oscap parameters>
```
+ 使用自定義安全策略掃描Docker
    + SSG SCAP security 安裝在 /usr/share/xml/scap/ssg/content/
    + 使用範例
``` bash
sudo oscap-docker image registry.access.redhat.com/rhel7 oval eval --results oval-results.xml --report report.html /usr/share/xml/scap/ssg/content/ssg-rhel7-oval.xml 

sudo oscap-docker image registry.access.redhat.com/rhel7 xccdf eval --profile C2S --results oval-results-rhel7-bbb.xml --report report-rhel7-bbb.html /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
```

## 參考資料
+ [How To Install and Use Docker on CentOS 7](https://linuxize.com/post/how-to-install-and-use-docker-on-centos-7/)
+ [Security compliance of RHEL7 Docker containers](https://www.open-scap.org/resources/documentation/security-compliance-of-rhel7-docker-containers/)
