FROM centos:7

RUN yum -y update
RUN yum -y install initscripts

RUN yum -y install centos-release-scl \
&& yum -y install devtoolset-10-gcc devtoolset-10-gcc-c++ devtoolset-10-gcc-plugin-devel \
&& yum -y install devtoolset-10-gcc-gdb-plugin make \
&& yum -y install libatomic \
&& yum install libpcap-devel
RUN echo "source /opt/rh/devtoolset-7/enable" >> ~/.bashrc

RUN yum -y install wget \
&& yum -y install net-tools nc telnet \
&& yum -y install tmux \
&& yum -y install vim \
&& yum install iproute iproute-doc \
&& yum install -y tcpdump

RUN yum -y install gcc automake autoconf libtool make

WORKDIR /home/Lab2
ENTRYPOINT ["/bin/bash"]