#!/bin/bash
# This file creates a standard build environment for building Kubernetes
FROM alpine

MAINTAINER Lion lionwei1992@gmail.com

# mkdir
RUN mkdir -p /usr/bin
RUN mkdir -p /opt/cni/bin
RUN mkdir -p /etc/cni/net.d
RUN touch /var/cni.log

# add cniDriver package and cni plugin
ADD kubernetes-cni /usr/bin/
ADD bins.tar.gz /opt/cni/bin/
ADD 10-calico.conf /etc/cni/net.d/

CMD /usr/bin/kubernetes-cni