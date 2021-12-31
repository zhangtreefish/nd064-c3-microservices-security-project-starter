# syntax=docker/dockerfile:1.0-experimental

#FROM treefishdocker/udacity-microservices-security:hardened-v2.0
FROM opensuse/leap:latest

#define maintainer 
LABEL maintainer="nick.reva@snap.com"

#define version
LABEL version="V1"

# create a directory to work in
RUN mkdir udacity \
    && cd udacity

#install zypper 
RUN zypper refs && zypper refresh

#add local user
USER $SEC_USER
