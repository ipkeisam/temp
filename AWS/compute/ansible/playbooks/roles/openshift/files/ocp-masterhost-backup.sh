#!/bin/bash
set -eo pipefail
ORIGINFILES="origin-master origin-master-api origin-master-controllers origin-node"
OCPFILES="atomic-openshift-master atomic-openshift-master-api atomic-openshift-master-controllers atomic-openshift-node"

die(){
  echo "$1"
  exit $2
}

usage(){
  echo "$0 [path]"
  echo "  path  The directory where the backup will be stored"
  echo "        /tmp/backup/\$(hostname)/\$(date +%Y%m%d) by default"
  echo "Examples:"
  echo "    $0 /my/mountpoint/\$(hostname)"
}

ocpFiles(){
  mkdir -p ${BACKUPLOCATION}/etc/sysconfig
  echo "Exporting OCP related files to ${BACKUPLOCATION}"
  
  if [ -f /etc/origin ]
  then
      cp -aR /etc/origin ${BACKUPLOCATION}/etc
  fi

  for file in ${ORIGINFILES} ${OCPFILES}
  do
    if [ -f /etc/sysconfig/${file} ]
    then
      cp -aR /etc/sysconfig/${file} ${BACKUPLOCATION}/etc/sysconfig/
    fi
  done
}

otherFiles(){
  mkdir -p ${BACKUPLOCATION}/etc/sysconfig
  mkdir -p ${BACKUPLOCATION}/etc/pki/ca-trust/source
  echo "Exporting other important files to ${BACKUPLOCATION}"
  if [ -f /etc/sysconfig/flanneld ]
  then
    cp -a /etc/sysconfig/flanneld ${BACKUPLOCATION}/etc/sysconfig/
  fi
  if [ -f /etc/sysconfig/iptables ]
  then
      cp -aR /etc/sysconfig/iptables ${BACKUPLOCATION}/etc/sysconfig/
  fi

  cp -aR /etc/sysconfig/docker-* ${BACKUPLOCATION}/etc/sysconfig/
  
  if [ -d /etc/cni ]
  then
    cp -aR /etc/cni ${BACKUPLOCATION}/etc/
  fi
  if [ -f /etc/dnsmasq.conf ]
  then
    cp -aR /etc/dnsmasq.conf ${BACKUPLOCATION}/etc/
  fi
  if [ -f /etc/pki/ca-trust/source/anchors ]
  then
    cp -aR /etc/pki/ca-trust/source/anchors ${BACKUPLOCATION}/etc/pki/ca-trust/source/
  fi
}

etcdFiles(){

  mkdir -p ${BACKUPLOCATION}/etcd-config-$(date +%Y%m%d)/
  cp -R /etc/etcd/ ${BACKUPLOCATION}/etcd-config-$(date +%Y%m%d)/

  systemctl show etcd --property=ActiveState,SubState
  mkdir -p /var/lib/etcd/backup/etcd-$(date +%Y%m%d) 
  
  systemctl is-active ectd && etcdctl3 snapshot save /var/lib/etcd/backup/etcd-$(date +%Y%m%d)/db

  if [ -f /etc/origin/node/pods ]
  then
    mkdir -p /etc/origin/node/pods-stopped
    mv /etc/origin/node/pods/* /etc/origin/node/pods-stopped/
  fi

  systemctl is-active ectd && etcdctl2 backup --data-dir /var/lib/etcd --backup-dir ${BACKUPLOCATION}/etcd-$(date +%Y%m%d)

  # Check if executed as OSE system:admin
  if [[ "$(oc whoami)" != "system:admin" ]]; then
    echo -n "Trying to log in as system:admin... "
    oc login -u system:admin > /dev/null && echo "done."
  fi

  if [ -f /etc/origin/node/pods/etcd.yaml ]
  then
    export ETCD_POD_MANIFEST="/etc/origin/node/pods/etcd.yaml"
    export ETCD_EP=$(grep https ${ETCD_POD_MANIFEST} | cut -d '/' -f3)
    export ETCD_POD=$(oc get pods -n kube-system | grep -o -m 1 '\S*etcd\S*')

    oc project kube-system
    oc exec ${ETCD_POD} -c etcd -- /bin/bash -c "ETCDCTL_API=3 etcdctl --cert /etc/etcd/peer.crt --key /etc/etcd/peer.key --cacert /etc/etcd/ca.crt --endpoints $ETCD_EP snapshot save /var/lib/etcd/snapshot.db"
  fi
}

packageList(){
  echo "Creating a list of rpms installed in ${BACKUPLOCATION}"
  rpm -qa | sort > ${BACKUPLOCATION}/packages.txt
}

if [[ ( $@ == "--help") ||  $@ == "-h" ]]
then
  usage
  exit 0
fi

BACKUPLOCATION=${1:-"/tmp/backup/$(hostname)/$(date +%Y%m%d)"}

mkdir -p ${BACKUPLOCATION}

ocpFiles
otherFiles
etcdFiles
packageList

exit 0