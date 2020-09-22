#!/bin/bash
#!/usr/bin/env bash

DATE=`date +%Y%m%d.%H`
DIR=/tmp/backup

#DIR=$DIR/$DATE

# Backup object per project for easy restore
echo -n "Backup object per project for easy restore"
mkdir -p $DIR/projects
cd $DIR/projects

# Check if executed as OSE system:admin
if [[ "$(oc whoami)" != "system:admin" ]]; then
  echo -n "Trying to log in as system:admin... "
  oc login -u system:admin > /dev/null && echo "done."
fi

for i in `oc get projects --no-headers |grep Active |awk '{print $1}'`
do
  echo -e "\nExporting OCP Project for $i\n"
  mkdir $i
  cd $i
  oc export namespace $i --as-template="$i" >ns.yml
  oc export secrets -n $i --as-template="$i" >secrets.yml
  oc export rolebindings -n $i --as-template="$i" >rolebindings.yml
  oc export serviceaccounts -n $i --as-template="$i" >serviceaccounts.yml
  # loop through all configs to be backup
  for j in deploymentconfigs buildconfigs services routes pvc secrets imagestreams networkpolicy policies policybindings roles rolebindings serviceaccounts secrets imagestreamtags podpreset configmap egressnetworkpolicies rolebindingrestrictions limitranges resourcequotas pvcs templates cronjobs statefulsets hpas deployments replicasets poddisruptionbudget endpoints
  do
    mkdir $j
    cd $j
    for k in `oc get $j -n $i --no-headers |awk '{print $1}'`
    do
      echo export $j $k '-n' $i --as-template="$i"
      oc export $j $k -n $i --as-template="$i" >$k.yml
    done
    cd ..
  done
  cd ..
done