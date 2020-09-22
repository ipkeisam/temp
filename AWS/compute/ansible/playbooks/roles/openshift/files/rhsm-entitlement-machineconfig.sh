#!/usr/bin/env bash 

# TODO: if renewal is required, match UUID with UUID from the RHSM payload
uuid=$(oc get clusterversion -o jsonpath='{.items[].spec.clusterID}{"\n"}')

mkdir entitlements
cd entitlements

# Get entitlements, provided the user is already logged into the admin account
curl -O https://access.redhat.com/management/systems/$uuid/certificate/download

# Get MachineConfig template
curl -O https://raw.githubusercontent.com/openshift-psap/blog-artifacts/master/how-to-use-entitled-builds-with-ubi/0003-cluster-wide-machineconfigs.yaml.template

# If only one file replace arr[0] with "$uuid.pem"
# sed 's/BASE64_ENCODED_PEM_FILE/'"$(base64 -w 0 "${arr[0]}")"'/g' 0003-cluster-wide-machineconfigs.yaml.template > 0003-cluster-wide-machineconfigs.yaml
sed 's/BASE64_ENCODED_PEM_FILE/'"$(base64 -w 0 "$uuid.pem")"'/g' 0003-cluster-wide-machineconfigs.yaml.template > 0003-cluster-wide-machineconfigs.yaml

# Applying a MachineConfig will cause all worker nodes to reboot which will restart every application pod at least once. 
# Make sure you've notified DEV teams and have scheduled a CRQ for PRD clusters before proceeding.
# oc create -f 0003-cluster-wide-machineconfigs.yaml

# Test
# curl -O https://raw.githubusercontent.com/openshift-psap/blog-artifacts/master/how-to-use-entitled-builds-with-ubi/0004-cluster-wide-entitled-pod.yaml
# oc create -f 0004-cluster-wide-entitled-pod.yaml
# sleep 20
# oc logs -f cluster-entitled-build-pod