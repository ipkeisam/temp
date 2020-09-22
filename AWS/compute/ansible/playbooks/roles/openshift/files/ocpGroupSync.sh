#!/bin/sh

oc login -u system:admin
oc adm groups sync --sync-config=/root/ad-sync/sync_config.txt --whitelist=/root/ad-sync/sync_whitelist.txt --confirm
oc adm groups prune --sync-config=/root/ad-sync/sync_config.txt --confirm

