#!/bin/bash
# prune-artifacts
# https://docs.openshift.org/latest/admin_guide/pruning_resources.html
# https://docs.openshift.com/container-platform/3.7/admin_guide/pruning_resources.html

KEEP_COMPLETE=5
KEEP_FAILED=5
KEEP_YOUNGER="60m"
KEEP_TAG_REVISIONS=3
PRUNE_SERVICEACCOUNT="pruneacct"

USAGE="$0 --artifact <builds,deployments,images> --keep_complete <num> --keep_failed <num> --keep_younger <time> --keep-tag-revisions <num>"

while [[ $# -gt 1 ]]; do
  key="$1"

  case $key in
      --artifact)
        ARTIFACT="$2"
        shift
      ;;
      --keep-complete)
        KEEP_COMPLETE="$2"
        shift
      ;;
      --keep-failed)
        KEEP_FAILED="$2"
        shift
      ;;
      --keep-younger)
        KEEP_YOUNGER="$2"
        shift
      ;;
      --keep-tag-revisions)
        KEEP_TAG_REVISIONS="$2"
        shift
      ;;
  esac
  shift
done

LOGGER="logger -t prune-$ARTIFACT"

if [ -z "$ARTIFACT" ]; then
  echo "$USAGE"
  $LOGGER "$USAGE"
  exit 1
fi

oc project default

if [ "$ARTIFACT" == "images" ]; then
  $LOGGER "pruning $ARTIFACT over $KEEP_YOUNGER, keep at least $KEEP_TAG_REVISIONS tag revisions as user $PRUNE_SERVICEACCOUNT"
  $LOGGER "oc --token=<token> adm prune $ARTIFACT --keep-tag-revisions=$KEEP_TAG_REVISIONS  --keep-younger-than=$KEEP_YOUNGER --confirm"
  oc --token=$(oc serviceaccounts get-token "$PRUNE_SERVICEACCOUNT") adm prune "$ARTIFACT" \
    --keep-tag-revisions="$KEEP_TAG_REVISIONS"  --keep-younger-than="$KEEP_YOUNGER" --confirm | $LOGGER

else
  $LOGGER "pruning $ARTIFACT over $KEEP_YOUNGER, keep at least $KEEP_COMPLETE and $KEEP_FAILED failed"

  artifact_count=$(oc adm prune $ARTIFACT \
    --orphans --keep-complete=$KEEP_COMPLETE --keep-failed=$KEEP_FAILED --keep-younger-than=$KEEP_YOUNGER 2>/dev/null | wc -l)
  if [ $? -eq 0 ]; then
    $LOGGER "count $artifact_count $ARTIFACT to delete"
    if [ "$artifact_count" -gt "0" ]; then
      $LOGGER "oc adm prune $ARTIFACT " \
        "--orphans --keep-complete=$KEEP_COMPLETE --keep-failed=$KEEP_FAILED --keep-younger-than=$KEEP_YOUNGER --confirm"
      oc adm prune "$ARTIFACT" \
        --orphans --keep-complete="$KEEP_COMPLETE" --keep-failed="$KEEP_FAILED" --keep-younger-than="$KEEP_YOUNGER" --confirm
    fi
  else
    $LOGGER "failed to count existing $ARTIFACT"
    exit 1
  fi
fi