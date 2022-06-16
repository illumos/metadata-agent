#!/bin/bash

DLADM="/usr/sbin/dladm"
IPADM="/usr/sbin/ipadm"
GREP="/usr/bin/grep"

links=$($DLADM show-link -p -o link,class | $GREP phys)

for link in $links; do
  link_name=${link%:*}
  link_class=${link#*:}
  echo "Trying to enable DHCP on $link_name"
  if $IPADM create-addr -T dhcp -1 -t "$link_name/cloud-init-dhcp"; then
    break;
  fi
done