#!/bin/bash
mkdir reports
for n in $(kubectl get ns | awk '{print $1}')
do
  for vuln in $(kubectl get vuln --no-headers -n  $n 2> /dev/null  | awk '{print $1}')
  do
    echo writing to $n."$vuln"
    kubectl get vuln  "$vuln" -n $n -o yaml > reports/$n."$vuln"    
  done
done
