#!/bin/bash

root_domains="orgs.txt"
full_domains="all_domains.txt"
daily_domains="daily_domains.txt"

while true; do
    cat $root_domains | awk '{print $NF}' | gungnir -r <(cat -) | anew $full_domains | notify -silent -id daily_recon | tee -a $daily_domains
    sleep 3600
done
