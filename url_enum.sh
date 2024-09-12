#!/bin/bash

## Ctrl + c 
# (function)
signal_handler(){
  echo -e "\n[!] User terminated."
  tput cnorm; exit 1 # return cursor and exit
}
# (signal)
trap signal_handler SIGINT

## Functions
# display help panel
help(){
  echo -e "\nDescription: Web scraping of website"
  echo
  echo "[*] Use: $0 target_url"
  echo
}

# valid arguments
if [[ $# -ne 1 ]]
then
  help
  tput cnorm; exit 1
fi

# get the urls of a website
get_urls(){
  local scan_depth_limit=$2
  target_url=$1

  local website_urls=$(curl -skL $target_url | grep -oP "(\"|'|)(href|src|url)(\"|'|)\s*(=|:|,)\s*[\"|'|](.*?)[\"|'|>]" | sort -u | grep -oP '"(.*?)"' | tr -d '"' | grep -vE "^#" | xargs)
  IFS=' ' read -ra website_urls_array <<< "$website_urls"
  
  ((scan_depth_limit--))
  for url in "${website_urls_array[@]}"
  do
    if [[ "$url" != *"http"* ]]
    then
      if  [[ "$url" != *"//"* ]] then
        target_url=$(echo -n "$target_url" | grep -oP "https?://.*?/")
        echo $target_url$url
        echo $target_url$url >> new_data.txt
      else
        echo "https:"$url >> new_data.txt
      fi
      continue
    else
      if [[ ! "$url" == *"$scope"* || ! "$target_url" == *"$scope"* ]]
      then
        continue
      fi
    fi
    echo $url >> new_data.txt
    
    if [[ ! $scan_depth_limit -eq 0 ]]
    then
      if [[ "$(echo -n "$url" | tail -c 1)" != "/" ]]; then 
        url+="/"; 
      fi
      get_urls "$url" $scan_depth_limit &
    else
      return
    fi
  done; wait
}


# Main flow
# ---------
tput civis # hide cursor (esthetic)

scan_depth_limit=3
filename="custom_urls.txt"

if ! test -f $filename; then
  echo -n '' > $filename # create file to save urls
fi
if ! test -f "new_data.txt"; then
  echo -n '' > new_data.txt # create temp file
fi

target_domain=$(echo $1 | awk -F'//' '{print $2}' | awk -F'/' '{print $1}' | tr -d '\n') # only find with specific domain
scope=$(echo $target_domain | awk -F'.' '{print $(NF-1)"."$NF}')
echo -e "\n[*] Scanning site: $1\n"
get_urls "$1" $scan_depth_limit # call function (recursive)


cat new_data.txt | sort -u | anew $filename # filter unique urls and save
rm new_data.txt
echo -e "\n[+] Saving output: $filename"

tput cnorm # return cursor
