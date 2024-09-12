#!/bin/bash

# global variables
temp_file="tmp.txt"
domains_file="all_domains.txt"
urls_file="all_urls.txt"
bruteforce_wordlist="" #/YOUR_PATH/combined_subdomains.txt"
resolvers_file="" #/YOUR_PATH/resolvers-trusted.txt"
massdns_path="" #/YOUR_PATH/massdns/bin/massdns"
alive_file="alive_domains.txt"
pids=()
NUM_JOBS=20 # to ASN enumeration
export PDCP_API_KEY=YOUR-KEY-HERE # update proyect discovery api key
export GITHUB_TOKEN=YOUR-TOKEN-HERE # update github token
shodan_api=YOUR-SHOADAN-API # update shodan api
bufferover_api=YOUR-BUTT-API # update bufferover api

# Ctrl + c
signal_handler(){
    # Wait for any remaining background jobs to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    # to amass threads (upgrade later)
    pkill -P $$
    
    # del some files
    rm -f $temp_file wordlist_path_* *.out *.temp

    echo -e "\n[!] User aborted."
    exit 1
}
# (signal)
trap signal_handler SIGINT
# add new data (execution)
add_new_data(){
    local data_file=$1
    local out_file=$2
    local curr_out_file=$3

    cat $data_file | sort -u | anew $out_file > "$curr_out_file"
    echo "$(wc -l $curr_out_file | awk '{print $1}')"
}

# requirements
check_program(){
    command -v "$1" >/dev/null 2>&1 || {
        echo >&2 "Error: $1 is not installed. Please install $1 and try again."
        exit 1
    }
}
# !!! Importan: you need to install those manually.
check_requirements(){
    programs=("lynx" "asnmap" "metabigor" "amass" "tlsx" "anew" "subfinder" "jq" "sublist3r.py" "psql" "theHarvester.py" "github-subdomains" "shosubgo" "shuffledns" "$massdns_path" "dnsgen" "parallel" "dnsx" "httpx" "waybackurls" "gau" "katana" "gospider" "hakrawler" "uro")
    for program in "${programs[@]}"; do
        check_program $program
    done
}

# help
help_panel(){
    echo
    echo -e "[*] Usage: $0 -d root_domains.txt [-a (asn_enum)] [-p (passive_enum)] [-b (active_enum)] [-l [domains_file](alive_domains)] [-u [domains_file](url_enum)]"

    echo -e "\n[*] root_domains.txt format:"
    echo -e "\t<COMPANY NAME> <ROOT DOMAIN>"
    echo -e "\tGOOGLE google.com"
    echo -e "\t..."
}

# split and add new values to array
add_to_array(){
    local string=$1
    local delimiter=$2
    local -n arr=$3

    IFS="$delimiter" read -ra temp_array <<< "$string"
    arr+=("${temp_array[@]}")
}

# required threads commands
run_command(){
    local tool=$1
    local cidr=$2

    echo "Starting $tool for CIDR: $cidr"
    if [ "$tool" == "amass" ]; then
        amass intel -cidr "$cidr" -max-dns-queries 200 -timeout 5 | tee -a $temp_file
    elif [ "$tool" == "tlsx" ]; then
        echo "$cidr" | tlsx -san -cn -silent -resp-only | tee -a $temp_file
    fi
}

# parallel jobs
parallel_job(){
    local tool=$1
    local total_commands=$((${#uniq_cidrs_arr[@]}/$NUM_JOBS))
    local i=1

    for cidr in "${uniq_cidrs_arr[@]}"; do
        run_command "$tool" "$cidr" &
        pids+=($!)

        # If the number of background jobs reaches NUM_JOBS, wait for them to finish
        if [[ ${#pids[@]} -ge $NUM_JOBS ]]; then
	    # first update progress bar
	    draw_progress_bar $(($i * 100 / $total_commands)) && ((i++))
	    echo ""
    
            for pid in "${pids[@]}"; do wait "$pid"; done
            pids=()
        fi
    done

    # Wait for any remaining background jobs to complete
    for pid in "${pids[@]}"; do wait "$pid"; done
}

# function to draw a progress bar
draw_progress_bar() {
    local width=50
    local progress=$(( $1 * width / 100 ))
    local complete=$(printf "%${progress}s")
    local remaining=$(printf "%$((width - progress))s")
    printf "\rProgress: [${complete// /#}${remaining// /-}] ${1}%%"
}

# ASN/CIDR enumeration
asn_enumeration(){ 
    declare -a asns_arr
    declare -a cidrs_arr

    echo "[*] Enum ASNs and CIDRs:"
    IFS=$'\n'; # read lines with spaces
    for company in $(cat $companies); do

        # get ASNs (lynx + bgp)
        org=$(echo $company | awk '{$NF=""}1')
        org_enc=$(echo -n $org | tr ' ' '+' | head -c -1)
        asns=$(lynx --nolist \
                    --nonumbers \
                    --dump \
                    "https://bgp.he.net/search?search%5Bsearch%5D=%22$org_enc%22&commit=Search" | grep -oP "AS\d+" | awk '{print $1}' | xargs)
		
        # get CIDRs (asnmap & metabigor)
        domain=$(echo $company | awk '{print $NF}')
        cidrs=$(asnmap -silent -d "$domain" && echo "$asns" | metabigor net --asn -q \
                && asnmap -silent -a "$(echo "$asns" | sed 's/ /,/g')") # ASNs to CIDRs
        cidrs=$(echo $cidrs | xargs)

        # print data      
        echo "$org: $domain -> $asns, $cidrs"
        
        # add data to array
        add_to_array "$asns" " " asns_arr
        add_to_array "$cidrs" " " cidrs_arr
    done
    
    # filter uniq values
    uniq_asns_arr=($(for i in "${asns_arr[@]}"; do echo "${i}"; done | sort -u))
    uniq_cidrs_arr=($(for i in "${cidrs_arr[@]}"; do echo "${i}"; done | sort -u))
    
    echo "[+] ${#uniq_asns_arr[@]} ASNs Found: ${uniq_asns_arr[@]}"
    echo "[+] ${#uniq_cidrs_arr[@]} CIDRs Found: ${uniq_cidrs_arr[@]}"
     
    # CIRD Domain enumeration
    echo "[*] Domain enum: CIDRs"

    # Threads
    # (amass)
    parallel_job "amass"
    # (tlsx)
    #parallel_job "tlsx" # works but take a lot of time...
    
    # save new domains found
    echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"
    rm -f $temp_file
}

# Passive enumeration
pass_enumeration(){
	
    IFS=$'\n'; # read lines with spaces
    for company in $(cat $companies); do
	domain=$(echo $company | awk '{print $NF}')
	
	# A.R.P. syndicate
	echo "[*] a.r.p. syndicate enum:"
	curl -sk "https://api.subdomain.center/?domain=$domain" | jq -r .[] | tee -a $temp_file
        echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"

    	# subfinder
	echo "[*] subfinder enum:"
	subfinder -silent -no-color -recursive -all -d $domain | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"

	# sublist3r
	echo "[*] sublist3r enum:"
	out_file="out.txt"
    	Sublist3r/sublist3r.py --no-color -d $domain -o $out_file && cat $out_file | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"
        rm -f $out_file 	
	
	# crtsh
	echo "[*] crtsh enum:"	
	DOMAIN="$domain" && echo "SELECT lower(NAME_VALUE) NAME_VALUE FROM certificate_and_identities WHERE plainto_tsquery('certwatch', '%.$DOMAIN') @@ identities (CERTIFICATE) AND NAME_TYPE LIKE 'san:%';" | psql -q --csv -t -h crt.sh -p 5432 -U guest certwatch 2>/dev/null | grep -v '#\| |Interrupt' | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"

	# theHarverest
	echo "[*] theharverest enum:"
	theHarvester/theHarvester.py -d $domain -b "anubis,baidu,github-code,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,urlscan,yahoo" | grep "Hosts found" -A 100000 | tail -n +3 | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"

	# github
	echo "[*] Github enum:"
	for i in $(seq 1 4); do
	    github-subdomains -d $domain >/dev/null
	    sleep 6
	done
	sleep 4
	github-subdomains -d $domain >/dev/null
	cat "$domain.txt" | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"
	rm -f "$domain.txt" #
	
	# Shosubgo
	echo "[*] Shosubgo enum:"
	shosubgo -d $domain -s $shodan_api | tee -a $temp_file	
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"
	
	# cloud ranges
	echo "[*] tls bufferver enum:"
	curl -sk "https://tls.bufferover.run/dns?q=.$domain" -H "x-api-key: $bufferover_api" | jq -r '.Results[] | split(",") | .[4]' | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"

	rm -f $temp_file
    done
}

# Active enumeration

# amass thread performance
set_thread_config(){
    wordlist=$1

    MAX_JOBS=$((6 * 75 / 100)) # CPU based
    WORDLIST_LEN=$(wc -l $wordlist | awk '{print $1}')
    LINES_PER_THREAD=$((WORDLIST_LEN / MAX_JOBS))
}

acti_enumeration(){

    IFS=$'\n'; # read lines with spaces
    for company in $(cat $companies); do
	domain=$(echo $company | awk '{print $NF}')
	
	# ShuffleDNS (require massdns binary)
	echo "[*] shuffleDNS enumeration:"
	shuffledns -silent -nc -d $domain -w $bruteforce_wordlist -r $resolvers_file -m $massdns_path -mode bruteforce | tee -a $temp_file
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"
   	
	# amass
	# set configuration and split wordlist to threads
	set_thread_config $bruteforce_wordlist
	split -l $LINES_PER_THREAD $bruteforce_wordlist wordlist_path_

	echo "[*] amass enumeration:"
	for sub_wordlist in wordlist_path_*; do
	    amass enum -nocolor -brute -active -d $domain -w "$sub_wordlist" -trf $resolvers_file -dns-qps 300 -timeout 30 -o "$sub_wordlist".out &
	done; wait
	cat *.out | grep 'FQDN' | awk '{print $1"\n"$6}' | grep -vP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|:' | tee -a $temp_file # extract only domains
	echo "[+] New domains found: $(add_new_data "$temp_file" "$domains_file")"
	rm -f wordlist_path_* $temp_file
     
    done
 
    # dnsgen (permutation) much domains, maybe with small target scope
    # set config to threads
    #set_thread_config $domains_file
    #split -l $LINES_PER_THREAD $domains_file domains_chunk_

    #echo "[*] domains permutation:"
    #ls domains_chunk_* | parallel -j 4 'cat {} | dnsgen - | tee {}_out.txt'
    #amass enum -nocolor -d domains_chunk_*_out.txt -trf $resolvers_file -dns-qps 300 -o dom_resolved.out # resolve gen domains
	
    # ..... filter domains    

    #new_domains=$(cat $temp_file | sort -u | anew $domains_file | wc -l)
    #echo "[+] New domains created: $new_domains"

}

# Alive domains
domains_validation(){
    echo "[+] Alive domains validation:"
    
    # alive temp
    domains_tmp="alive_$(date +"%Y_%m_%d-%H:%M").temp"

    cat $domains | awk -F':' '{print $1}' | grep -vE '\*|@' | sort -u \
	    | dnsx -silent -no-color -t 200 -r $resolvers_file \
	    | httpx -silent -no-color -cname -title -location -web-server -tech-detect -content-type -random-agent -content-length -threads 200 -o $temp_file # httpx python conflicts, use full go path /HOME/XNAME/go/bin/httpx

    # add to main list and save current alive domains apart
    echo "[+] New alive domains found: $(add_new_data "$temp_file" "$alive_file" "$domains_tmp")"

    rm -f $temp_file
}

# URL enumeration
url_enumeration(){
    echo "[+] URL enumeration:"
    
    # url temp
    urls_tmp="urls_$(date +"%Y_%m_%d-%H:%M").temp"
    
    # extract only domains, exclude cname, title, etc. 
    domains="domains.temp"
    cat $alive_domains | awk '{print $1}' > $domains
    
    echo "[*] Waybackurls:" 
    cat $domains | parallel -j 4 "echo {} | waybackurls | tee -a $temp_file"
    echo "[*] Gau:"
    cat $domains | gau --threads 100 --o gau.out | tee -a $temp_file
    echo "[*] katana:"
    katana -list $domains -silent -no-color -system-chrome -concurrency 100 -r $resolvers_file -headless -js-crawl -jsluice -o katana.out | tee -a $temp_file # maybe add -display-out-scope
    echo "[*] Hakrawler:"
    cat $domains | hakrawler -d 4 -t 100 | tee -a $temp_file
    echo -e "\n[*] Gospider:"
    gospider -S $domains -q -t 100 -c 10 -d 1 --other-source --include-subs > gospider.out
    cat gospider.out | awk -F' - ' '{print $NF}' | tee -a $temp_file # gospider filter
    
    # filter duplicates uris, save urls to main list and save current urls
    cat $temp_file | sort -u | uro | anew $urls_file > "$urls_tmp"
    new_urls=$(wc -l $urls_tmp | awk '{print $1}')
    echo "[+] New urls found: $new_urls"
    rm -f *.out $temp_file $domains
    
    # filter by scope
    # maybe order like gospider output?
}

# valid parameters
if [[ "$#" -eq 0 ]]; then
    help_panel; exit 1
fi

# valid requirements
check_requirements

# Main flow
while getopts ":hd:apbl:u:" opt
do
    case $opt in
	h)
	    help_panel
	    exit 1;;
	d)
	    companies=$OPTARG;;
	a)
	    asn_enumeration;;
	p) 
	    pass_enumeration;;
	b)
	    acti_enumeration;;
	l)
	    if [ -z "$OPTARG" ]; then
		domains=$domains_file
	    else
		domains=$OPTARG
	    fi
	    domains_validation;;
	u)  
	    if [ -z "$OPTARG" ]; then
		alive_domains=$alive_file
	    else
		alive_domains=$OPTARG
	    fi
	    url_enumeration;;
        \?)
            echo -e "\n[-] Invalid option."
            exit 1;;
    esac
done

# call functions
#asn_enumeration # too slow, upgrade tlsx performance, maybe with parallel tool
#pass_enumeration # good
#acti_enumeration # good (think permutation)
#domains_validation
