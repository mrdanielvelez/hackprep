#!/usr/bin/env bash
# HACKPREP by Daniel Velez — Version 1.0 — Automation script for configuring an attack machine
# Installs tools for penetration testing and performs several optimization actions

# EDITABLE:
TOOLS_DIRECTORY="/opt/tools" && NESSUS_USERNAME="admin" && DEFAULT_INTERFACE="eth0" && DATE=`date "+%F"`
# DO NOT EDIT:
NESSUS_RULES_FILE="/opt/nessus/etc/nessus/nessusd.rules" && NESSUS_LICENSE= && COBALT_STRIKE_LICENSE= && ARCH=`arch` && INSTALL_NESSUS=true && INSTALL_COBALT_STRIKE=true
OUTPUT_NESSUS=false && OUTPUT_COBALT_STRIKE=false && MALLEABLE_C2_PROFILE= && FRAGILE_HOSTS_FILE=
INTERNAL_IP=`ip -f inet addr show $DEFAULT_INTERFACE | sed -En 's/.*inet ([0-9.]+).*/\1/p'`
PLUS_SIGN="\033[1m\033[92m[+]\033[0m" && NEGATIVE_SIGN="\033[1m\033[91m[-]\033[0m" && STAR_SIGN="\033[1m[*]\033[0m"
PROMPT_SIGN="\033[1m\033[95m[>]\033[0m" && INSTALL_SIGN="\033[1m\033[95m[!]\033[0m"

main() {
	intro
	test_connectivity
	check_arch
	display_prompts
	apt_operations
	install_nessus
	configure_nessus
	install_cobalt_strike
	configure_cobalt_strike
	update_tools
	install_collection
	install_requirements
	configure_responder
	backup_resolv
	update_database
	fix_libcrypto
	fix_certipy
	zshrc_functions
	conclusion
}

intro() {
	echo -e "[\033[1m\033[3m\033[93mHACKPREP\033[0m by Daniel Velez — \033[96mAutoconfigure\033[0m an \033[91mAttack Machine\033[0m — \033[93mv1.0\033[0m]\n"
	if [[ $EUID -ne 0 ]]
	then
		clean_exit "\033[1m\033[3m\033[93mHACKPREP\033[0m must be executed as \033[37mroot\033[0m."
	elif [[ ! -d $TOOLS_DIRECTORY ]]
	then
		mkdir $TOOLS_DIRECTORY && chmod 755 $TOOLS_DIRECTORY && echo -e "$PLUS_SIGN Created directory for tools: \033[93m$TOOLS_DIRECTORY\033[0m"
	fi
}

test_connectivity() {
	if ping -q -c 1 8.8.8.8 &>/dev/null && ping -q -c 1 1.1.1.1 &>/dev/null
	then
		echo -e "$PLUS_SIGN Confirmed internet connectivity."
	else
		clean_exit "Internet connectivity tests failed."
	fi
	if host google.com &>/dev/null && host cobaltstrike.com &>/dev/null && host nessus.com &>/dev/null
	then
		echo -e "$PLUS_SIGN External IP address: \033[93m`curl -s -k -L ifconfig.io || curl -s -k -L ipinfo.io/ip`\033[0m."
		echo -e "$PLUS_SIGN Internal IP address: \033[93m$INTERNAL_IP\033[0m."
		echo -e "$PLUS_SIGN Confirmed DNS name resolution."
	else
		clean_exit "DNS name resolution tests failed."
	fi
}

check_arch() {
	if [[ $ARCH == "x86_64" ]]
	then
		NESSUS_FILENAME="Nessus-latest-debian10_amd64.deb"
	elif [[ $ARCH == "aarch64" ]]
	then
		NESSUS_FILENAME="Nessus-latest-ubuntu1804_$ARCH.deb"
		echo -e "$NEGATIVE_SIGN arm64 isn't compatible with \033[91mCobalt Strike's\033[0m team server." \
		&& INSTALL_COBALT_STRIKE=false
	else
		clean_exit "Unsupported CPU architecture."
	fi
}

display_prompts() {
	if [[ $INSTALL_NESSUS == true ]]
	then
		echo -n -e "$PROMPT_SIGN Enter \033[94mNessus\033[0m license key (optional): " 1>&2
		while true; do
		  IFS= read -r -N1 -s char
		  code=$(printf '%02x' "'$char")
		  case "$code" in
		  ''|0a|0d) break ;; # Exit EOF, Linefeed, or Return
		  08|7f) # Backspace or Delete
		      if [ -n "$NESSUS_LICENSE" ]; then
		        NESSUS_LICENSE="$( echo "$NESSUS_LICENSE" | sed 's/.$//' )"
		        echo -n $'\b \b' 1>&2
		      fi
		      ;;
		  15) # ^U or kill line
		      echo -n "$NESSUS_LICENSE" | sed 's/./\cH \cH/g' >&2
		      NESSUS_LICENSE=''
		      ;;
		  [01]?) ;; # Ignore all other control characters
		  *)  NESSUS_LICENSE="$NESSUS_LICENSE$char"
		      echo -n '*' 1>&2
		      ;;
		  esac
		done

		echo
		if [[ -z $NESSUS_LICENSE ]]
		then
			echo -e "$STAR_SIGN No license key was entered. Skipping \033[94mNessus\033[0m..."
			INSTALL_NESSUS=false
		elif ! grep -P -q '^[A-Za-z0-9]{4}+-[A-Za-z0-9]{4}+-[A-Za-z0-9]{4}+-[A-Za-z0-9]{4}+$' <<< $NESSUS_LICENSE
		then
			clean_exit "Error — invalid license key."
		else
			echo -e "$STAR_SIGN Specify a list of \033[93mhosts\033[0m for \033[94mNessus\033[0m to reject (besides \033[93m$INTERNAL_IP\033[0m)."
			echo -e "$STAR_SIGN Press \033[37mEnter\033[0m if N/A. Tab completion is \033[92menabled\033[0m. A relative path works."
			echo -e -n "$PROMPT_SIGN"
			read -e -p " File path (optional): " FRAGILE_HOSTS_FILE
			
			if [[ -f $FRAGILE_HOSTS_FILE ]]
			then
				FRAGILE_HOSTS_FILE=`realpath $FRAGILE_HOSTS_FILE`
			fi
		fi
	fi

	if [[ $INSTALL_COBALT_STRIKE == true ]]
	then
		echo -n -e "$PROMPT_SIGN Enter \033[91mCobalt Strike\033[0m license key (optional): " 1>&2
		while true; do
		  IFS= read -r -N1 -s char
		  code=$(printf '%02x' "'$char")
		  case "$code" in
		  ''|0a|0d) break ;; # Exit EOF, Linefeed, or Return
		  08|7f) # Backspace or Delete
		      if [ -n "$COBALT_STRIKE_LICENSE" ]; then
		        COBALT_STRIKE_LICENSE="$( echo "$COBALT_STRIKE_LICENSE" | sed 's/.$//' )"
		        echo -n $'\b \b' 1>&2
		      fi
		      ;;
		  15) # ^U or kill line
		      echo -n "$COBALT_STRIKE_LICENSE" | sed 's/./\cH \cH/g' >&2
		      COBALT_STRIKE_LICENSE=''
		      ;;
		  [01]?) ;; # Ignore all other control characters
		  *)  COBALT_STRIKE_LICENSE="$COBALT_STRIKE_LICENSE$char"
		      echo -n '*' 1>&2
		      ;;
		  esac
		done

		echo
		if [[ -z $COBALT_STRIKE_LICENSE ]]
		then
			echo -e "$STAR_SIGN No license key was entered. Skipping \033[91mCobalt Strike\033[0m..."
			INSTALL_COBALT_STRIKE=false 
		elif ! grep -P -q '^[A-Za-z0-9]{4}+-[A-Za-z0-9]{4}+-[A-Za-z0-9]{4}+-[A-Za-z0-9]{4}+$' <<< $COBALT_STRIKE_LICENSE
		then
			clean_exit "Error — invalid license key."
		else
			echo -e "$STAR_SIGN Specify a \033[96mMalleable C2 Profile\033[0m to use within \033[91mCobalt Strike\033[0m\033[0m."
			echo -e "$STAR_SIGN Press \033[37mEnter\033[0m if N/A. Tab completion is \033[92menabled\033[0m. A relative path works."
			echo -e -n "$PROMPT_SIGN"
			read -e -p " File path (optional): " MALLEABLE_C2_PROFILE

			if [[ -f $MALLEABLE_C2_PROFILE ]]
			then
				MALLEABLE_C2_PROFILE=`realpath $MALLEABLE_C2_PROFILE`
			else
				MALLEABLE_C2_PROFILE="$TOOLS_DIRECTORY/cobaltstrike/c2-profiles/normal/webbug.profile"
			fi
		fi
	fi
}

apt_operations() {
	echo -e "$STAR_SIGN Executing \033[95mAPT\033[0m package operations..."
	if apt update -y &>/dev/null && apt autoremove -y &>/dev/null
	then
		echo -e "$PLUS_SIGN Performed update/cleanup tasks via \033[95mAPT\033[0m."
	else
		echo -e "$NEGATIVE_SIGN APT operations failed. Continuing..."
	fi
}

install_nessus() {
	if [[ $INSTALL_NESSUS == false ]]; then return 1; fi

	if dpkg -l | grep -q -i nessus
	then
		echo -e "$STAR_SIGN \033[94mNessus\033[0m appears to be installed already."
		echo -e -n "$PROMPT_SIGN Is \033[1m\033[3m\033[93mHACKPREP\033[0m permitted to reinstall it?"
		read -n 1 -p " [y | n] " choice && echo
		if [[ $choice =~ y|Y ]]
		then
			echo -e "$STAR_SIGN Uninstalling \033[94mNessus\033[0m..."
			if ! systemctl stop nessusd.service &>/dev/null \
			&& systemctl disable nessusd.service &>/dev/null \
			&& echo y | /opt/nessus/sbin/nessuscli fix --reset-all &>/dev/null \
			&& echo > $NESSUS_RULES_FILE
			then
				clean_exit "Unable to reset original \033[94mNessus\033[0m instance prior to reinstallation."
			fi
			NESSUS_USERLIST=`/opt/nessus/sbin/nessuscli lsuser`
			for USERNAME in $NESSUS_USERLIST
			do
				if ! echo y | /opt/nessus/sbin/nessuscli rmuser $USERNAME &>/dev/null
				then
					clean_exit "Unable to clear \033[94mNessus\033[0m userbase prior to reinstallation."
				fi
			done
			if ! rm -rf /opt/nessus/* && apt purge -y nessus && dpkg -P nessus &>/dev/null && rm -rf /opt/nessus* && systemctl daemon-reload && systemctl reset-failed
			then
				clean_exit "Unable to uninstall \033[94mNessus\033[0m."
			fi
		elif [[ $choice =~ n|N ]]
		then
			echo -e "$NEGATIVE_SIGN Continuing without reinstalling/configuring \033[94mNessus\033[0m..."
			INSTALL_NESSUS=false
			return 1
		else
			clean_exit "Error — invalid input."
		fi
	fi

	echo -e "$STAR_SIGN Downloading and installing \033[94mNessus\033[0m..."
	curl -s -k -L "https://www.tenable.com/downloads/api/v2/pages/nessus/files/$NESSUS_FILENAME" -o /tmp/$NESSUS_FILENAME
	if ! dpkg -i /tmp/$NESSUS_FILENAME &>/dev/null && rm /tmp/$NESSUS_FILENAME \
	&& systemctl start nessusd.service && systemctl enable nessusd.service
	then
		clean_exit "Error installing \033[94mNessus\033[0m via /tmp/$NESSUS_FILENAME."
	fi
}

configure_nessus() {
	if [[ $INSTALL_NESSUS == false ]]; then return 1; fi

	echo -e "$STAR_SIGN Updating and initializing \033[94mNessus\033[0m..."
	if /opt/nessus/sbin/nessuscli fetch --register "$NESSUS_LICENSE" &>/dev/null \
	&& systemctl restart nessusd.service &>/dev/null
	then
		echo -e "$PLUS_SIGN Activated \033[94mNessus\033[0m using license key."
	else
		clean_exit "Failed to activate \033[94mNessus\033[0m using license key."
	fi

	NESSUS_PASSWORD=`head /dev/urandom | tr -dc 'A-Za-z0-9[]{}^!' | head -c 20`
	if [[ -n $NESSUS_PASSWORD ]]
	then
		echo -e "$PLUS_SIGN Generated a secure password for \033[94mNessus\033[0m."
	else
		clean_exit "Couldn't generate a password for \033[94mNessus\033[0m."
	fi

	cat <<< '#!/usr/bin/expect -f
	set username [lindex $argv 0];
	set password [lindex $argv 1];
	spawn /opt/nessus/sbin/nessuscli adduser $username

	expect "Login password"
	send -- "$password\r"

	expect "Login password"
	send -- "$password\r"

	expect "system administrator"
	send -- "y\r"

	expect "empty rules set"
	send -- "\r"

	expect "system administrator"
	send -- "y\r"
	expect eof' > /tmp/create_nessus_user.exp

	if apt install expect -y &>/dev/null && \
	expect -f /tmp/create_nessus_user.exp $NESSUS_USERNAME $NESSUS_PASSWORD &>/dev/null && rm /tmp/create_nessus_user.exp \
	&& echo -e "[Nessus Credentials for https://127.0.0.1:8834]\n\n$NESSUS_USERNAME:$NESSUS_PASSWORD\n\n[Generated by HACKPREP on $DATE]\n" > /opt/nessus/creds_hackprep_$DATE.txt
	then
		OUTPUT_NESSUS=true
		echo -e "$INSTALL_SIGN Output info to \033[92m/opt/nessus/creds_hackprep_$DATE.txt\033[0m."
	else
		clean_exit "Unable to create admin user and output \033[94mNessus\033[0m credentials file."
	fi
	
	systemctl restart nessusd.service
	sleep 3
	sed -i '/default accept/d' $NESSUS_RULES_FILE || touch $NESSUS_RULES_FILE

	if grep -q "reject $INTERNAL_IP" $NESSUS_RULES_FILE \
	|| echo "reject $INTERNAL_IP" >> $NESSUS_RULES_FILE
	then
		echo -e "$PLUS_SIGN Rejected the attack machine (\033[93m$INTERNAL_IP\033[0m) within \033[94mNessus\033[0m."
	else
		clean_exit "Unable to append to \033[93mnessusd.rules\033[0m. Troubleshoot   \033[94mNessus\033[0m installation."
	fi

	if apt install sqlite3 -y &>/dev/null && \
	sqlite3 /opt/nessus/etc/nessus/nessusd.db \
	'update preferences set value = "127.0.0.1" where name = "listen_address"; update preferences set value = "no" where name = "scan_vulnerability_groups"; update preferences set value = "no" where name = "scan_vulnerability_groups_mixed"'
	then
		echo -e "$PLUS_SIGN Configured \033[94mNessus\033[0m to only listen on localhost (\033[93m127.0.0.1\033[0m)."
		echo -e "$PLUS_SIGN Disabled vulnerability grouping within \033[94mNessus\033[0m."
	else
		clean_exit "Unable to edit \033[93mnessusd.db\033[0m SQLite database file via sqlite3."
	fi

	if [[ -f $FRAGILE_HOSTS_FILE ]]
	then
		COUNTER=0
		for host in `cat $FRAGILE_HOSTS_FILE`
		do
			(( COUNTER++ ))
			echo "reject $host" >> $NESSUS_RULES_FILE
		done
		echo -e "$INSTALL_SIGN Rejected \033[93m$COUNTER\033[0m hosts from \033[96m$FRAGILE_HOSTS_FILE\033[0m within \033[94mNessus\033[0m."
	fi
	
	echo "default accept" >> $NESSUS_RULES_FILE

	if ! systemctl restart nessusd.service
	then
		clean_exit "Error restarting \033[94mNessus\033[0m."
	fi
}

install_cobalt_strike() {
	if [[ $INSTALL_COBALT_STRIKE == false ]]; then return 1; fi

	if [[ -d $TOOLS_DIRECTORY/cobaltstrike ]]
	then
		echo -e "$NEGATIVE_SIGN The directory \033[93m$TOOLS_DIRECTORY/cobaltstrike\033[0m already exists."
		echo -e -n "$PROMPT_SIGN Is \033[1m\033[3m\033[93mHACKPREP\033[0m permitted to overwrite this directory?"
		read -n 1 -p " [y | n] " choice && echo
		if [[ $choice =~ y|Y ]]
		then
			systemctl stop teamserver_hackprep.service &>/dev/null
			systemctl disable teamserver_hackprep.service &>/dev/null
			rm -rf /etc/systemd/system/teamserver_hackprep.service &>/dev/null
			for file in `locate teamserver_hackprep.service`; do rm -rf $file; done
			systemctl daemon-reload &>/dev/null
			systemctl reset-failed &>/dev/null
			if ! rm -rf $TOOLS_DIRECTORY/cobaltstrike
			then
				clean_exit "Unable to delete \033[93m$TOOLS_DIRECTORY/cobaltstrike\033[0m."
			fi
		elif [[ $choice =~ n|N ]]
		then
			echo -e "$NEGATIVE_SIGN Continuing without downloading \033[91mCobalt Strike\033[0m..."
			INSTALL_COBALT_STRIKE=false
			return 1
		else
			clean_exit "Error — invalid input."
		fi
	fi

	echo -e "$STAR_SIGN Downloading \033[91mCobalt Strike\033[0m to \033[93m$TOOLS_DIRECTORY/cobaltstrike\033[0m..."
	MAIN_TOKEN=`curl -s -k -L -X "POST" -d dlkey="$COBALT_STRIKE_LICENSE" 'https://download.cobaltstrike.com/download' | grep 'href="/downloads' | cut -d '/' -f 3,4`
	if [[ -z $MAIN_TOKEN ]]
	then
		clean_exit "Unable to extract \033[91mCobalt Strike\033[0m download token."
	fi
	curl -s -k -L "https://download.cobaltstrike.com/downloads/$MAIN_TOKEN/cobaltstrike-dist.tgz" -o /tmp/cobaltstrike-dist.tgz
	tar -xf /tmp/cobaltstrike-dist.tgz -C $TOOLS_DIRECTORY/ && rm /tmp/cobaltstrike-dist.tgz
	cd $TOOLS_DIRECTORY/cobaltstrike && ./update <<< $COBALT_STRIKE_LICENSE | grep "Unpacking" -q && echo -e "$PLUS_SIGN Successfully downloaded \033[91mCobalt Strike\033[0m. Unpacking data..."

	chmod +x "$TOOLS_DIRECTORY/cobaltstrike/TeamServerImage" &>/dev/null

	curl -s -k -L -X "POST" -o "/tmp/cs_request_$DATE.txt" -c "/tmp/cs_cookies_$DATE.txt" -d dlkey="$COBALT_STRIKE_LICENSE" 'https://download.cobaltstrike.com/scripts'
	ARSENAL_PATH=`grep 'href="/downloads/' "/tmp/cs_request_$DATE.txt" | head -n 1 | cut -d '/' -f 3,4 | cut -d '"' -f 1`
	if [[ -z $ARSENAL_PATH ]]
	then
		clean_exit "Unable to extract \033[96mArsenal Kit\033[0m file path."
	fi
	ARSENAL_ARCHIVE=`echo $ARSENAL_PATH | cut -d '/' -f 2`
	curl -s -k -L -b "/tmp/cs_cookies_$DATE.txt" "https://download.cobaltstrike.com/downloads/$ARSENAL_PATH" -o /tmp/$ARSENAL_ARCHIVE
	rm /tmp/cs_request_$DATE.txt /tmp/cs_cookies_$DATE.txt
	if tar -xf /tmp/$ARSENAL_ARCHIVE -C $TOOLS_DIRECTORY/cobaltstrike/
	then
		echo -e "$PLUS_SIGN Extracted the \033[96mArsenal Kit\033[0m to \033[93m$TOOLS_DIRECTORY/cobaltstrike/arsenal-kit\033[0m."
		rm /tmp/$ARSENAL_ARCHIVE
	else
		clean_exit "Unable to extract the \033[96mArsenal Kit\033[0m."
	fi

	if git clone https://github.com/rsmudge/Malleable-C2-Profiles $TOOLS_DIRECTORY/cobaltstrike/c2-profiles &>/dev/null
	then
		echo -e "$PLUS_SIGN Downloaded vanilla \033[96mMalleable C2 Profiles\033[0m to \033[93m$TOOLS_DIRECTORY/cobaltstrike/c2-profiles\033[0m."
	else
		echo -e "$NEGATIVE_SIGN Unable to download vanilla \033[96mMalleable C2 Profiles\033[0m."
	fi
}

configure_cobalt_strike() {
	if [[ $INSTALL_COBALT_STRIKE == false ]]; then return 1; fi

	echo -e "$STAR_SIGN Configuring and optimizing \033[91mCobalt Strike\033[0m..."

	TEAM_SERVER_PASSWORD=`head /dev/urandom | tr -dc 'A-Za-z0-9[]{}^!' | head -c 20`
	if [[ -n $TEAM_SERVER_PASSWORD ]]
	then
		echo -e "$PLUS_SIGN Generated a secure team server password."
	else
		clean_exit "Couldn't generate a team server password."
	fi

	if ! which shuf &>/dev/null; then apt install coreutils -y &>/dev/null; fi
	TEAM_SERVER_PORT=`shuf -i 10000-65000 -n 1` && sed -i "s/50050/$TEAM_SERVER_PORT/g" $TOOLS_DIRECTORY/cobaltstrike/teamserver
	if [[ -z $TEAM_SERVER_PORT ]]; then TEAM_SERVER_PORT=50050; fi # If a random port doesn't get generated, use the default port.

	if ! [[ -f $MALLEABLE_C2_PROFILE ]]
	then
		clean_exit "\033[96mMalleable C2 Profile\033[0m has not been specified."
	else
		cp $MALLEABLE_C2_PROFILE $TOOLS_DIRECTORY/cobaltstrike/c2-profiles/`basename $MALLEABLE_C2_PROFILE` \
		&& MALLEABLE_C2_PROFILE="c2-profiles/`basename $MALLEABLE_C2_PROFILE`"
	fi

	if ! echo -e "[Unit]\nDescription=Cobalt Strike Team Server\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=always\nRestartSec=1\nUser=root\nWorkingDirectory=$TOOLS_DIRECTORY/cobaltstrike\nExecStart=$TOOLS_DIRECTORY/cobaltstrike/teamserver '$INTERNAL_IP' '$TEAM_SERVER_PASSWORD' '$MALLEABLE_C2_PROFILE'\n\n[Install]\nWantedBy=multi-user.target" \
	> /etc/systemd/system/teamserver_hackprep.service
	then
		clean_exit "Couldn't create team server service file."
	fi

	echo -e "$STAR_SIGN Initializing team server service..."

	if systemctl daemon-reload &>/dev/null \
	&& systemctl reset-failed &>/dev/null \
	&& systemctl start teamserver_hackprep.service &>/dev/null \
	&& systemctl enable teamserver_hackprep.service &>/dev/null
	then
		sleep 4
		cd $TOOLS_DIRECTORY/cobaltstrike
		if ./c2lint $MALLEABLE_C2_PROFILE &>/dev/null | grep -q "Unable to load"
		then
			echo -e "$NEGATIVE_SIGN Error with \033[96m$MALLEABLE_C2_PROFILE\033[0m."
			clean_exit "Obtain info via c2lint, then rerun \033[1m\033[3m\033[93mHACKPREP\033[0m."
		fi
		echo -e "$PLUS_SIGN Launched team server on \033[1m\033[91m$INTERNAL_IP\033[0m\033[1m:\033[91m$TEAM_SERVER_PORT\033[0m."
		sleep 4
		SERVER_HASH=`journalctl -u teamserver_hackprep | grep hash | tail -n 1 | rev | cut -d ' ' -f 1 | rev`
		echo -e "$PLUS_SIGN Fingerprint: \033[1m\033[3m$SERVER_HASH\033[0m."
		if echo -e "[Cobalt Strike Team Server Connection Info]\n\nFingerprint: $SERVER_HASH\nServer: $INTERNAL_IP:$TEAM_SERVER_PORT\nPassword: $TEAM_SERVER_PASSWORD\n\n[Generated by HACKPREP on $DATE]\n" \
		> $TOOLS_DIRECTORY/cobaltstrike/server_info_hackprep_$DATE.txt
		then
			OUTPUT_COBALT_STRIKE=true
			echo -e "$INSTALL_SIGN Output info to \033[92m$TOOLS_DIRECTORY/cobaltstrike/server_info_hackprep_$DATE.txt\033[0m."
		else
			clean_exit "Unable to write team server connection info to \033[92m$TOOLS_DIRECTORY/cobaltstrike/\033[0m."
		fi
		else
		clean_exit "Unable to configure team server service."
	fi

	if mkdir $TOOLS_DIRECTORY/cobaltstrike/built_kits \
	&& echo -e "$PLUS_SIGN Created \033[93m$TOOLS_DIRECTORY/cobaltstrike/built_kits\033[0m. Building kits..."
	then
		for KIT in mimikatz resource process_inject
		do
			if cd $TOOLS_DIRECTORY/cobaltstrike/arsenal-kit/kits/$KIT \
			&& ./build.sh "$TOOLS_DIRECTORY/cobaltstrike/built_kits/$KIT" &>/dev/null
			then
				echo -e "$PLUS_SIGN Successfully built \033[95m$KIT\033[0m kit."
			else
				echo -e "$NEGATIVE_SIGN Unable to build \033[95m$KIT\033[0m kit. Continuing..."
			fi
		done
  	fi
}

update_tools() {
	if find $TOOLS_DIRECTORY/ -mindepth 1 -maxdepth 1 -type d -exec git -C {} pull \; &>/dev/null
	then
		echo -e "$PLUS_SIGN Updated tools within \033[93m$TOOLS_DIRECTORY\033[0m via Git."
	else
		echo -e "$NEGATIVE_SIGN Couldn't perform update operations within \033[93m$TOOLS_DIRECTORY\033[0m. Continuing..."
	fi
	if git clone https://github.com/udhos/update-golang /tmp/ug &>/dev/null && /tmp/ug/update-golang.sh &>/dev/null && rm -rf /tmp/ug
	then
		echo -e "$PLUS_SIGN Updated \033[93mGolang\033[0m via update-golang.sh."
	else
		clean_exit "Failed to update \033[93mGolang\033[0m via update-golang.sh."
	fi
}

install_collection() {
	echo -e "$STAR_SIGN Commencing installation routine. This may take a while..."

	# Git
	if ! apt install git -y &>/dev/null
	then
		echo "$NEGATIVE_SIGN Couldn't install \033[96mGit\033[0m. Exiting automatic tool installation process..."
		return 1
	else
		echo -e "$INSTALL_SIGN Installed \033[96mGit\033[0m via APT."
	fi

	# pipx
	if ! python3 -m pip install pipx --upgrade &>/dev/null && python3 -m pipx ensurepath &>/dev/null
	then
		echo "$NEGATIVE_SIGN Couldn't install \033[96mpipx\033[0m. Exiting automatic tool installation process..."
		return 1
	else
		echo -e "$INSTALL_SIGN Installed \033[96mpipx\033[0m via pip."
	fi

	# Impacket
	python3 -m pipx install impacket &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mImpacket\033[0m via pipx."

	# CrackMapExec
	python3 -m pipx install crackmapexec &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mCrackMapExec (CME)\033[0m via pipx."

	# Coercer
	python3 -m pipx install coercer &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mCoercer\033[0m via pipx."

	# Certipy
	python3 -m pipx install certipy-ad &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mCertipy\033[0m via pipx."

	# ldapdomaindump
	python3 -m pipx install ldapdomaindump &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mldapdomaindump\033[0m via pipx."

	# BloodHound Python Ingestor
	python3 -m pipx install bloodhound &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mBloodHound Python Ingestor (bloodhound-python)\033[0m via pipx."

	# mitm6
	rm -rf $TOOLS_DIRECTORY/mitm6 \
	&& python3 -m pipx install mitm6 &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mmitm6\033[0m via pipx."

 	# ntdsutil
	python3 -m pipx install git+https://github.com/mrdanielvelez/ntdsutil &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mntdsutil\033[0m via pipx."

	# feroxbuster
	apt install feroxbuster -y &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mferoxbuster\033[0m via APT."

	# Nmap
	apt install nmap -y &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mNmap\033[0m via APT."

	# BruteShark
	if ! [[ -d $TOOLS_DIRECTORY/BruteShark ]] && ! which BruteShark &>/dev/null && ! which BruteSharkCli &>/dev/null
	then
		curl -s -k -L https://github.com/odedshimon/BruteShark/releases/latest/download/BruteSharkCli \
		-o /usr/bin/BruteSharkCli && chmod 755 /usr/bin/BruteSharkCli \
		&& grep -q 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1' "$HOME/.zshrc" || echo 'export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1;' >> "$HOME/.zshrc" \
		&& echo -e "$INSTALL_SIGN Installed \033[96mBruteSharkCli\033[0m via cURL."
	fi

	# Evil-WinRM
	which gem &>/dev/null \
	&& gem install evil-winrm &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mEvil-WinRM\033[0m via Gem."

	# Chisel
	go install github.com/jpillora/chisel@latest &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mChisel\033[0m via Go."

	# GoWitness
	go install github.com/sensepost/gowitness@latest &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mGoWitness\033[0m via Go."

	# Gosecretsdump (Offline secretsdump.py converted to Golang to increase speed) 
	go install github.com/C-Sto/gosecretsdump@latest &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mGosecretsdump\033[0m via Go."

	# Kerbrute — credit to Parker Hunter for providing the "errors.go" patch shown below
	if ! [[ -d $TOOLS_DIRECTORY/kerbrute ]]
	then
		git clone https://github.com/ropnop/kerbrute $TOOLS_DIRECTORY/kerbrute &>/dev/null \
		&& sed -i '44 i \\tif strings.Contains(eString, "KDC_Error: AS Exchange Error") {' $TOOLS_DIRECTORY/kerbrute/session/errors.go \
		&& sed -i '45 i \\t\treturn true, "Unknown Error"\n\t}' $TOOLS_DIRECTORY/kerbrute/session/errors.go \
		&& cd $TOOLS_DIRECTORY/kerbrute && make clean &>/dev/null && make linux &>/dev/null \
		&& cp dist/kerbrute_linux_amd64 /usr/bin/kerbrute && cp dist/kerbrute_linux_amd64 "$HOME/go/bin/kerbrute" \
		&& echo -e "$INSTALL_SIGN Installed \033[96mKerbrute\033[0m from source (patched \033[93mAS Exchange Error\033[0m)."
	fi

	# PetitPotam
	if ! [[ -d $TOOLS_DIRECTORY/petitpotam || -d $TOOLS_DIRECTORY/PetitPotam ]]
	then
		git clone https://github.com/topotam/PetitPotam $TOOLS_DIRECTORY/PetitPotam &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mPetitPotam\033[0m via Git."
	fi

 	# LSA-Reaper
	if ! [[ -d $TOOLS_DIRECTORY/LSA-Reaper ]]
	then
		git clone https://github.com/samiam1086/LSA-Reaper $TOOLS_DIRECTORY/LSA-Reaper &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mLSA-Reaper\033[0m via Git."
	fi

	# nullinux
	if ! [[ -d $TOOLS_DIRECTORY/nullinux ]]
	then
		git clone https://github.com/m8sec/nullinux $TOOLS_DIRECTORY/nullinux &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mnullinux\033[0m via Git."
	fi
	
	# FindUncommonShares
	if ! [[ -d $TOOLS_DIRECTORY/FindUncommonShares ]]
	then
		git clone https://github.com/p0dalirius/FindUncommonShares $TOOLS_DIRECTORY/FindUncommonShares &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mFindUncommonShares\033[0m via Git."
	fi

	# statistically-likely-usernames
	if ! [[ -d $TOOLS_DIRECTORY/statistically-likely-usernames ]]
	then
		git clone https://github.com/insidetrust/statistically-likely-usernames $TOOLS_DIRECTORY/statistically-likely-usernames &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mstatistically-likely-usernames\033[0m via Git."
	fi

	# krbrelayx
	if ! [[ -d $TOOLS_DIRECTORY/krbrelayx ]]
	then
		git clone https://github.com/dirkjanm/krbrelayx $TOOLS_DIRECTORY/krbrelayx &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mkrbrelayx\033[0m via Git."
	fi

	# PowerSharpPack
	if ! [[ -d $TOOLS_DIRECTORY/PowerSharpPack ]]
	then
		git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack $TOOLS_DIRECTORY/PowerSharpPack &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mPowerSharpPack\033[0m via Git."
	fi

	# windapsearch
	if ! [[ -d $TOOLS_DIRECTORY/windapsearch ]]
	then
		git clone https://github.com/ropnop/windapsearch $TOOLS_DIRECTORY/windapsearch &>/dev/null \
		&& echo -e "$INSTALL_SIGN Installed \033[96mwindapsearch\033[0m via Git."
	fi

	# newtmux
	if ! [[ -d $TOOLS_DIRECTORY/newtmux ]] && ! which newtmux &>/dev/null
	then
		git clone https://github.com/mrdanielvelez/newtmux $TOOLS_DIRECTORY/newtmux &>/dev/null \
		&& grep -q 'alias newtmux' "$HOME/.zshrc" || echo "alias newtmux='$TOOLS_DIRECTORY/newtmux/newtmux.sh';" >> "$HOME/.zshrc" \
		&& echo -e "$INSTALL_SIGN Installed \033[96mnewtmux\033[0m via Git. Alias: \033[93mnewtmux\033[0m."
	fi

	# Responder
	if [[ -d $TOOLS_DIRECTORY/Responder || -d $TOOLS_DIRECTORY/responder ]]
	then
		rm -rf $TOOLS_DIRECTORY/Responder $TOOLS_DIRECTORY/responder 
	fi
	git clone https://github.com/lgandx/Responder $TOOLS_DIRECTORY/Responder &>/dev/null \
	&& echo -e "$INSTALL_SIGN Installed \033[96mResponder\033[0m via Git."

	# LdapRelayScan
	if [[ -d $TOOLS_DIRECTORY/LdapRelayScan || -d $TOOLS_DIRECTORY/ldaprelayscan ]]
	then
		rm -rf $TOOLS_DIRECTORY/LdapRelayScan $TOOLS_DIRECTORY/ldaprelayscan
	fi
	docker info &>/dev/null || apt install docker.io -y &>/dev/null \
	&& git clone https://github.com/zyn3rgy/LdapRelayScan $TOOLS_DIRECTORY/LdapRelayScan &>/dev/null \
	&& docker build -f $TOOLS_DIRECTORY/LdapRelayScan/docker/Dockerfile -t ldaprelayscan $TOOLS_DIRECTORY/LdapRelayScan &>/dev/null \
	&& rm -rf $TOOLS_DIRECTORY/LdapRelayScan \
	&& grep -q 'alias ldaprelayscan' "$HOME/.zshrc" || echo "alias ldaprelayscan='docker run ldaprelayscan';" >> "$HOME/.zshrc" \
	&& echo -e "$INSTALL_SIGN Installed \033[96mLdapRelayScan\033[0m via Docker. Alias: \033[93mldaprelayscan\033[0m."
}

install_requirements() {
	if find $TOOLS_DIRECTORY/ -name "requirements.txt" -exec python3 -m pip install -r {} \; &>/dev/null
	then
		echo -e "$INSTALL_SIGN Installed \033[92mPython requirements\033[0m for tools within \033[93m$TOOLS_DIRECTORY\033[0m via pip."
	else
		echo -e "$NEGATIVE_SIGN Error installing requirements for tools within \033[93m$TOOLS_DIRECTORY\033[0m via pip. Continuing..."
	fi
}

configure_responder() {
	if [[ -f $TOOLS_DIRECTORY/Responder/Responder.conf ]]
	then
		echo -e "$STAR_SIGN Modifying \033[91mResponder's\033[0m configuration file..." && sleep 1
	else
		echo -e "$NEGATIVE_SIGN \033[93m$TOOLS_DIRECTORY/Responder/Responder.conf\033[0m does not exist..."
		return 1
	fi
	if sed -i "s/Challenge = Random/Challenge = 1122334455667788/" $TOOLS_DIRECTORY/Responder/Responder.conf
	then
		echo -e "$PLUS_SIGN Defined magic challenge of \033[95m1122334455667788\033[0m."
	fi
	if sed -i "s/SMB = On/SMB = Off/" $TOOLS_DIRECTORY/Responder/Responder.conf
	then
		echo -e "$PLUS_SIGN Disabled \033[91mResponder's\033[0m SMB server."
	fi
	if sed -i "s/HTTP = On/HTTP = Off/" $TOOLS_DIRECTORY/Responder/Responder.conf
	then
		echo -e "$PLUS_SIGN Disabled \033[91mResponder's\033[0m HTTP server."
	fi	
	if sed -i "s/DontRespondTo = /DontRespondTo = $INTERNAL_IP/" $TOOLS_DIRECTORY/Responder/Responder.conf
	then
		echo -e "$PLUS_SIGN Disabled responding to attack machine (\033[93m$INTERNAL_IP\033[0m)."
	fi
}

backup_resolv() {
	if cp /etc/resolv.conf /etc/resolv_hackprep_$DATE.conf
	then
		echo -e "$PLUS_SIGN Backed up \033[93mresolv.conf\033[0m to \033[96m/etc/resolv_hackprep_$DATE.conf\033[0m."
	else
		echo -e "$NEGATIVE_SIGN Couldn't backup /etc/resolv.conf. Continuing..."
	fi
}

update_database() {
	echo -e "$STAR_SIGN Running \033[95mupdatedb\033[0m..."
	if updatedb &>/dev/null
	then
		echo -e "$PLUS_SIGN Successfully executed \033[95mupdatedb\033[0m."
	else
		clean_exit "Unable to execute \033[95mupdatedb\033[0m."
	fi
}

fix_libcrypto() {
	echo -e "$STAR_SIGN Checking for broken \033[92mLibcrypto\033[0m files..."
	
	FIXED_CFFI=`curl -s -k -L https://raw.githubusercontent.com/wbond/oscrypto/d5f3437ed24257895ae1edd9e503cfb352e635a8/oscrypto/_openssl/_libcrypto_cffi.py`
	FIXED_CTYPES=`curl -s -k -L https://raw.githubusercontent.com/wbond/oscrypto/d5f3437ed24257895ae1edd9e503cfb352e635a8/oscrypto/_openssl/_libcrypto_ctypes.py`

	# SHA256 Hash of broken _libcrypto_cffi.py: 5137e131c185f45dbe395104a6b42d12b458e4b7be039565e346fa0c7276466f
	for file in `locate 'oscrypto/_openssl/_libcrypto_cffi.py'`
	do
		if [[ `sha256sum "$file" | cut -d ' ' -f 1` == "5137e131c185f45dbe395104a6b42d12b458e4b7be039565e346fa0c7276466f" ]]
			then cat <<< $FIXED_CFFI > $file \
			&& LIBCRYPTO=FIXED
		fi
	done

	# SHA256 Hash of broken _libcrypto_ctypes.py: 5d9146415e4d521667bd6f6b54296472e344bdcbe583b24e8b992150f7f5977f
	for file in `locate 'oscrypto/_openssl/_libcrypto_ctypes.py'`
	do
		if [[ `sha256sum "$file" | cut -d ' ' -f 1` == "5d9146415e4d521667bd6f6b54296472e344bdcbe583b24e8b992150f7f5977f" ]]
			then cat <<< $FIXED_CTYPES > $file \
			&& LIBCRYPTO=FIXED
		fi
	done

	if [[ $LIBCRYPTO == "FIXED" ]]
	then
		echo -e "$PLUS_SIGN Patched \033[92mLibcrypto\033[0m regular expressions." && unset LIBCRYPTO
	else
		echo -e "$PLUS_SIGN Zero broken \033[92mLibcrypto\033[0m files were detected."
	fi
}

fix_certipy() {
	echo -e "$STAR_SIGN Checking if \033[96menum.py\033[0m needs to be patched..."
	for enumfile in `locate enum.py | grep "python.*enum.py"`
	do
	if ! grep -q 'def _decompose(' $enumfile
	then
		echo -e "def _decompose(flag, value):\n    # Extract all members from the value.\n    # _decompose is only called if the value is not named\n    not_covered = value\n    negative = value < 0\n    members = []\n    for member in flag:\n        member_value = member.value\n        if member_value and member_value & value == member_value:\n            members.append(member)\n            not_covered &= ~member_value\n    if not negative:\n        tmp = not_covered\n        while tmp:\n            flag_value = 2 ** _high_bit(tmp)\n            if flag_value in flag._value2member_map_:\n                members.append(flag._value2member_map_[flag_value])\n                not_covered &= ~flag_value\n            tmp &= ~flag_value\n    if not members and value in flag._value2member_map_:\n        members.append(flag._value2member_map_[value])\n    members.sort(key=lambda m: m._value_, reverse=True)\n    if len(members) > 1 and members[0].value == value:\n        # we have the breakdown, don't need the value member itself\n        members.pop(0)\n    return members, not_covered" \
		>> $enumfile \
		&& CERTIPY=FIXED
	fi
	done
	if [[ $CERTIPY == "FIXED" ]]
	then
		echo -e "$PLUS_SIGN Patched \033[92mCertipy\033[0m AttributeError (>= Python3.11)."
	else
		echo -e "$PLUS_SIGN Didn't need to patch \033[96menum.py\033[0m for \033[95mCertipy\033[0m."
	fi
}

zshrc_functions() {
	! grep -q -i "rsmbhttp()" "$HOME/.zshrc" \
	&& cat <<< 'rsmbhttp() {
	
	RESPONDER_CONF=
	if [[ -f /opt/tools/Responder/Responder.conf ]]
	then
		RESPONDER_CONF="/opt/tools/Responder/Responder.conf"
	else
		RESPONDER_CONF=`locate Responder.conf` || updatedb && RESPONDER_CONF=`locate Responder.conf`
		RESPONDER_CONF=`echo $RESPONDER_CONF | head -n 1`
	fi
	
	display_conf() {
		echo -e "\033[93m[*]\033[0m $RESPONDER_CONF:" \
		&& grep "SMB = .*" "$RESPONDER_CONF" \
		&& grep "HTTP = .*" "$RESPONDER_CONF"	
	}
	
	if [[ $# -eq 0 ]]
	then
		display_conf
	elif [[ $1 == "off" ]]
	then
		sed -i "s/SMB = On/SMB = Off/" "$RESPONDER_CONF" \
		&& sed -i "s/HTTP = On/HTTP = Off/" "$RESPONDER_CONF" \
		&& display_conf
	elif [[ $1 == "on" ]]
	then
		sed -i "s/SMB = Off/SMB = On/" "$RESPONDER_CONF" \
		&& sed -i "s/HTTP = Off/HTTP = On/" "$RESPONDER_CONF" \
		&& display_conf
	elif [[ $1 == "http" ]]
	then
		if grep -q "HTTP = Off" "$RESPONDER_CONF"
		then
			sed -i "s/HTTP = Off/HTTP = On/" "$RESPONDER_CONF" \
			&& display_conf
		else
			sed -i "s/HTTP = On/HTTP = Off/" "$RESPONDER_CONF" \
			&& display_conf
		fi
	elif [[ $1 == "smb" ]]
	then
		if grep -q "SMB = Off" "$RESPONDER_CONF"
		then
			sed -i "s/SMB = Off/SMB = On/" "$RESPONDER_CONF" \
			&& display_conf
		else
			sed -i "s/SMB = On/SMB = Off/" "$RESPONDER_CONF" \
			&& display_conf
		fi
	else
		echo -e "Invalid input to \033[93m$0\033[0m."
		return 1
	fi' >> "$HOME/.zshrc" \
	&& echo '}' >> "$HOME/.zshrc" \
	&& echo -e "$PLUS_SIGN Added \033[93mrsmbhttp\033[0m helper function to \033[96m$HOME/.zshrc\033[0m."

	! grep -q -i "zippy()" "$HOME/.zshrc" \
	&& cat <<< 'zippy() {
	DATE=`date "+%F_%I:%M-%p"`

	success() {
		echo -e "\033[1m\033[92m[+]\033[0m Compressed evidence to \033[93mevidence_$DATE.zip\033[0m."
	}

	if [[ $# -eq 0 ]]
	then
		if [[ -d "$HOME/tmux-logging-output" ]]
		then
			zip -r evidence_$DATE.zip . "$HOME/tmux-logging-output" >/dev/null && success
		else
			zip -r evidence_$DATE.zip . >/dev/null && success
		fi
	else
		if [[ -d "$HOME/tmux-logging-output" ]]
		then
			zip -r evidence_$DATE.zip $1 "$HOME/tmux-logging-output" >/dev/null && success
		else
			zip -r evidence_$DATE.zip $1 >/dev/null && success
		fi
	fi' >> "$HOME/.zshrc" \
	&& echo '}' >> "$HOME/.zshrc" \
	&& echo -e "$PLUS_SIGN Added \033[93mzippy\033[0m helper function to \033[96m$HOME/.zshrc\033[0m."
}

conclusion() {
	echo -e "$STAR_SIGN Run \033[96msource $HOME/.zshrc\033[0m to use new \033[93maliases\033[0m/\033[93mfunctions\033[0m."

	if [[ $OUTPUT_NESSUS == true ]] || [[ $OUTPUT_COBALT_STRIKE == true ]]
	then
 		echo && sleep 1
	fi
	if [[ $OUTPUT_NESSUS == true ]]
	then
		echo -e "\033[1m\033[93m[*]\033[0m \033[1m\033[3mNessus Credentials\033[0m \033[1m\033[93m—\033[0m \033[1m/opt/nessus/creds_hackprep_$DATE.txt\033[0m"
	fi
	if [[ $OUTPUT_COBALT_STRIKE == true ]]
	then
		echo -e "\033[1m\033[93m[*]\033[0m \033[1m\033[3mTeam Server Info\033[0m \033[1m\033[93m—\033[0m \033[1m$TOOLS_DIRECTORY/cobaltstrike/server_info_hackprep_$DATE.txt\033[0m"
	fi
	echo -e "\n\033[1m\033[3m\033[93mHACKPREP\033[0m finished execution at \033[91m`date '+%I:%M %p'`\033[0m on \033[93m`date '+%B %d, %Y'`\033[0m.\n"
	exit 0
}

clean_exit() {
	ERROR_MESSAGE=$1
	echo -e "$NEGATIVE_SIGN $ERROR_MESSAGE"
	echo -e "$NEGATIVE_SIGN Exiting..."
	exit 1
}

main
