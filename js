#!/bin/bash
_CONF_FILE="/etc/jailspaces/js.conf"


check_config() {
	[ -f "$_PHP_FPM_CONF_TEMPLATE" ] || die "$_PHP_FPM_CONF_TEMPLATE missing"
	[ -f "$_NGINX_CONF_TEMPLATE" ]   || die "$_NGINX_CONF_TEMPLATE missing"
}

get_user_list() {
	eval "$_USER_LIST_CMD" | while read user; do echo $user; done;
}

user_create() {
	local cmd="${_USER_CREATE_CMD//@USERNAME@/$1}"
	eval "$cmd"
	return $?
}

user_exists() {
	get_user_list | grep -x "$1" &> /dev/null
	return $?
}

group_exists() {
	getent group | grep -P "^$1:" &> /dev/null
	return $?
}

user_is_valid() {
	echo "$1" | grep -ivP "[^a-z0-9]" &> /dev/null && [ "`echo -n \"$1\" | wc -c`" -le 10 ] && [ "`echo -n \"$1\" | wc -c`" -ge 4 ] && return 0
	return 1
}

get_user_chroot() {
	echo "${_PHP_FPM_CHROOT//@USERNAME@/$1}"
}

get_user_binds() {
	local username="$1"
	echo $_PHP_FPM_CHROOT_BIND

	if [ -n "$username" ]; then
		local bind_local="${_PHP_FPM_CHROOT_BIND_LOCAL//@USERNAME@/$username}"
		[ -f "$bind_local" ] && cat "$bind_local"
	fi
}

die() {
	echo "ERROR: $1" && stop 1
}

is_valid_fqdn() {
	echo "$1" | grep -P '^(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.){1,126}(?!\d+)[a-zA-Z\d]{1,63}$' &> /dev/null
	return $?
}

get_FQDNs_for_user() {
	local nginx_config="${_NGINX_CONF//@USERNAME@/$1}"
	[ ! -r "$nginx_config" ] && nginx_config="$nginx_config.disabled"
	[   -r "$nginx_config" ] || echo ""
	for domain in `grep -P '^\s*server_name\s+.+;$' "$nginx_config" | rev | cut -c 2- | rev`; do
		[ "$domain" = "server_name" ] && continue;
		is_valid_fqdn "$domain" && echo "$domain"
	done | sort -u;
}

file_has() {
	case "$1" in
		perm)       [ -e "$2" -a "`printf '%04d' \`stat -c '%a' $2\``" = "$3" ] && return 0 || return 1;;
		owner)      [ -e "$2" -a "`stat -c '%U:%G' $2`" = "$3" ]                && return 0 || return 1;;
		type)       [ "$3" = "f" -a -f "$2" ] && return 0; [ "$3" = "d" -a -d "$2" ] && return 0; return 1;;
	esac
}

color() {
	local n="\033[0m"
	local g="\033[32m"
	local y="\033[33m"
	local r="\033[31m"
	eval "echo -en \"\$$1\""
	echo -e "$2$n"
}


status() {
	local msg="";
	case "$1" in
		g) msg="$2";;
		y) msg="$3";;
		r) msg="$4";;
	esac
	[ -n "$msg" ] && echo -n  "[`color $1 \"$msg\"`]"
}

check_file_permissions() {
	local uUSERNAME="$1"
	local uCHROOT="`get_user_chroot $uUSERNAME`"
	local violation=false
	local cfile=""
	local suffix=""
	local f=1
	for permDef in $_PHP_FPM_CHROOT_DIRS; do
		f=1; for field in file perm owner type; do eval "f_$field=\"`echo $permDef | cut -d, -f$f`\""; f=$(($f+1)); done;
		f_file="${f_file//@USERNAME@/$uUSERNAME}"
		cfile=$uCHROOT$f_file
		suffix="$f_perm,${f_owner//@USERNAME@/$uUSERNAME},$f_type"
		echo -n "$f_file,"
		[ ! -e "$cfile" ] && violation=true && echo "false,true,true,true,$suffix" && continue;
		! file_has perm "$cfile" "$f_perm" && violation=true &&  echo -n "true,false," || echo -n "true,true,"
		! file_has owner "$cfile" "${f_owner//@USERNAME@/$uUSERNAME}" && violation=true && echo -n "false," || echo -n "true,"
		! file_has type "$cfile" "$f_type" && violation=true && echo -n "false," || echo -n "true,"
		echo "$suffix"
	done;
	$violation && return 1 || return 0
}

fix_or_check_file_permissions() {
	local uUSERNAME="$1"
	local uCHROOT="`get_user_chroot $uUSERNAME`"
	local fix=false
	local f=1
	local returnValue=0
	[ -n "$2" ] && fix=true

	check_file_permissions "$uUSERNAME" | while read check; do
		f=1; for field in file exists perm owner type iperm iowner itype; do eval "f_$field=\"`echo $check | cut -d, -f$f`\""; f=$(($f+1)); done;
		local fullPath="$uCHROOT$f_file"

		if ! $f_exists; then
			local msg="$f_file does not exist"
			if $fix; then
				local status="r"
				[ "$f_itype" = "f" ] && touch "$fullPath" &> /dev/null && [ -f "$fullPath" ] && status="g"
				[ "$f_itype" = "d" ] && status="r" && mkdir -p "$fullPath" &> /dev/null && [ -d "$fullPath" ] && status="g"
				[ "$status" = "g"  ] && status="r" && chown "$f_iowner" "$fullPath" && chmod "$f_iperm" "$fullPath" && status="g"

				printf "$pf2" "$msg" "`status $status 'CREATED' '' 'FAILED'`"
				[ "$status" = "g" ] || returnValue=1
			else
				printf "$pf1" "" "$msg"
			fi
		fi

		if ! $f_perm; then
			local msg="$f_file has wrong permissions (must $f_iperm)"
			if $fix; then
				local status='r'
				chmod "$f_iperm" "$fullPath" && status="g"
				printf "$pf2" "$msg" "`status $status 'FIXED' '' 'FAILED'`"
				[ "$status" = "g" ] || returnValue=1
			else
				printf "$pf1" "" "$msg"
			fi
		fi

		if ! $f_owner; then
			local msg="$f_file has wrong ownership (must $f_iowner)"
			if $fix; then
				local status="r"
				chown "$f_iowner" "$fullPath" && status="g"
				printf "$pf2" "$msg" "`status $status 'FIXED' '' 'FAILED'`"
				[ "$status" = "g" ] || returnValue=1
			else
				printf "$pf1" "" "$msg"
			fi
		fi

		if ! $f_type; then
			local msg=""
			[ -f "$fullPath" ] && msg="$f_file is not a directory"
			[ -d "$fullPath" ] && msg="$f_file is not a regular file"

			if $fix; then
				printf "$pf2" "$msg --> please fix manually" "`status y '' 'SKIPPED'`"
			else
				printf "$pf1" "" "$msg"
			fi
		fi
	done;
	return $returnValue
}

# template destination owner mode var1 value1 var2 value2
install_template() {
	local template="$1"
	local destination="$2"
	local owner="$3"
	local mode="$4"
	local override="$5"
	shift 5

	[ ! -f "$template" ]                                && printf "$pf2" "Template \"$template\" does not exist" "`status r '' '' 'ERROR'`" && return 1
	! $override && [ -f "$destination" -o -f "$destination.disabled" ] && printf "$pf2" "Template target \"$destination\" already in use" "`status r '' '' 'ERROR'`" && return 2

	local sedCmd="sed"
	while [ $# -gt 0 ]; do
		sedCmd="$sedCmd -e \"s/@$1@/$2/g\""
		shift 2
	done
	sedCmd="$sedCmd \"$template\""

	local returnValue=0
	local status="r"

	eval "$sedCmd" > "$destination" && status="g"
	printf "$pf2" "Installing template to \"$destination\"" "`status $status 'DONE' '' 'FAILED'`"
	[ "$status" = "g" ] || return 1

	[ "$status" = "g" ] && status="r" && chown "$owner" "$destination" && status="g"
	printf "$pf2" "Setting ownership to $owner" "`status $status 'DONE' '' 'FAILED'`"
	[ "$status" = "g" ] || returnValue=1

	[ "$status" = "g" ] && status="r" && chmod "$mode" "$destination" && status="g"
	printf "$pf2" "Setting mode to $mode" "`status $status 'DONE' '' 'FAILED'`"
	[ "$status" = "g" ] || returnValue=1

	return $returnValue
}

is_bound() {
        mount | grep " on $1 type " > /dev/null && return 0 || return 1
}

get_base_path() {
        local path="$1"
        local lastPath=""
        while [ "$path" != "/" ]; do lastPath=$path; path=`dirname $path`; done;
        echo "$lastPath"
}

is_any_unbound() {
	local username="$1"
	local chroot="`get_user_chroot \"$username\"`"
	for bind in `get_user_binds "$username"`; do
		is_bound "$chroot$bind" || return 0
	done
	return 1
}

is_any_bound() {
	local username="$1"
	local chroot="`get_user_chroot \"$username\"`"
	for bind in `get_user_binds "$username"`; do
		is_bound "$chroot$bind" && return 0
	done
	return 1
}

reload_services() {
	local status="r"
	local error=false
	local sudo=""
	[ -n "$2" -a "$2" = "sudo" ] && sudo="sudo "

	if [ -n "$_OPT_RELOAD" ] && $_OPT_RELOAD; then

		if [ -z "$1" -o "$1" = "nginx" -o "$1" = "ALL" ]; then
			eval "$sudo$_RELOAD_NGINX_CMD" && status="g"
			printf "$pf2" "Reloading NGINX" "`status $status 'DONE' '' 'FAILED'`"
			[ "$status" = "g" ] || error=true
		fi

		if [ -z "$1" -o "$1" = "php-fpm" -o "$1" = "ALL" ]; then
			status="r"
			eval "$sudo$_RELOAD_PHP_FPM_CMD" && status="g"
			printf "$pf2" "Reloading PHP-FPM" "`status $status 'DONE' '' 'FAILED'`"
			[ "$status" = "g" ] || error=true
		fi
	fi
	if $error; then
		return 1
	else
		return 0
	fi
}

reset_nscd() {
	nscd --invalidate passwd &> /dev/null
	nscd --invalidate group &> /dev/null
}

stop() {
	rm -f "$_LOCKFILE"
	exit $1
}

le_cmd() {
	if $_LOW_PRIV_TLS_REFRESH; then
		eval "$1"
	else
		su -c "$1" "$_LETS_ENCRYPT_USER"
	fi

	return $?
}

cert_get_domains() {

	local commonName="`openssl x509 -noout -text -in \"$1\" | grep 'Subject: CN=' | cut -d= -f2`"
	[ -n "$commonName" ] && echo $commonName

	# Subject Alternative Names
	[ -z "`openssl x509 -noout -text -in \"$1\" | grep 'X509v3 Subject Alternative Name:'`" ] && return 0

	for d in \
		`openssl x509 -noout -text -in "$1" | \
		grep -A1 'X509v3 Subject Alternative Name:' \
		| tail -n1 | tr -d '[:space:]' | \
		sed -e 's/DNS://g' -e 's/,/ /g'`; do
		[ "$d" != "$commonName" ] && echo $d; done;
}

cert_get_expiry() {
	 local expiry="`openssl x509 -noout -text -in \"$1\" | grep 'Not After' | cut -d: -f2-4`";
	 date -d "$expiry" +%s
}


create_systemd_units() {
	local chroot=""
	local eChroot=""
	local bind=""
	local eBind=""
	local mountpoint=""

	[ ! -f "${_SYSTEMD_UNIT_DIR}/php-chroots.target" ] && \
	cat <<- END > "${_SYSTEMD_UNIT_DIR}/php-chroots.target" && \
	echo -e "Created ${_SYSTEMD_UNIT_DIR}/php-chroots.target"
	# PHP-FPM-CHROOT-BIND
	[Install]
	WantedBy=${_PHP_FPM_SERVICE}.service

	[Unit]
	Description=Bind all binds for all PHP-FPM chroots
	Before=${_PHP_FPM_SERVICE}.service
	END

	get_user_list | while read user; do
		chroot="`get_user_chroot ${user}`"
		eChroot="`systemd-escape -p \"${chroot}\"`"

		[ ! -f "${_SYSTEMD_UNIT_DIR}/php-chroot-${eChroot}.target" ] && \
		cat <<- END > "${_SYSTEMD_UNIT_DIR}/php-chroot-${eChroot}.target" && \
		echo -e "Created ${_SYSTEMD_UNIT_DIR}/php-chroot-${eChroot}.target"
		# PHP-FPM-CHROOT-BIND
		[Unit]
		Description=Bind all binds for PHP-FPM chroot ${chroot}
		END

		for bind in `get_user_binds "$user"`; do
			eBind="`systemd-escape -p \"${bind}\"`"
			mountpoint="`systemd-escape -p \"${chroot}${bind}\"`"

			[ ! -f "${_SYSTEMD_UNIT_DIR}/${mountpoint}.mount" ] && \
			cat <<- END > "${_SYSTEMD_UNIT_DIR}/${mountpoint}.mount" && \
			echo -e "Created ${_SYSTEMD_UNIT_DIR}/${mountpoint}.mount"
			# PHP-FPM-CHROOT-BIND
			[Unit]
			Description=Bind ${bind} for PHP-FPM chroot ${chroot}
			Requires=php-chroot-create-mountpoint-file-${eBind}@${eChroot}.service
			Requires=php-chroot-create-mountpoint-dir-${eBind}@${eChroot}.service
			BindsTo=php-chroot-${eChroot}.target

			[Mount]
			What=${bind}
			Where=${chroot}${bind}
			Type=none
			Options=bind,ro
			END

			[ ! -f "${_SYSTEMD_UNIT_DIR}/php-chroot-create-mountpoint-file-${eBind}@.service" ] && \
			cat <<- END > "${_SYSTEMD_UNIT_DIR}/php-chroot-create-mountpoint-file-${eBind}@.service" && \
			echo -e "Created ${_SYSTEMD_UNIT_DIR}/php-chroot-create-mountpoint-file-${eBind}@.service"
			# PHP-FPM-CHROOT-BIND
			[Unit]
			Description=Create mountpoint (file) for ${bind} in PHP-FPM Chroot
			Before=%i-${eBind}.mount
			ConditionPathExists=!/%I${bind}
			ConditionPathExists=${bind}
			ConditionPathIsDirectory=!${bind}

			[Service]
			Type=oneshot
			ExecStart=/bin/mkdir -p "/%I${bind}" ; /bin/rm -r "/%I${bind}" ; /usr/bin/touch "/%I${bind}"
			END

			[ ! -f "${_SYSTEMD_UNIT_DIR}/php-chroot-create-mountpoint-dir-${eBind}@.service" ] && \
			cat <<- END > "${_SYSTEMD_UNIT_DIR}/php-chroot-create-mountpoint-dir-${eBind}@.service" && \
			echo -e "Created ${_SYSTEMD_UNIT_DIR}/php-chroot-create-mountpoint-dir-${eBind}@.service"
			# PHP-FPM-CHROOT-BIND
			[Unit]
			Description=Create mountpoint (dir) for ${bind} in PHP-FPM Chroot
			Before=%i-${eBind}.mount
			ConditionPathExists=!/%I${bind}
			ConditionPathExists=${bind}
			ConditionPathIsDirectory=${bind}

			[Service]
			Type=oneshot
			ExecStart=/bin/mkdir -p "/%I${bind}"
			END

			echo "Requires=${mountpoint}.mount" >> "${_SYSTEMD_UNIT_DIR}/php-chroot-${eChroot}.target"
		done
		echo "BindsTo=php-chroots.target" >> "${_SYSTEMD_UNIT_DIR}/php-chroot-${eChroot}.target"
		echo "Wants=php-chroot-${eChroot}.target" >> "${_SYSTEMD_UNIT_DIR}/php-chroots.target"
	done
	return 0
}

list_systemd_units() {
	local unit=""
	ls -1b "${_SYSTEMD_UNIT_DIR}/"* 2> /dev/null | while read unit; do
		[ -f "$unit" ] && head -n1 "${unit}" | \
		grep -x "# PHP-FPM-CHROOT-BIND" > /dev/null && echo "${unit}"
	done
	return 0
}

delete_systemd_units() {
	ls -1b "${_SYSTEMD_UNIT_DIR}/"* 2> /dev/null | while read unit; do
		[ -f "$unit" ] && head -n1 "${unit}" | \
		grep -x "# PHP-FPM-CHROOT-BIND" > /dev/null && \
		echo -n "${unit}" && if $_OPT_YES; then
			rm "${unit}" && echo " (deleted)"
		else
			echo " (not deleted, use -Y)"
		fi
	done
	return 0
}



pf0="%-16s: %-50s %11s\n"
pf1="%-18s%s\n"
pf2="%-69s%11s\n"


! source "$_CONF_FILE" &> /dev/null && printf "$pf2" "$_CONF_FILE could not be read." "`status r '' '' 'ERROR'`" && stop 1

# Skip single instance check for internal calls
_OPT_INTERNAL_CALL=false
if [ "$1" = "_INTERNAL_" -a "$EUID" -eq 0 ]; then
	_OPT_INTERNAL_CALL=true
	shift
fi

case "$1" in
	list)
		_OPT_ACTION="list"
		;;
	status|fixperm)
		_OPT_ACTION="$1"
		_OPT_USERNAME="$2"
		;;
	enable|disable)
		_OPT_ACTION="$1"
		_OPT_USERNAME="$2"
		_OPT_RELOAD=true
		if [ -n "$3" ]; then
			[ "$3" != "-n" ] && _OPT_ACTION="help"
			_OPT_RELOAD=false
		fi
		;;
	binds)
		_OPT_ACTION="binds"
		_OPT_USERNAME="$3"
		case "$2" in
			bind  ) _OPT_ACTION_BIND="bind";;
			unbind) _OPT_ACTION_BIND="unbind";;
			clean )
				_OPT_ACTION_BIND="clean"
				_OPT_YES=false
				[ -n "$4" -a "$4" = "-Y" ] && _OPT_YES=true
				;;
			status) _OPT_ACTION_BIND="status";;
			list  ) _OPT_ACTION_BIND="list";;
			systemd)
				_OPT_ACTION_BIND="systemd"
				case "$3" in
					list)  _OPT_ACTION_BIND_SYSTEMD="list";;
					create) _OPT_ACTION_BIND_SYSTEMD="create";;
					clean)
						_OPT_ACTION_BIND_SYSTEMD="clean"
						_OPT_YES=false
						[ -n "$4" -a "$4" = "-Y" ] && _OPT_YES=true
						;;
					update) _OPT_ACTION_BIND_SYSTEMD="update";;
					*)_OPT_ACTION="help";;
				esac;;
			*)_OPT_ACTION="help";;
		esac
		;;
	create)
		_OPT_ACTION="create"
		_OPT_USERNAME="$2"
		_OPT_DOMAINS=""
		shift 2
		while [ "$#" -gt 0 ]; do
			! is_valid_fqdn "$1" && printf "$pf2" "$1 is not a valid FQDN" "`status r '' '' 'ERROR'`" && stop 1
			_OPT_DOMAINS="$_OPT_DOMAINS $1"
			shift
		done
		;;
	regenerate-config)
		_OPT_ACTION="regenerate-config"
		_OPT_USERNAME="$2"
		;;
	delete)
		_OPT_ACTION="delete"
		_OPT_USERNAME="$2"
		_OPT_YES=false
		[ -n "$3" -a "$3" = "-Y" ] && _OPT_YES=true
		;;
	tls)
		_OPT_ACTION="tls"
		case "$2" in
			init)    _OPT_ACTION_TLS="init";;
			refresh|forcerefresh)
				_OPT_ACTION_TLS="refresh"
				_OPT_ACTION_TLS_FORCEREFRESH=false
				[ "$2" = "forcerefresh" ] && _OPT_ACTION_TLS_FORCEREFRESH=true
				_OPT_USERNAME="$3"
				_OPT_RELOAD=true
				if [ -n "$4" ]; then
					[ "$4" != "-n" ] && _OPT_ACTION="help"
					_OPT_RELOAD=false
				fi
				;;
			*) _OPT_ACTION="help";;
		esac
		;;
	*)
		_OPT_ACTION="help"
		;;
esac

# Check if this is the only instance
if ! $_OPT_INTERNAL_CALL; then
	_LOCKFILE="/tmp/wss.lock"
	if [ -e "$_LOCKFILE" ] && kill -0 `cat $_LOCKFILE` &> /dev/null; then
		printf "$pf2" "Another instance of this script seems to be runnig" "`status r '' '' 'ERROR'`"
	    exit 1
	fi
	trap "rm -f $_LOCKFILE;" INT TERM EXIT
	echo $$ > $_LOCKFILE
fi


# Check if we run as letsencrypt user for certificate refresh
_LOW_PRIV_TLS_REFRESH=false
if [ "$USER" = "$_LETS_ENCRYPT_USER" -a "$_OPT_ACTION_TLS" = "refresh" ]; then
	_LOW_PRIV_TLS_REFRESH=true
fi


# Check if this is run as root
if ! $_LOW_PRIV_TLS_REFRESH && [ "$EUID" -ne 0 ]; then
	printf "$pf2" "Not run as root" "`status r '' '' 'ERROR'`"
	stop 1
fi


if ! echo "$_OPT_ACTION" | grep -P "list|help" &> /dev/null && [ "$_OPT_ACTION_TLS" != "init" ] && [ "$_OPT_ACTION_BIND" != "systemd" ]; then
	if ! user_is_valid "$_OPT_USERNAME" ]; then
			printf "$pf2" "Username \"$_OPT_USERNAME\" is not valid" "`status r '' '' 'ERROR'`"
			stop 1
	fi
fi

if ! echo "$_OPT_ACTION" | grep -P "list|help|create" &> /dev/null && [ "$_OPT_ACTION_TLS" != "init" ] && [ "$_OPT_ACTION_BIND" != "systemd" ]; then
	if ! user_exists "$_OPT_USERNAME"; then
		printf "$pf2" "Username \"$_OPT_USERNAME\" does not exist" "`status r '' '' 'ERROR'`"
		stop 1
	fi
fi

uUSERNAME="$_OPT_USERNAME"
uCERT="$_LETS_ENCRYPT_CRT_DIR/$uUSERNAME.crt"
uCHROOT="`get_user_chroot \"$uUSERNAME\"`"
uPOOL="${_PHP_FPM_CONF//@USERNAME@/$uUSERNAME}"
uNGINX="${_NGINX_CONF//@USERNAME@/$uUSERNAME}"

id "$uUSERNAME" &> /dev/null && status_user_exists="g" || status_user_exists="r"
[ -r "$uNGINX"  ] && status_nginx_exists="g"  || status_nginx_exists="r"  && [ -r "$uNGINX.disabled" ] && status_nginx_exists="y"
[ "$status_nginx_exists" != "r" ] && uFQDNS="`get_FQDNs_for_user \"$uUSERNAME\"`"

status_crt_exists="g"
status_crt_expiry="g"
status_crt_fqdns="g"
if $_LETS_ENCRYPT_ENABLE; then
	[ -e "$uCERT" ] && status_crt_exists="g" || status_crt_exists="r"
	if [ "$status_crt_exists" = "g" ]; then

		uCERTFQDNS="`cert_get_domains \"$uCERT\"`"

		timeToExpiry=$((`cert_get_expiry "$uCERT"`-`date +%s`))
		[ "$timeToExpiry" -le "$_LETS_ENCRYPT_EXPIRY" ] && status_crt_expiry="y"
		[ "$timeToExpiry" -le 0 ] && status_crt_expiry="r"

		if [ -n "$uFQDNS" ]; then
			for d in $uFQDNS; do
				dinc=false
				for c in $uCERTFQDNS; do
					[ "$d" = "$c" ] && dinc=true && break
				done
				! $dinc && status_crt_fqdns="r" && break
			done
		fi

	fi
fi

if ! $_LOW_PRIV_TLS_REFRESH; then
	[ -d "$uCHROOT" ] && status_chroot_exists="g" || status_chroot_exists="r"
	[ -r "$uPOOL"   ] && status_pool_exists="g"   || status_pool_exists="r"   && [ -r "$uPOOL.disabled"  ] && status_pool_exists="y"
	group_exists "$uUSERNAME" && status_usergroup_exists="g" || status_usergroup_exists="r"
	check_file_permissions "$uUSERNAME" &> /dev/null && status_fileperms="g" || status_fileperms="r"
	is_any_unbound "$uUSERNAME" && status_binds="r" || status_binds="g"

	check_config
fi


case "$_OPT_ACTION" in
	list)
		get_user_list
		;;

	status)
		printf "$pf0" "USERNAME"       "$uUSERNAME" "`status $status_user_exists      'OK' ''         'INVALID'`"
		[ "$status_usergroup_exists" = "g" ] && statusMsg="$uUSERNAME" || statusMsg="No group \"$uUSERNAME\""
		printf "$pf0" "USERGROUP"      "$statusMsg" "`status $status_usergroup_exists 'OK' ''         'MISSING'`"
		printf "$pf0" "PHP-FPM-CHROOT" "$uCHROOT"   "`status $status_chroot_exists    'OK' ''         'MISSING'`"
		printf "$pf0" "PHP-FPM-POOL"   "$uPOOL"     "`status $status_pool_exists      'ENABLED' 'DISABLED' 'MISSING'`"
		printf "$pf0" "NGINX CONFIG"   "$uNGINX"    "`status $status_nginx_exists     'ENABLED' 'DISABLED' 'MISSING'`"

		if [ "$status_nginx_exists" != "r" ]; then
			printf "$pf0" "FQDNs" "`get_FQDNs_for_user \"$uUSERNAME\" | wc -l`"
			get_FQDNs_for_user "$uUSERNAME" | while read fqdn; do
				printf "$pf1" "" "$fqdn"
			done;
		else
			printf "$pf0" "FQDNs" "Unknown (NGINX config missing)" "`status y '' 'UNKNOWN'`"
		fi

		if $_LETS_ENCRYPT_ENABLE; then

			if [ "$status_crt_exists" != "g" ]; then
				printf "$pf0" "TLS CERTIFICATE" "Missing" "`status r '' '' 'MISSING'`"
			else

				case "$status_crt_expiry" in
					g) statusMsg="valid";;
					y) statusMsg="expiring";;
					r) statusMsg="expired";;
				esac
				status="$status_crt_expiry"
				[ "$status_crt_fqdns" = "r" ] && statusMsg="$statusMsg, domains missing" && status="r"

				printf "$pf0" "TLS CERTIFICATE" "Exists, $statusMsg" "`status $status 'OK' 'EXPIRING' 'ERROR'`"


				if [ "$status_crt_fqdns" = "r" ]; then
					allFqdnsInCert=true
					for fqdn in $uFQDNS; do
						fqdnInCert=false
						for certfqdn in $uCERTFQDNS; do
							[ "$fqdn" = "$certfqdn" ] && fqdnInCert=true && break
						done
						! $fqdnInCert && printf "$pf1" "" "$fqdn not in certificate" && allFqdnsInCert=false
					done

				else
					[ "$status_nginx_exists" = "r" ] && printf "$pf0" "TLS CERTIFICATE" "Unknown (NGINX config missing)" "`status y '' 'UNKNOWN'`"
				fi
			fi
		fi

		if [ "$status_chroot_exists" != "r" ]; then
			printf "$pf0" "FILE PERMISSIONS" "`[ "$status_fileperms" = "g" ] && echo -n \"All correct\" || echo -n \"Incorrect\"`" "`status $status_fileperms 'OK' '' 'INCORRECT'`"
			fix_or_check_file_permissions "$uUSERNAME"
		else
			printf "$pf0" "FILE PERMISSIONS" "Unknown (PHP-FPM-CHROOT missing)" "`status y '' 'UNKNOWN'`"
		fi

		if [ "$status_chroot_exists" != "r" ] ; then
			printf "$pf0" "CHROOT BINDS" "`[ "$status_binds" = "g" ] && echo -n  \"All bound\" || echo -n \"Binds missing\"`" "`status $status_binds 'OK' '' 'MISSING'`"
			if [ "$status_binds" != "g" ]; then
				for bind in `get_user_binds "$uUSERNAME"`; do
					! is_bound "$uCHROOT$bind" && printf "$pf1" "" "$bind missing"
				done
			fi
		else
			printf "$pf0" "CHROOT BINDS" "Unknown (PHP-FPM-CHROOT missing)" "`status y '' 'UNKNOWN'`"
		fi

		# Return value
		checkList="status_user_exists status_chroot_exists status_pool_exists status_nginx_exists status_usergroup_exists status_fileperms status_binds status_crt_exists status_crt_expiry status_crt_fqdns"
		for check in $checkList; do [ "${!check}" = "r" ] && stop 1; done
		stop 0
		;;

	fixperm)
		if [ "$status_chroot_exists" == "r" ]; then
			printf "$pf2" "Chroot does not exist. Please create manually." "`status r '' '' 'ERROR'`"
			stop 1
		else
			fix_or_check_file_permissions "$uUSERNAME" fix
			stop $?
		fi
		;;

	binds)
		returnValue=0


		if [ "$_OPT_ACTION_BIND" = "systemd" ]; then
			! $_SYSTEMD_ENABLE && stop 0
			# List systemd unit files
			[ "$_OPT_ACTION_BIND_SYSTEMD" = "list" ] && list_systemd_units && stop 0

			# Set up systemd unit files
			[ "$_OPT_ACTION_BIND_SYSTEMD" = "create" ] && create_systemd_units && stop 0

			# Clean up systemd unit files
			[ "$_OPT_ACTION_BIND_SYSTEMD" = "clean" ] && delete_systemd_units && stop 0

			# Update systemd unit files
			[ "$_OPT_ACTION_BIND_SYSTEMD" = "update" ] && $0 _INTERNAL_ binds systemd clean -Y && $0 _INTERNAL_ binds systemd create && systemctl daemon-reload && stop 0

			stop 1
		fi



		if [ "$status_chroot_exists" != "g" ]; then
			printf "$pf2" "Chroot \"$uCHROOT\" does not exist." "`status r '' '' 'ERROR'`"
			stop 1
		fi
        for bind in `get_user_binds "$uUSERNAME"`; do

        		if [ "$_OPT_ACTION_BIND" = "list" ]; then
        			echo "$bind"
        			continue
        		fi

        		if [ "$_OPT_ACTION_BIND" = "status" ]; then
					status_bind="r" && is_bound "$uCHROOT$bind" && status_bind="g"
					printf "$pf2" "$bind" "`status $status_bind 'BOUND' '' 'UNBOUND'`"
					[ "$status_bind" = "r" ] && returnValue=1
					continue
        		fi

                if [ "$_OPT_ACTION_BIND" = "bind" ] && ! is_bound "$uCHROOT$bind"; then
                		# Create mointpoints
                		if [ ! -e "$uCHROOT$bind" ]; then
                			if [ -d "$bind" ]; then
                				status="r"
                				mkdir -p "$uCHROOT$bind" && status="g" || returnValue=1
                				printf "$pf2" "Creating mountpoint $uCHROOT$bind (dir)" "`status $status 'DONE' '' 'FAILED'`"
                			else
                				dir="$uCHROOT`dirname $bind`"
                				status="r"
                				mkdir -p "$dir" && status="g" || returnValue=1
                				printf "$pf2" "Creating directory $dir" "`status $status 'DONE' '' 'FAILED'`"
                				status="r"
                				touch "$uCHROOT$bind" && status="g" || returnValue=1
                				printf "$pf2" "Creating mountpoint $uCHROOT$bind (file)" "`status $status 'DONE' '' 'FAILED'`"
                			fi
                		fi

						if [ $returnValue -eq 0 ]; then
							status="r"
	                        mount --bind  "$bind" "$uCHROOT$bind" && status="g" || returnValue=1
	                        printf "$pf2" "Mount $uCHROOT$bind" "`status $status 'DONE' '' 'FAILED'`"
	                        [ "$status" = "g" ] && status="r" && mount -o "remount,ro,bind" "$bind" "$uCHROOT$bind" && status="g" || returnValue=1
	                        printf "$pf2" "Remount $uCHROOT$bind readonly" "`status $status 'DONE' '' 'FAILED'`"
						else
							printf "$pf" "Mount $uCHROOT$bind" "`status y '' 'SKIPPED'`"
						fi
                fi

                if [ "$_OPT_ACTION_BIND" = "unbind" -o "$_OPT_ACTION_BIND" = "clean" ] && is_bound "$uCHROOT$bind"; then
                	status="r"
					umount "$uCHROOT$bind" && status="g" || returnValue=1
					printf "$pf2" "Umount $uCHROOT$bind" "`status $status 'DONE' '' 'FAILED'`"
                fi
        done;

        if [ "$_OPT_ACTION_BIND" = "clean" ]; then
        	deletePathes=()
        	allPathes=()
        	for bind in `get_user_binds "$uUSERNAME"`; do
        		deletePath="`get_base_path \"$bind\"`"

        		inList=false
        		for e in "${allPathes[@]}"; do
        			[ "$e" = "$uCHROOT$deletePath" ] && inList=true
        		done
        		$inList || allPathes+=("$uCHROOT$deletePath")

        		if ! $inList; then

	        		if [ ! -e "$uCHROOT$deletePath" ]; then
	        			printf "$pf2" "$uCHROOT$deletePath - does not exist" "`status y '' 'SKIPPED'`"
	        			continue
	        		fi

	        		if is_bound "$uCHROOT$bind"; then
	        			printf "$pf2" "$uCHROOT$deletePath - still mounted" "`status r '' '' 'ERROR'`"
	        			continue
	        		fi

        			deletePathes+=("$uCHROOT$deletePath")
        		fi
        	done

        	[ "${#deletePathes}" -eq 0 ] && stop $returnValue


			if ! $_OPT_YES; then
				echo -e "\nWill execute the following commands in order:\n"

				for i in `seq 0 $((${#deletePathes[@]}-1))`; do
					echo -e "\trm -rf \"${deletePathes[$i]}\""
				done;
				echo
			fi

			while [ "$commandsOK" != "y" -a "$commandsOK" != "n" ]; do

				! $_OPT_YES && read -p "Are you OK with that? [y/n]: " commandsOK
				$_OPT_YES && commandsOK="y"

				if [ "$commandsOK" = "y" ]; then
					! $_OPT_YES && echo
					for i in `seq 0 $((${#deletePathes[@]}-1))`; do
						cmd_status="r"
						rm -rf "${deletePathes[$i]}"
						[ "$?" -eq 0 ] && cmd_status="g"
						printf "$pf2" "Delete ${deletePathes[$i]}" "`status "$cmd_status" 'DONE' '' 'FAILED'`"
						[ "$cmd_status" = "g" ] || returnValue=1
					done;
				fi

				if [ "$commandsOK" = "n" ]; then
					printf "$pf2" "Aborted by user." "`status y '' 'SKIPPED'`"
				fi
			done
		fi

        stop $returnValue
		;;

	enable|disable)
		status="r"
		[ "$status_pool_exists"  = "r" ] && printf "$pf2" "\"$uPOOL\" missing." "`status r '' '' 'ERROR'`" && stop 1
		[ "$status_nginx_exists" = "r" ] && printf "$pf2" "\"$uNGINX\" missing." "`status r '' '' 'ERROR'`" && stop 1
		[ "$status_pool_exists" != "$status_nginx_exists" ] && printf "$pf2" "POOL and NGINX config not in same state." "`status r '' '' 'ERROR'`" && stop 1

		if [ "$_OPT_ACTION" = "enable" ]; then
			[ "$status_pool_exists" = "g" ] && printf "$pf2" "Webspace already enabled." "`status y '' 'SKIPPED' ''`" && stop 0

			! $0 _INTERNAL_ status "$uUSERNAME" &> /dev/null && printf "$pf2" "Webspace can not be enabled. Run \"$0 status $uUSERNAME\" to see why." "`status r '' '' 'ERROR'`" && stop 1

			mv "$uPOOL.disabled" "$uPOOL" && status="g"
			[ "$status" = "g" ] && status="r" && mv "$uNGINX.disabled" "$uNGINX" && status="g"
			printf "$pf2" "Webspace enabled" "`status $status 'ENABLED' '' 'FAILED'`"
			[ "$status" = "g" ] || stop 1

		elif [ "$_OPT_ACTION" = "disable" ]; then
			[ "$status_pool_exists" = "y" ] && printf "$pf2" "Webspace already disabled." "`status y '' 'SKIPPED' ''`" && stop 0
			mv "$uPOOL" "$uPOOL.disabled" && status="g"
			[ "$status" = "g" ] && status="r" && mv "$uNGINX" "$uNGINX.disabled" && status="g"
			printf "$pf2" "Webspace disabled" "`status $status 'DISABLED' '' 'FAILED'`"
			[ "$status" = "g" ] || stop 1
		fi
		reload_services || stop 1
		;;

	create)
		returnValue=0

		reset_nscd

		! user_is_valid "$_OPT_USERNAME" && printf "$pf2" "Invalid username ([a-zA-Z0-9]{4,10})" "`status r '' '' 'ERROR'`" && stop 1

		if user_create "$_OPT_USERNAME"; then
			printf "$pf2" "Run _USER_CREATE_CMD..." "`status g 'DONE'`"
		else
			printf "$pf2" "Run _USER_CREATE_CMD..." "`status r '' '' 'FAILED'`"
			stop 1
		fi

		status="r"
		eval "${_NGINX_ADD_GROUP_CMD//@USERNAME@/$_OPT_USERNAME}" && status="g"
		printf "$pf2" "Run _NGINX_ADD_GROUP_CMD..." "`status $status 'DONE' '' 'FAILED'`"
		[ "$status" = "g" ] || returnValue=1



		! id "$_OPT_USERNAME" &> /dev/null && printf "$pf2" "User \"$_OPT_USERNAME\" not found in system." "`status r '' '' 'ERROR'`" && stop 1
		! group_exists "$_OPT_USERNAME"    && printf "$pf2" "No group \"$_OPT_USERNAME\" found in system." "`status r '' '' 'ERROR'`" && stop 1

		uCHROOT="`get_user_chroot \"$_OPT_USERNAME\"`"

		if [ ! -d "$uCHROOT" ]; then
			status="r"
			mkdir -p "$uCHROOT" && status="g"
			printf "$pf2" "Create chroot \"$uCHROOT\"" "`status $status 'DONE' '' 'FAILED'`"
		fi

		[ ! -d "$uCHROOT" ] && printf "$pf2" "Chroot \"$uCHROOT\" does not exist." "`status r '' '' 'ERROR'`" && stop 1

		domains="$_OPT_DOMAINS"
		if [ -z "$domains" ]; then
			# Ask for domain list
			echo
			printf "$pf2" "Please specify at least one domain for the new webspace."
			printf "$pf2" "Finish list with empty input."
			domains=""
			while true; do
				read -p "FQDN: " fqdn
				fqdn="`echo -e \"$fqdn\" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`"

				[ -z "$fqdn" -a -n "$domains" ] && break

				if is_valid_fqdn "$fqdn"; then
					domains="$domains $fqdn"
				else
					printf "$pf2" "Not a valid domain." "`status r '' '' 'ERROR'`"
				fi
			done
			domains="`echo -e \"$domains\" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`"
		fi

		echo
		install_template "$_NGINX_CONF_TEMPLATE" "${_NGINX_CONF//@USERNAME@/$_OPT_USERNAME}.disabled" "$_NGINX_CONF_TEMPLATE_OWNER" "$_NGINX_CONF_TEMPLATE_MODE" "false" "USERNAME" "$_OPT_USERNAME" "DOMAINS" "$domains" || returnValue=1
		install_template "$_PHP_FPM_CONF_TEMPLATE" "${_PHP_FPM_CONF//@USERNAME@/$_OPT_USERNAME}.disabled" "$_PHP_FPM_CONF_TEMPLATE_OWNER" "$_PHP_FPM_CONF_TEMPLATE_MODE" "false" "USERNAME" "$_OPT_USERNAME" || returnValue=1

		echo
		$0 _INTERNAL_ fixperm "$_OPT_USERNAME" || returnValue=1
		echo
		$0 _INTERNAL_ binds bind "$_OPT_USERNAME" || returnValue=1

		status="r"
		$0 _INTERNAL_ binds systemd update > /dev/null && status="g"
		[ "$status" = "g" ] || returnValue=1
		printf "$pf2" "Update systemd units for chroot binds..." "`status $status 'DONE' '' 'FAILED'`"

		if $_LETS_ENCRYPT_ENABLE; then
			echo
			$0 _INTERNAL_ tls refresh "$_OPT_USERNAME"
		fi

		if [ -n "$_POST_CREATE_CMD" ]; then
			echo
			status="r"
			eval "${_POST_CREATE_CMD//@USERNAME@/$_OPT_USERNAME}" && status="g"
			[ "$status" = "g" ] || returnValue=1
			printf "$pf2" "Run _POST_CREATE_CMD..." "`status $status 'DONE' '' 'FAILED'`"
		fi

		stop $returnValue
		;;

	regenerate-config)
		if [ "$status_nginx_exists" = "g" -o "$status_pool_exists" = "g" ]; then
			printf "$pf2" "Please disable webspace first." "`status r '' '' 'ERROR'`"
			stop 1
		fi

		domains=""
		for d in $uFQDNS; do
			domains="$domains $d"
		done;
		echo "Dimains: $domains"
		domains="`echo -e \"$domains\" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`"
		

		returnValue=0
		status="g"
		install_template "$_NGINX_CONF_TEMPLATE" "${_NGINX_CONF//@USERNAME@/$_OPT_USERNAME}.disabled" "$_NGINX_CONF_TEMPLATE_OWNER" "$_NGINX_CONF_TEMPLATE_MODE" "true" "USERNAME" "$_OPT_USERNAME" "DOMAINS" "$domains" || status="r"
		printf "$pf2" "Regenerate NGINX configuration..." "`status $status 'DONE' '' 'FAILED'`"
		[ "$status" = "g" ] || returnValue=1
		
		install_template "$_PHP_FPM_CONF_TEMPLATE" "${_PHP_FPM_CONF//@USERNAME@/$_OPT_USERNAME}.disabled" "$_PHP_FPM_CONF_TEMPLATE_OWNER" "$_PHP_FPM_CONF_TEMPLATE_MODE" "true" "USERNAME" "$_OPT_USERNAME" || status="r"
		printf "$pf2" "Regenerate PHP-FPM configuration..." "`status $status 'DONE' '' 'FAILED'`"
		[ "$status" = "g" ] || returnValue=1

		stop $returnValue
		;;

	delete)

		if [ "$status_nginx_exists" = "g" -o "$status_pool_exists" = "g" ]; then
			printf "$pf2" "Please disable webspace first." "`status r '' '' 'ERROR'`"
			stop 1
		fi

		deleteCmd[0]="rm \"${_NGINX_CONF//@USERNAME@/$uUSERNAME}.disabled\""
		deleteCmd[1]="rm \"${_PHP_FPM_CONF//@USERNAME@/$uUSERNAME}.disabled\""
		deleteCmd[2]="rm -f \"$uCERT\""
		deleteCmd[3]="rm -f \"$_LETS_ENCRYPT_CSR_DIR/$uUSERNAME.csr\""
		deleteCmd[4]="rm -r \"${_PHP_FPM_CHROOT//@USERNAME@/$uUSERNAME}\""
		deleteCmd[5]="${_USER_DELETE_CMD//@USERNAME@/$uUSERNAME}"


		if ! $_OPT_YES; then
			echo -e "Will execute the following commands in order:\n"

			for i in `seq 0 $((${#deleteCmd[@]}-1))`; do
				echo -e "\t${deleteCmd[$i]}"
			done;
			echo
		fi

		returnValue=0
		while [ "$commandsOK" != "y" -a "$commandsOK" != "n" ]; do

			! $_OPT_YES && read -p "Are you OK with that? [y/n]: " commandsOK
			$_OPT_YES && commandsOK="y"

			if [ "$commandsOK" = "y" ]; then
				! $_OPT_YES && echo

				if is_any_bound "$uUSERNAME"; then
					$0 _INTERNAL_ binds unbind "$uUSERNAME"
					[ "$?" -ne 0 ] && printf "$pf2" "Unbind failed." "`status r '' '' 'ERROR'`" && stop 1
				fi



				for i in `seq 0 $((${#deleteCmd[@]}-1))`; do
					cmd_status="r"
					eval "${deleteCmd[$i]}"
					[ "$?" -eq 0 ] && cmd_status="g"
					printf "$pf2" "${deleteCmd[$i]}" "`status "$cmd_status" 'DONE' '' 'FAILED'`"
					[ "$cmd_status" = "g" ] || returnValue=1
				done;
			fi

			if [ "$commandsOK" = "n" ]; then
				printf "$pf2" "Aborted by user." "`status y '' 'SKIPPED'`"
				stop 1
			fi
		done
		reset_nscd
		status="r"
		$0 _INTERNAL_ binds systemd update > /dev/null && status="g"
		[ "$status" = "g" ] || returnValue=1
		printf "$pf2" "Update systemd units for chroot binds..." "`status $status 'DONE' '' 'FAILED'`"

		stop $returnValue
		;;

	tls)

		! $_LETS_ENCRYPT_ENABLE && printf "$pf2" "Let's Encrypt functionality is not enabled." "`status r '' '' 'ERROR'`" && stop 1



		# Check if we can use _LETS_ENCRYPT_USER
		if ! le_cmd "true"; then
			printf "$pf2" "Could not run as \"$_LETS_ENCRYPT_USER\"" "`status r '' '' 'ERROR'`"
			stop 1
		fi

		# Check/setup _LETS_ENCRYPT_CRT/CSR/CHALLENGE_DIR
		for d in CRT CSR CHALLENGE; do
			dir="`eval echo \\$_LETS_ENCRYPT_${d}_DIR`"
			eval "status_${d}_dir=\"y\""
			le_cmd "[ -d \"$dir\" -a -w \"$dir\" ]" && eval "status_${d}_dir=\"g\""
			[ "`eval echo \\$status_${d}_dir`" = "y" -a "$_OPT_ACTION_TLS" != "init" ] && eval "status_${d}_dir=\"r\""
			status="`eval echo \\$status_${d}_dir`"
			printf "$pf2" "_LETS_ENCRYPT_${d}_DIR exists and writable by $_LETS_ENCRYPT_USER" "`status $status 'YES' 'NO' 'NO'`"
			[ "$status" = "r" ] && stop 1

			if [ "$status" = "y" ]; then
				create_owner="$_LETS_ENCRYPT_USER:$_NGINX_USERGROUP"
				create_mode="0710"

				if [ "$d" = "CSR" ]; then
					create_owner="$_LETS_ENCRYPT_USER:$_LETS_ENCRYPT_USERGROUP"
					create_mode="0700"
				fi

				status_create="r"
				mkdir -p "$dir" && status_create="g"
				printf "$pf2" "Create $dir" "`status $status_create 'DONE' '' 'FAILED'`"
				[ "$status_create" = "g" ] && status_create="r" && chown "$create_owner" "$dir" && chmod "$create_mode" "$dir" && status_create="g"
				printf "$pf2" "Setting permissions to $create_owner mode $create_mode" "`status $status_create 'DONE' '' 'FAILED'`"
				[ "$status_create" != "g" ] && stop 1
			fi
		done


		# Check/setup Account and Server key
		for k in ACCOUNT SERVER; do
			keyPath="`eval echo \\$_LETS_ENCRYPT_${k}_KEY`"

			eval "status_${k}_key=\"y\""
			le_cmd "[ -r \"$keyPath\" ]" && eval "status_${k}_key=\"g\""
			[ "`eval echo \\$status_${k}_key`" = "y" -a "$_OPT_ACTION_TLS" != "init" ] && eval "status_${k}_key=\"r\""
			status="`eval echo \\$status_${k}_key`"
			printf "$pf2" "_LETS_ENCRYPT_${k}_KEY exists and readable by $_LETS_ENCRYPT_USER" "`status $status 'YES' 'NO' 'NO'`"
			[ "$status" = "r" ] && stop 1

			if [ "$status" = "y" ]; then
				create_owner="$_LETS_ENCRYPT_USER:$_NGINX_USERGROUP"
				create_mode="0440"

				if [ "$k" = "ACCOUNT" ]; then
					create_owner="$_LETS_ENCRYPT_USER:$_LETS_ENCRYPT_USERGROUP"
					create_mode="0400"
				fi;

				status_create="r"
				openssl genrsa $_LETS_ENCRYPT_KEYLENGTH > "$keyPath" && status_create="g"
				printf "$pf2" "Generate _LETS_ENCRYPT_${k}_KEY" "`status $status_create 'DONE' '' 'FAILED'`"
				[ "$status_create" = "g" ] && status_create="r" && chown "$create_owner" "$keyPath" && chmod "$create_mode" "$keyPath" && status_create="g"
				printf "$pf2" "Setting permissions to $create_owner mode $create_mode" "`status $status_create 'DONE' '' 'FAILED'`"
				[ "$status_create" != "g" ] && stop 1
			fi
		done


		# Check/setup dhparams
		status_dhparams_exists="y"
		le_cmd "[ -r \"$_LETS_ENCRYPT_DHPARAMS\" ]" && status_dhparams_exists="g"
		[ "$status_dhparams_exists" = "y" -a "$_OPT_ACTION_TLS" != "init" ] && status_dhparams_exists="r"
		printf "$pf2" "_LETS_ENCRYPT_DHPARAMS exists and readable by $_LETS_ENCRYPT_USER" "`status $status_dhparams_exists 'YES' 'NO' 'NO'`"
		[ "$status_dhparams_exists" = "r" ] && stop 1

		if [ "$status_dhparams_exists" = "y" ]; then
			status_create="r"
			openssl dhparam -out "$_LETS_ENCRYPT_DHPARAMS" $_LETS_ENCRYPT_DHPARAMS_LENGTH > "$_LETS_ENCRYPT_DHPARAMS" && status_create="g"
			printf "$pf2" "Generating _LETS_ENCRYPT_DHPARAMS..." "`status $status_create 'DONE' '' 'FAILED'`"
			[ "$status_create" = "g" ] && status_create="r" && chown "$_LETS_ENCRYPT_USER:$_NGINX_USERGROUP" "$_LETS_ENCRYPT_DHPARAMS" && chmod "440" "$_LETS_ENCRYPT_DHPARAMS" && status_create="g"
			printf "$pf2" "Setting permissions to $_LETS_ENCRYPT_USER:$_NGINX_USERGROUP mode 440" "`status $status_create 'DONE' '' 'FAILED'`"
			[ "$status_create" != "g" ] && stop 1
		fi

		if [ "$_OPT_ACTION_TLS" = "refresh" ]; then

			[ "$status_nginx_exists" = "r" ] && printf "$pf2" "NGINX config could not be read" "`status r '' '' 'ERROR'`" && stop 1
			[ -z "$uFQDNS" ]                 && printf "$pf2" "No domains for $uUSERNAME" "`status r '' '' 'ERROR'`" && stop 1

			proceed=false
			if ! $_OPT_ACTION_TLS_FORCEREFRESH; then

				status="$status_crt_exists"
				[ "$status" = "r" ] && status="y"
				printf "$pf2" "Checking existance..." "`status $status 'YES' 'NO' ''`"
				[ "$status" != "g" ] && proceed=true

				if ! $proceed; then
					status="$status_crt_expiry"
					[ "$status" != "r" ] && printf "$pf2" "Checking expiry..." "`status $status 'VALID' 'EXPIRING' ''`"
					[ "$status" = "r" ]  && printf "$pf2" "Checking expiry..." "`status r '' 'EXPIRED' ''`"
					[ "$status" != "g" ] && proceed=true
				fi

				if ! $proceed; then
					status="$status_crt_fqdns"
					[ "$status" = "r" ] && status="y"
					printf "$pf2" "Checking all domains available in cert..." "`status $status 'OK' 'MISSING' ''`"
					[ "$status" != "g" ] && proceed=true
				fi
			else
				proceed=true
			fi

			! $proceed && printf "$pf2" "No reason to refresh certificate for $uUSERNAME" "`status y '' 'SKIPPING' ''`" && stop 0

			status="r"
			csr_path="$_LETS_ENCRYPT_CSR_DIR/$uUSERNAME.csr"

			san="DNS:`echo $uFQDNS | sed -e 's/ /,DNS:/g'`"
			le_cmd "openssl req -new -sha256 -key \"$_LETS_ENCRYPT_SERVER_KEY\" -subj \"/\" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf \"[SAN]\nsubjectAltName=$san\")) > \"$csr_path\"" && status="g"

			printf "$pf2" "Creating CSR for $uUSERNAME..." "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			status="r" && le_cmd "chown \"$_LETS_ENCRYPT_USER:$_LETS_ENCRYPT_USERGROUP\" \"$csr_path\"" && status="g"
			printf "$pf2" "Set owner to $_LETS_ENCRYPT_USER:$_LETS_ENCRYPT_USERGROUP" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			status="r" && le_cmd "chmod $_LETS_ENCRYPT_CSR_MODE \"$csr_path\"" && status="g"
			printf "$pf2" "Set mode to $_LETS_ENCRYPT_CSR_MODE" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			status="r"
			le_cmd "$_LETS_ENCRYPT_ACME_TINY --account-key \"$_LETS_ENCRYPT_ACCOUNT_KEY\" --csr \"$csr_path\" --acme-dir \"$_LETS_ENCRYPT_CHALLENGE_DIR\" > \"$uCERT.signed\"" && status="g"
			printf "$pf2" "Request certificate for $uUSERNAME" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && le_cmd "rm -f $uCERT.signed" && stop 1

			status="r" && le_cmd "cat \"$uCERT.signed\" > \"$uCERT.chained\"" && status="g"
			printf "$pf2" "Chaining certifiacte..." "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && le_cmd "rm -f $uCERT.chained" && stop 1

			status="r" && le_cmd "mv \"$uCERT.chained\" \"$uCERT\"" && status="g"
			printf "$pf2" "Putting new cert in place" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			status="r" && le_cmd "rm \"$uCERT.signed\"" && status="g"
			printf "$pf2" "Removing unchained certificate" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			status="r" && le_cmd "chown "$_LETS_ENCRYPT_USER:$_LETS_ENCRYPT_USERGROUP" \"$uCERT\"" && status="g"
			printf "$pf2" "Set owner to $_LETS_ENCRYPT_USER:$_LETS_ENCRYPT_USERGROUP" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			status="r" && le_cmd "chmod $_LETS_ENCRYPT_CRT_MODE \"$uCERT\"" && status="g"
			printf "$pf2" "Set mode to $_LETS_ENCRYPT_CRT_MODE" "`status $status 'OK' '' 'FAILED'`"
			[ "$status" = "r" ] && stop 1

			reload_services "nginx" "sudo" || stop 1

		fi
		;;

	help)

cat <<END
Usage: $0 <command> [<subcommand> [<subcommand>]] [<username>] [-n|-Y]

    <command> can be one of...

        list:
            List all usernames associated with webspaces

        create <username> [FQDN0 [FQDN1 [...]]]:
            Create a webspace associated with <username> with
            domains FQDN0 - FQDNn. If the domains are not provided
            from the commandline, they need to be provided interactively.

        regenerate-config <username>:
            Regenerate configuration for NGINX and PHP-FPM from
            template files.

        status <username>:
            Show status of webspace associated with <username>

        enable <username> [-n]:
            Enable webspace associated with <username>
            -n prevents reload of services

        disable <username> [-n]:
            Disable webspace associated with <username>
            -n prevents reload of services

        delete <username> [-Y]:
            Delete webspace associated with <username>.
            If -Y is provided, no questions will be asked
            and the account and all data of this webspace will
            be deleted.

        fixperm <username>:
            Set permissions and ownerships in PHP-FPM chroot
            of <username> as defined in _PHP_FPM_CHROOT_DIRS

        binds list|status|bind|unbind|clean [-Y] <username>:

            list:
                List binds for <username>

            status:
                Show mount status of binds for <username>

            bind:
                Mount all binds for <username>'s chroot. Mountpoints
                will be created if they do not exist.

            unbind:
                Unmount all binds for <username>.

            clean [-Y]:
                Unmount all binds for <username> and delete
                mountpoints for binds. Without -Y it will
                just list the paths that would be deleted and
                ask for confirmation interactively.

        binds systemd list|create|update|clean [-Y]

             These commands manage unit files for systemd to
             automatically create mountpoints for users on boot
             and mount binds for the user's chroots.

            list:
                List all systemd unit files managed by this script.

            create:
                Create systemd units for all users.

            update:
                Same as

                  $0 binds systemd clean -Y && $0 binds systemd create

                This is idempotent and will bring the unitfiles in sync
                with the user's chroot binds.

            clean [-Y]:
                Delete all unit files managed by this script. Without -Y it will
                just list the paths that would be deleted and
                ask for confirmation interactively.


        tls <subcommand> [<username>]:

            _LETS_ENCRYPT_ENABLE must be set to "true" to use these commands

            <subcommand> can be one of...

            init:
                Check preconditions and setup environment
                (directories, keys) for requesting TLS
                certificates using the "refresh" subcommand.

            refresh <username> [-n]:
                Request and apply certificate for webspace
                associated with <username> if no certificate
                is available, or if the actual certificate is
                expired or about to expire.

                -n prevents reload of services

            forcerefresh <username> [-n]:
                Same as "refresh" but always gets a new certificate

                -n prevents reload of services

END
		stop 1
		;;

esac
