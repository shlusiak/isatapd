#!/sbin/runscript

ISATAPD="/usr/sbin/isatapd"
PID=/var/run/isatapd.pid

opts="reload"

depend() {
	need net localmount
	after bootmisc
	use dns logger
}

start() {
	[ -n "${ISATAP_INTERVAL}" ] && DAEMON_OPTS="${DAEMON_OPTS} --interval ${ISATAP_INTERVAL} "
	[ -n "${ISATAP_NAME}" ] && DAEMON_OPTS="${DAEMON_OPTS} --name ${ISATAP_NAME} "
	[ -n "${ISATAP_LINK}" ] && DAEMON_OPTS="${DAEMON_OPTS} --link ${ISATAP_LINK} "
	[ -n "${MTU}" ] && DAEMON_OPTS="${DAEMON_OPTS} --mtu ${MTU} "

	if [ -n "${ISATAP_USER_RS}" ]; then
		if yesno ${ISATAP_USER_RS}; then
			DAEMON_OPTS="${DAEMON_OPTS} --user-rs "
		else
			DAEMON_OPTS="${DAEMON_OPTS} --no-user-rs "
		fi
	fi

	ebegin "Starting ${SVCNAME}"
	start-stop-daemon --start --exec ${ISATAPD} -- \
		--daemon --pid ${PID} ${DAEMON_OPTS} ${ISATAP_ROUTERS}
	eend $?
}

stop() {
	ebegin "Stopping ${SVCNAME}"
	start-stop-daemon --stop --pidfile ${PID}
	eend $?
}

reload() {
	ebegin "Reloading ${SVCNAME}"
	if ! service_started "${SVCNAME}" ; then
		eend 1 "${SVCNAME} is not started"
		return 1
	fi
	
	start-stop-daemon --stop --signal HUP --oknodo --pidfile ${PID}
	eend $?
}
