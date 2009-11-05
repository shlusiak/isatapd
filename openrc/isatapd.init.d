#!/sbin/runscript

ISATAPD="/usr/sbin/isatapd"
PID=/var/run/isatapd.pid

opts="reload"

depend() {
	need net
	after bootmisc
	use dns logger
}

start() {
	[ -n "${ISATAP_INTERVAL}" ] && DAEMON_OPTS="${DAEMON_OPTS} --interval ${ISATAP_INTERVAL} "
	[ -n "${ISATAP_NAME}" ] && DAEMON_OPTS="${DAEMON_OPTS} --name ${ISATAP_NAME} "
	[ -n "${ISATAP_LINK}" ] && DAEMON_OPTS="${DAEMON_OPTS} --link ${ISATAP_LINK} "
	[ -n "${ISATAP_MTU}" ] && DAEMON_OPTS="${DAEMON_OPTS} --mtu ${ISATAP_MTU} "
	[ -n "${ISATAP_CHECK_DNS}" ] && DAEMON_OPTS="${DAEMON_OPTS} --check-dns ${ISATAP_CHECK_DNS} "

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
