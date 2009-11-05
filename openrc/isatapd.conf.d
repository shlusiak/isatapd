# /etc/conf.d/isatapd: config file for /etc/init.d/isatapd

# A space separated list of one or more hostnames/IPv4 addresses to use as
# potential routers.
# The default is the unqualified hostname 'isatap'
#ISATAP_ROUTERS=""

# Interval in seconds to send router solicitations.
# Default (unset): 'auto'
#ISATAP_INTERVAL="600"

# Interval in seconds to check for DNS changes. Set to 0 to disable.
# Default: 3600
#ISATAP_CHECK_DNS="3600"

# Link tunnel to device
# Default (unset): automatically find outgoing device
#ISATAP_LINK=""

# The name of the ISATAP tunnel device
# Default is 'is0' if ISATAP_LINK is unset and 'is_${ISATAP_LINK}' otherwise.
#ISATAP_NAME="is0"

# IPv6 MTU of the created ISATAP tunnel interface. The IPv4 path to
# the ISATAP router and all other ISATAP clients should be able to
# handle at least MTU+20 bytes. 
# The minimum IPv6 MTU (1280 Bytes) is the safest choice here
ISATAP_MTU="1280"


# Additional options, see isatapd(8) for details
#DAEMON_OPTS=""
