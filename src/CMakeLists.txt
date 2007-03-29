include_directories (${NDISC6_BINARY_DIR} ${NDISC6_SOURCE_DIR}/include)

# ndisc6
add_executable (ndisc6 ndisc.c)
target_link_libraries (ndisc6 ${LIBRT})

# rdisc6
add_executable (rdisc6 ndisc.c)
set_target_properties (rdisc6 PROPERTIES COMPILE_FLAGS -DRDISC)
target_link_libraries (rdisc6 ${LIBRT})

# rltraceroute6
add_executable (rltraceroute6 traceroute.c traceroute.h 
                              trace-tcp.c trace-udp.c trace-icmp.c)
target_link_libraries (rltraceroute6 ${LIBRT})

# tcptraceroute6
add_executable (tcptraceroute6 tcptraceroute.c)
set_target_properties (tcptraceroute6 PROPERTIES COMPILE_FLAGS
                       "-DMYEXECDIR=\\\"/usr/local/sbin\\\" -DRLTRACEROUTE6=\\\"rltraceroute6\\\"")

# tcpspray
add_executable (tcpspray tcpspray.c)
target_link_libraries (tcpspray ${LIBRT})

# addrinfo
add_executable (addrinfo addrinfo.c)
