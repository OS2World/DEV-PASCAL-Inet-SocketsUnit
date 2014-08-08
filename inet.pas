unit Inet;

{
  Inet & Sockets Unit v1.04.
  /c/ 2000, 2001 by madded2 (madded@vao.udmnet.ru).
  based on units from SIBYL & infos from Toolkit 4.0.

  for help use tcppr.inf and C samples from toolkit.

  without res_* and dh_* funcs, and have very
  bad suppot for select() and ioctl() funcs

  also needed STRINGS unit for PChar <-> Pascal strings convertions..

  new in ver 1.04 : little ioctl() & iptrace support + errors SOCE* constants
  new in ver 1.03 : used inet_lib.lib file for fixing VP linker bug
  new in ver 1.02 : $saves sections, need for correct registers operations
  new in ver 1.01 : ip header struct
  }

interface
{&Cdecl+,AlignRec-,AlignData-}
{$R-,Q-}

{$OrgName+}
{$L inet_lib.lib}

{ ip.h - ip packet header struct }

{
 * Structure of an internet header, naked of options.
}
type
   ip = record
      hlen_ver			       :  Byte; { lo 4 bits = header len/4
						  hi 4 bits = ip ver (4) }
      ip_tos			       :  Byte;      { type of service }
      ip_len			       :  SmallWord; { total packet length }
      ip_id			       :  SmallWord; { identification }
      ip_off			       :  SmallWord; { fragment offset field }
      ip_ttl			       :  Byte;      { time to live }
      ip_p			       :  Byte;      { protocol (see IPPROTO_*) }
      ip_sum			       :  SmallWord; { header checksum }
      ip_src, ip_dst		       :  Longint;   { ip from / to addr }
   end;


{ in.h / inet.h const & func }

{
 * Protocols
}
const
     IPPROTO_IP 	     = 0;		{ dummy for IP }
     IPPROTO_ICMP	     = 1;		{ control message protocol }
     IPPROTO_GGP	     = 3;		{ gateway^2 (deprecated) }
     IPPROTO_TCP	     = 6;		{ tcp }
     IPPROTO_EGP	     = 8;		{ exterior gateway protocol }
     IPPROTO_PUP	     = 12;		{ pup }
     IPPROTO_UDP	     = 17;		{ user datagram protocol }
     IPPROTO_IDP	     = 22;		{ xns idp }

     IPPROTO_RAW	     = 255;		{ raw IP packet }
     IPPROTO_MAX	     = 256;

{
 * Ports < IPPORT_RESERVED are reserved for
 * privileged processes (e.g. root).
 * Ports > IPPORT_USERRESERVED are reserved
 * for servers, not necessarily privileged.
}
const
    IPPORT_RESERVED	    = 1024;
    IPPORT_USERRESERVED     = 5000;

{
 * Link numbers
}
const
    IMPLINK_IP		    = 155;
    IMPLINK_LOWEXPER	    = 156;
    IMPLINK_HIGHEXPER	    = 158;

{
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
}
const
     IN_CLASSA_NET	     = $ff000000;
     IN_CLASSA_NSHIFT	     = 24;
     IN_CLASSA_HOST	     = $00ffffff;
     IN_CLASSA_MAX	     = 128;

     IN_CLASSB_NET	     = $ffff0000;
     IN_CLASSB_NSHIFT	     = 16;
     IN_CLASSB_HOST	     = $0000ffff;
     IN_CLASSB_MAX	     = 65536;

     IN_CLASSC_NET	     = $ffffff00;
     IN_CLASSC_NSHIFT	     = 8;
     IN_CLASSC_HOST	     = $000000ff;

     INADDR_ANY 	     = $00000000;
     INADDR_BROADCAST	     = $ffffffff;     { must be masked }
     INADDR_NONE	     = $ffffffff;     { -1 return }

     IN_LOOPBACKNET	     = 127;	      { official! }

{
 * Socket address, internet style.
}
type
   sockaddr_in = record
      sin_family		       :  SmallWord;
      sin_port			       :  SmallWord; { htons first!! }
      sin_addr			       :  Longint; {in_addr; hist reasons :)) }
      sin_zero			       :  array[0..7] of Byte; {must be zero}
   end;

{ * Internet address (a structure for historical reasons) }
type
   in_addr = record
      s_addr			       :  Longint;
   end;

{*
 * Options for use with [gs]etsockopt at the IP level.
 * }
const

  IP_OPTIONS		= 1;   // buf/ip_opts; set/get IP options
  IP_MULTICAST_IF	= 2;   // u_char; set/get IP multicast i/f
  IP_MULTICAST_TTL	= 3;   // u_char; set/get IP multicast ttl
  IP_MULTICAST_LOOP	= 4;   // u_char; set/get IP multicast loopback
  IP_ADD_MEMBERSHIP	= 5;   // ip_mreq; add an IP group membership
  IP_DROP_MEMBERSHIP	= 6;   // ip_mreq; drop an IP group membership
  IP_HDRINCL		= 7;   // int; header is included with data
  IP_TOS		= 8;   // int; IP type of service and preced.
  IP_TTL		= 9;   // int; IP time to live
  IP_RECVOPTS		= 10;  // bool; receive all IP opts w/dgram
  IP_RECVRETOPTS	= 11;  // bool; receive IP opts for response
  IP_RECVDSTADDR	= 12;  // bool; receive IP dst addr w/dgram
  IP_RETOPTS		= 13;  // ip_opts; set/get IP options
  IP_RECVTRRI		= 14;  // bool; receive token ring routing inf

{*
 * Defaults and limits for options
 * }
  IP_DEFAULT_MULTICAST_TTL  = 1;    // normally limit m'casts to 1 hop
  IP_DEFAULT_MULTICAST_LOOP = 1;    // normally hear sends if a member
  IP_MAX_MEMBERSHIPS	    = 20;   // per socket; must fit in one mbuf
  MAX_IN_MULTI	  = 16*IP_MAX_MEMBERSHIPS;     // 320 max per os2


{ sockets def & funcs }
// * Definitions related to sockets: types, address families, options.

// * Address families.
const

  AF_UNSPEC	 = 0;	     // unspecified
  AF_LOCAL	 = 1;	     // local to host (pipes, portals)
  AF_UNIX	 = AF_LOCAL; // backward compatibility
  AF_OS2	 = AF_UNIX;
  AF_INET	 = 2;	     // internetwork: UDP, TCP, etc.
  AF_IMPLINK	 = 3;	     // arpanet imp addresses
  AF_PUP	 = 4;	     // pup protocols: e.g. BSP
  AF_CHAOS	 = 5;	     // mit CHAOS protocols
  AF_NS 	 = 6;	     // XEROX NS protocols
  AF_ISO	 = 7;	     // ISO protocols
  AF_OSI	 = AF_ISO;
  AF_ECMA	 = 8;	     // european computer manufacturers
  AF_DATAKIT	 = 9;	     // datakit protocols
  AF_CCITT	 = 10;	     // CCITT protocols, X.25 etc
  AF_SNA	 = 11;	     // IBM SNA
  AF_DECnet	 = 12;	     // DECnet
  AF_DLI	 = 13;	     // DEC Direct data link interface
  AF_LAT	 = 14;	     // LAT
  AF_HYLINK	 = 15;	     // NSC Hyperchannel
  AF_APPLETALK	 = 16;	     // Apple Talk
  AF_NB 	 = 17;	     // Netbios
  AF_NETBIOS	 = AF_NB;
  AF_LINK	 = 18;	     // Link layer interface
  pseudo_AF_XTP  = 19;	     // eXpress Transfer Protocol (no AF)
  AF_COIP	 = 20;	     // connection-oriented IP, aka ST II
  AF_CNT	 = 21;	     // Computer Network Technology
  pseudo_AF_RTIP = 22;	     // Help Identify RTIP packets
  AF_IPX	 = 23;	     // Novell Internet Protocol
  AF_SIP	 = 24;	     // Simple Internet Protocol
  AF_INET6	 = 24;
  pseudo_AF_PIP  = 25;	     // Help Identify PIP packets
  AF_ROUTE	 = 39;	     // Internal Routing Protocol
  AF_FWIP	 = 40;	     // firewall support
  AF_IPSEC	 = 41;	     // IPSEC and encryption techniques
  AF_DES	 = 42;	     // DES
  AF_MD5	 = 43;
  AF_CDMF	 = 44;

  AF_MAX	 = 45;

// * Protocol families, same as address families for now.
const

  PF_UNSPEC    = AF_UNSPEC;
  PF_LOCAL     = AF_LOCAL;
  PF_UNIX      = PF_LOCAL;	 // backward compatibility
  PF_OS2       = PF_UNIX;
  PF_INET      = AF_INET;
  PF_IMPLINK   = AF_IMPLINK;
  PF_PUP       = AF_PUP;
  PF_CHAOS     = AF_CHAOS;
  PF_NS        = AF_NS;
  PF_ISO       = AF_ISO;
  PF_OSI       = AF_OSI;
  PF_ECMA      = AF_ECMA;
  PF_DATAKIT   = AF_DATAKIT;
  PF_CCITT     = AF_CCITT;
  PF_SNA       = AF_SNA;
  PF_DECnet    = AF_DECnet;
  PF_DLI       = AF_DLI;
  PF_LAT       = AF_LAT;
  PF_HYLINK    = AF_HYLINK;
  PF_APPLETALK = AF_APPLETALK;
  PF_NETBIOS   = AF_NB;
  PF_NB        = AF_NB;
  PF_ROUTE     = AF_ROUTE;
  PF_LINK      = AF_LINK;
  PF_XTP       = pseudo_AF_XTP;  // really just proto family, no AF
  PF_COIP      = AF_COIP;
  PF_CNT       = AF_CNT;
  PF_SIP       = AF_SIP;
  PF_INET6     = AF_INET6;
  PF_IPX       = AF_IPX;	 // same format as AF_NS
  PF_RTIP      = pseudo_AF_RTIP; // same format as AF_INET
  PF_PIP       = pseudo_AF_PIP;

  PF_MAX       = AF_MAX;

{
 SOCE* constants - socket errors from NERRNO.H
 * All OS/2 SOCKET API error constants are biased by SOCBASEERR from the
   "normal"
}
const
  SOCBASEERR	     = 10000;

  SOCEPERM	     = (SOCBASEERR+1);	    // Not owner
  SOCENOENT	     = (SOCBASEERR+2);	    // No such file or directory
  SOCESRCH	     = (SOCBASEERR+3);	    // No such process
  SOCEINTR	     = (SOCBASEERR+4);	    // Interrupted system call
  SOCEIO	     = (SOCBASEERR+5);	    // Input/output error
  SOCENXIO	     = (SOCBASEERR+6);	    // No such device or address
  SOCE2BIG	     = (SOCBASEERR+7);	    // Argument list too long
  SOCENOEXEC	     = (SOCBASEERR+8);	    // Exec format error
  SOCEBADF	     = (SOCBASEERR+9);	    // Bad file number
  SOCECHILD	     = (SOCBASEERR+10);     // No child processes
  SOCEDEADLK	     = (SOCBASEERR+11);     // Resource deadlock avoided
  SOCENOMEM	     = (SOCBASEERR+12);     // Cannot allocate memory
  SOCEACCES	     = (SOCBASEERR+13);     // Permission denied
  SOCEFAULT	     = (SOCBASEERR+14);     // Bad address
  SOCENOTBLK	     = (SOCBASEERR+15);     // Block device required
  SOCEBUSY	     = (SOCBASEERR+16);     // Device busy
  SOCEEXIST	     = (SOCBASEERR+17);     // File exists
  SOCEXDEV	     = (SOCBASEERR+18);     // Cross-device link
  SOCENODEV	     = (SOCBASEERR+19);     // Operation not supported by device
  SOCENOTDIR	     = (SOCBASEERR+20);     // Not a directory
  SOCEISDIR	     = (SOCBASEERR+21);     // Is a directory
  SOCEINVAL	     = (SOCBASEERR+22);     // Invalid argument
  SOCENFILE	     = (SOCBASEERR+23);     // Too many open files in system
  SOCEMFILE	     = (SOCBASEERR+24);     // Too many open files
  SOCENOTTY	     = (SOCBASEERR+25);     // Inappropriate ioctl for device
  SOCETXTBSY	     = (SOCBASEERR+26);     // Text file busy
  SOCEFBIG	     = (SOCBASEERR+27);     // File too large
  SOCENOSPC	     = (SOCBASEERR+28);     // No space left on device
  SOCESPIPE	     = (SOCBASEERR+29);     // Illegal seek
  SOCEROFS	     = (SOCBASEERR+30);     // Read-only file system
  SOCEMLINK	     = (SOCBASEERR+31);     // Too many links
  SOCEPIPE	     = (SOCBASEERR+32);     // Broken pipe

// math software
  SOCEDOM	     = (SOCBASEERR+33);     // Numerical argument out of domain
  SOCERANGE	     = (SOCBASEERR+34);     // Result too large

// non-blocking and interrupt i/o
  SOCEAGAIN	     = (SOCBASEERR+35);     // Resource temporarily unavailable
  SOCEWOULDBLOCK     = SOCEAGAIN;	    // Operation would block
  SOCEINPROGRESS     = (SOCBASEERR+36);     // Operation now in progress
  SOCEALREADY	     = (SOCBASEERR+37);     // Operation already in progress

// ipc/network software -- argument errors
  SOCENOTSOCK	     = (SOCBASEERR+38);     // Socket operation on non-socket
  SOCEDESTADDRREQ    = (SOCBASEERR+39);     // Destination address required
  SOCEMSGSIZE	     = (SOCBASEERR+40);     // Message too long
  SOCEPROTOTYPE      = (SOCBASEERR+41);     // Protocol wrong type for socket
  SOCENOPROTOOPT     = (SOCBASEERR+42);     // Protocol not available
  SOCEPROTONOSUPPORT = (SOCBASEERR+43);     // Protocol not supported
  SOCESOCKTNOSUPPORT = (SOCBASEERR+44);     // Socket type not supported
  SOCEOPNOTSUPP      = (SOCBASEERR+45);     // Operation not supported
  SOCEPFNOSUPPORT    = (SOCBASEERR+46);     // Protocol family not supported
  SOCEAFNOSUPPORT    = (SOCBASEERR+47);     // Address family not supported by protocol family
  SOCEADDRINUSE      = (SOCBASEERR+48);     // Address already in use
  SOCEADDRNOTAVAIL   = (SOCBASEERR+49);     // Can't assign requested address

// ipc/network software -- operational errors
  SOCENETDOWN	     = (SOCBASEERR+50);     // Network is down
  SOCENETUNREACH     = (SOCBASEERR+51);     // Network is unreachable
  SOCENETRESET	     = (SOCBASEERR+52);     // Network dropped connection on reset
  SOCECONNABORTED    = (SOCBASEERR+53);     // Software caused connection abort
  SOCECONNRESET      = (SOCBASEERR+54);     // Connection reset by peer
  SOCENOBUFS	     = (SOCBASEERR+55);     // No buffer space available
  SOCEISCONN	     = (SOCBASEERR+56);     // Socket is already connected
  SOCENOTCONN	     = (SOCBASEERR+57);     // Socket is not connected
  SOCESHUTDOWN	     = (SOCBASEERR+58);     // Can't send after socket shutdown
  SOCETOOMANYREFS    = (SOCBASEERR+59);     // Too many references: can't splice
  SOCETIMEDOUT	     = (SOCBASEERR+60);     // Operation timed out
  SOCECONNREFUSED    = (SOCBASEERR+61);     // Connection refused

  SOCELOOP	     = (SOCBASEERR+62);     // Too many levels of symbolic links
  SOCENAMETOOLONG    = (SOCBASEERR+63);     // File name too long

// should be rearranged
  SOCEHOSTDOWN	     = (SOCBASEERR+64);      // Host is down
  SOCEHOSTUNREACH    = (SOCBASEERR+65);      // No route to host
  SOCENOTEMPTY	     = (SOCBASEERR+66);      // Directory not empty

// quotas & mush
  SOCEPROCLIM	     = (SOCBASEERR+67);      // Too many processes
  SOCEUSERS	     = (SOCBASEERR+68);      // Too many users
  SOCEDQUOT	     = (SOCBASEERR+69);      // Disc quota exceeded

// Network File System
  SOCESTALE	     = (SOCBASEERR+70);      // Stale NFS file handle
  SOCEREMOTE	     = (SOCBASEERR+71);      // Too many levels of remote in path
  SOCEBADRPC	     = (SOCBASEERR+72);      // RPC struct is bad
  SOCERPCMISMATCH    = (SOCBASEERR+73);      // RPC version wrong
  SOCEPROGUNAVAIL    = (SOCBASEERR+74);      // RPC prog. not avail
  SOCEPROGMISMATCH   = (SOCBASEERR+75);      // Program version wrong
  SOCEPROCUNAVAIL    = (SOCBASEERR+76);      // Bad procedure for program

  SOCENOLCK	     = (SOCBASEERR+77);      // No locks available
  SOCENOSYS	     = (SOCBASEERR+78);      // Function not implemented

  SOCEFTYPE	     = (SOCBASEERR+79);      // Inappropriate file type or format
  SOCEAUTH	     = (SOCBASEERR+80);      // Authentication error
  SOCENEEDAUTH	     = (SOCBASEERR+81);      // Need authenticator

  SOCEOS2ERR	     = (SOCBASEERR+100);     // OS/2 Error
  SOCELAST	     = (SOCBASEERR+100);     // Must be equal largest errno


// * Types
const

  SOCK_STREAM	 = 1; // stream socket
  SOCK_DGRAM	 = 2; // datagram socket
  SOCK_RAW	 = 3; // raw-protocol interface
  SOCK_RDM	 = 4; // reliably-delivered message
  SOCK_SEQPACKET = 5; // sequenced packet stream

// * Option flags per-socket.
const

  SO_DEBUG	  = $0001; // turn on debugging info recording
  SO_ACCEPTCONN   = $0002; // socket has had listen()
  SO_REUSEADDR	  = $0004; // allow local address reuse
  SO_KEEPALIVE	  = $0008; // keep connections alive
  SO_DONTROUTE	  = $0010; // just use interface addresses
  SO_BROADCAST	  = $0020; // permit sending of broadcast msgs
  SO_USELOOPBACK  = $0040; // bypass hardware when possible
  SO_LINGER	  = $0080; // linger on close if data present
  SO_OOBINLINE	  = $0100; // leave received OOB data in line
  SO_L_BROADCAST  = $0200; // limited broadcast sent on all IFs
  SO_RCV_SHUTDOWN = $0400; // set if shut down called for rcv
  SO_SND_SHUTDOWN = $0800; // set if shutdown called for send
  SO_REUSEPORT	  = $1000; // allow local address & port reuse
  SO_TTCP	  = $2000; // allow t/tcp on socket

// * Additional options, not kept in so_options.
const

  SO_SNDBUF   = $1001; // send buffer size
  SO_RCVBUF   = $1002; // receive buffer size
  SO_SNDLOWAT = $1003; // send low-water mark
  SO_RCVLOWAT = $1004; // receive low-water mark
  SO_SNDTIMEO = $1005; // send timeout
  SO_RCVTIMEO = $1006; // receive timeout
  SO_ERROR    = $1007; // get error status and clear
  SO_TYPE     = $1008; // get socket type
  SO_OPTIONS  = $1010; // get socket options

// * Structure used for manipulating linger option.
type

  linger = record
     l_onoff			       :  Longint; // option on/off
     l_linger			       :  Longint; // linger time
  end;

// * Level number for (get/set)sockopt() to apply to socket itself.
const

  SOL_SOCKET = $ffff; // options for socket level

{*
 * User-settable options (used with setsockopt).
 *}
  TCP_NODELAY	 = $01;    // don't delay send to coalesce packets
  TCP_MAXSEG	 = $02;    // set maximum segment size
  TCP_MSL	 = $03;    // MSL HACK
  TCP_TIMESTMP	 = $04;    // RFC 1323 (RTTM TimeStamp)
  TCP_WINSCALE	 = $05;    // RFC 1323 (Window Scale)
  TCP_CC	 = $06;    // RFC 1644 (Connection Count)


// * Structure used by kernel to store most
// * addresses.
type

  sockaddr = record
    sa_len:    Byte;		      // total length
    sa_family: Byte;		      // address family
    sa_data:   array [0..13] of Byte; // up to 14 bytes of direct address
  end;

  psockaddr = ^sockaddr;

// * Structure used by kernel to pass protocol
// * information in raw sockets.
type

  sockproto = record
    sp_family:	 SmallWord; // address family
    sp_protocol: SmallWord; // protocol
  end;

// * Maximum queue length specifiable by listen.
const

  SOMAXCONN = 1024;

// * Message header for recvmsg and sendmsg calls.
// * Used value-result for recvmsg, value only for sendmsg.
type

  iovec = record
    iov_base  :  Pointer;
    iov_len   :  Longint;
  end;

  msghdr = record
    msg_name:	    pChar;     // optional address
    msg_namelen:    Longint;   // size of address
    msg_iov:	    ^iovec;    // scatter/gather array
    msg_iovlen:     Longint;   // # elements in msg_iov (max 1024)
    msg_control:    pChar;     // ancillary data, see below
    msg_controllen: Longint;   // ancillary data buffer len
    msg_flags:	    Longint;   // flags on received message
  end;

const

  MSG_OOB	= $1;	// process out-of-band data
  MSG_PEEK	= $2;	// peek at incoming message
  MSG_DONTROUTE = $4;	// send without using routing tables
  MSG_FULLREAD	= $8;	// send without using routing tables
  MSG_EOR	= $10;	// data completes record
  MSG_TRUNC	= $20;	// data discarded before delivery
  MSG_CTRUNC	= $40;	// control data lost before delivery
  MSG_WAITALL	= $80;	// wait for full request or error
  MSG_DONTWAIT	= $100; // this message should be nonblocking
  MSG_EOF	= $200;
  MSG_MAPIO	= $400; // mem mapped io

// * Header for ancillary data objects in msg_control buffer.
// * Used for additional information with/about a datagram
// * not expressible by flags.	The format is a sequence
// * of message elements headed by cmsghdr structures.
type

  cmsghdr = record
    cmsg_len:	Longint;    // data byte count, including hdr
    cmsg_level: Longint;    // originating protocol
    cmsg_type:	Longint;    // protocol-specific type
  end;

// *** *** ***
  cmsg = record
    cmsg_hdr:  cmsghdr;
    cmsg_data: array [0..0] of Byte;
  end;
// *** *** ***

// * "Socket"-level control message types:
const
  SCM_RIGHTS = $01; // access rights (array of int)

// * 4.3 compat sockaddr, move to compat file later
type

  osockaddr = record
    sa_family: SmallWord;	    // address family
    sa_data: array [0..13] of Byte; // up to 14 bytes of direct address
  end;

// * 4.3-compat message header (move to compat file later).
type

  omsghdr = record
    msg_name:	      pChar;   // optional address
    msg_namelen:      Longint;	  // size of address
    msg_iov:	      ^iovec;  // scatter/gather array
    msg_iovlen:       Longint;	  // # elements in msg_iov
    msg_accrights:    pChar;   // access rights sent/received
    msg_accrightslen: Longint;
  end;

// * bsd select definitions

const
{
 * Select uses bit masks of file descriptors in longs.	These macros
 * manipulate such bit fields (the filesystem macros use chars).
 * FD_SETSIZE may be defined by the user, but the default here should
 * be enough for most uses.
}
  FD_SETSIZE = 64;

type

  fd_set = record
    fd_count  :  SmallWord;			      // how many are SET?
    fd_array  :  array[0..FD_SETSIZE-1] of Longint;   // an array of SOCKETs
  end;

  timeval = record
    tv_sec   :	Longint; // Number of seconds
    tv_usec  :	Longint; // Number of microseconds
  end;

{
 * Structures returned by network data base library.  All addresses are
 * supplied in host order, and returned in network order (suitable for
 * use in system calls).
}

type

  PLongint = ^Longint;

  { struct for gethostbyname() and gethostbyaddr() }
  hostent = record
    h_name	 :  PChar;	 // official name of host
    h_aliases	 :  ^PChar;	 // alias list
    h_addrtype	 :  Longint;	 // host address type
    h_length	 :  Longint;	 // length of address
    h_addr_list  :  ^PLongint;	 // list of addresses from name server
  end;

  phostent = ^hostent;

{
 * Error return codes from gethostbyname(), gethostbyaddr() and res_* funcs
 * (left in extern int h_errno).
}

const

  NETDB_INTERNAL  = -1;       // see errno
  NETDB_SUCCESS   =  0;       // no problem
  HOST_NOT_FOUND  =  1;       // Authoritative Answer Host not found
  TRY_AGAIN	  =  2;       // Non-Authoritive Host not found, or SERVERFAIL
  NO_RECOVERY	  =  3;       // Non recoverable errors, FORMERR, REFUSED, NOTIMP
  NO_DATA	  =  4;       // Valid name, no data record of requested type
  NO_ADDRESS	  =  NO_DATA; // no address, look for MX record

type

  { struct for getprotobyname() and getprotobynumber() }
  protoent = record
    p_name     :  PChar;	 // official protocol name
    p_aliases  :  ^PChar;	 // alias list
    p_proto    :  Longint;	 // protocol #
  end;

  pprotoent = ^protoent;

type

  { struct for getservbyname() and getservbyport() }
  servent = record
    s_name     :  PChar;	 // official service name
    s_aliases  :  ^PChar;	 // alias list
    s_port     :  Longint;	 // port # (need ntohl() !!)
    s_proto    :  PChar;	 // protocol to use
  end;

  pservent = ^servent;

{
 * ioctl & ip trace support
}
const
  SIOCGIFFLAGS		=  $6900 + 17;	// get interface flags

  { Interface Tracing Support }
  SIOCGIFEFLAGS 	=  $6900 + 150; // get interface enhanced flags
  SIOCSIFEFLAGS 	=  $6900 + 151; // set interface enhanced flags
  SIOCGIFTRACE		=  $6900 + 152; // get interface trace data
  SIOCSIFTRACE		=  $6900 + 153; // set interface trace data
  { sorry, i skip other ioctl commands, see SYS\ioctl.h from toolkit for it.. }

  IFF_UP		=  $1;		// interface is up
  IFF_BROADCAST 	=  $2;		// broadcast address valid
  IFF_DEBUG		=  $4;		// turn on debugging
  IFF_LOOPBACK		=  $8;		// is a loopback net
  IFF_POINTOPOINT	=  $10; 	// interface is point-to-point link
  IFF_LINK2		=  $20; 	// was trailers, not used
  IFF_NOTRAILERS	=  IFF_LINK2;
  IFF_RUNNING		=  $40; 	// resources allocated
  IFF_NOARP		=  $80; 	// no address resolution protocol
  IFF_PROMISC		=  $100;	// receive all packets
  IFF_ALLMULTI		=  $200;	// receive all multicast packets
  IFF_BRIDGE		=  $1000;	// support token ring routine field
  IFF_SNAP		=  $2000;	// support extended SAP header
  IFF_DEFMTU		=  $400;	// default mtu of 1500
  IFF_RFC1469_BC	=  1;		// using broadcast
  IFF_RFC1469_FA	=  2;		// using functional
  IFF_RFC1469_MA	=  3;		// using multicast
  IFF_ETHER		=  $4000;	// Ethernet interface
  IFF_LOOPBRD		=  $8000;	// loop back broadcasts
  IFF_MULTICAST 	=  $800;	// supports multicast

  IFF_SIMPLEX		=  $10000;	// can't hear own transmissions
  IFF_OACTIVE		=  $20000;	// transmission in progress
  IFF_802_3		=  $40000;
  IFF_CANONICAL 	=  $80000;
  IFF_RUNNINGBLK	=  $100000;	// threads waited for intf running

  { Interface enhanced flags }
  IFFE_PKTTRACE 	=  $00000001;	// trace datalink where possible
  IFFE_IPTRACE		=  $00000002;	// trace ONLY IP packets

type
  { trace buffer struct }
  pkt_trace_hdr = record
     pt_htype		:  SmallWord;	// header type
     pt_len		:  SmallWord;	// in: pt_buf len, out: packet len
     pt_data		:  Pointer;	// packet
     pt_tstamp		:  Longint;	// time stamp in milliseconds
  end;

const
  { physical protocols IDs }
  HT_IP 		=  $01;  // IP
  HT_ETHER		=  $06;  // Ethernet
  HT_ISO88023		=  $07;  // CSMA CD
  HT_ISO88025		=  $09;  // Token Ring
  HT_SLIP		=  $1c;  // Serial Line IP
  HT_PPP		=  $18;  // PPP IP

const
  IFNAMSIZ		=  16;	 // interface name length

type
{
* Interface request structure used for socket
* ioctl's.  All interface ioctl's must have parameter
* definitions which begin with ifr_name.  The
* remainder may be interface specific.
}
  ifreq = record
     ifr_name		:  array[0..IFNAMSIZ-1] of Char;
     case Byte of
     0: (ifr_addr	:  sockaddr);  // address
     1: (ifr_dstaddr	:  sockaddr);  // other end of p-to-p link
     2: (ifr_broadaddr	:  sockaddr);  // broadcast address
     3: (ifr_flags	:  SmallWord); // flags
     4: (ifr_metric	:  Longint);   // metric
     5: (ifr_data	:  Pointer);   // for use by interface
     6: (ifr_eflags	:  Longint);   // eflags
  end;


{ --- inet* funcs from TCP32DLL.DLL --- }

{ * stupid checkings for network addrs }

function  IN_CLASSA(i:Longint):Boolean; inline;
Begin
   IN_CLASSA:=(((i) and $80000000) = 0);
end;

function  IN_CLASSB(i:Longint):Boolean; inline;
Begin
   IN_CLASSB:=(((i) and $c0000000) = $80000000);
end;

function  IN_CLASSC(i:Longint):Boolean; inline;
Begin
   IN_CLASSC:=(((i) and $e0000000) = $c0000000);
end;

function  IN_CLASSD(i:Longint):Boolean; inline;
Begin
   IN_CLASSD:=(((i) and $f0000000) = $e0000000);
end;

function  IN_MULTICAST(i:Longint):Boolean; inline;
Begin
   IN_MULTICAST:=(((i) and $f0000000) = $e0000000);
end;

function  IN_EXPERIMENTAL(i:Longint):Boolean; inline;
Begin
   IN_EXPERIMENTAL:=(((i) and $e0000000) = $e0000000);
end;

function  IN_BADCLASS(i:Longint):Boolean; inline;
Begin
   IN_BADCLASS:=(((i) and $f0000000) = $f0000000);
end;


{ * convertions of inet host/strings/etc }

{$saves ebx,esi,edi}
function  inet_addr(const ip_str:PChar):Longint;
{ ip addr str -> 4 byte ip addr }

{$saves ebx,esi,edi}
procedure inet_makeaddr(var net_addr:Longint; host_addr:Longint);
{ fucking shit ;) see docs for more info }

{$saves ebx,esi,edi}
function  inet_network(const net_str:PChar):Longint;
{ net addr str -> 4 byte net addr }

{$saves ebx,esi,edi}
function  inet_ntoa(inet_addr:Longint):PChar;
{ 4 byte ip addr -> ip addr str }

{$saves ebx,esi,edi}
function  inet_lnaof(inet_addr:Longint):Longint;
{ return local part of network addr }

{$saves ebx,esi,edi}
function  inet_netof(inet_addr:Longint):Longint;
{ return network part of network addr }

{&Cdecl-}

{$uses none} {$saves all}
function  LSwap(a:Longint):Longint;
{$uses none} {$saves all}
function  WSwap(a:SmallWord):SmallWord;

function  htonl(a:Longint):Longint; inline;
begin	Result:=LSwap(a);   end;
{ host -> network for long (4 bytes) }

function  ntohl(a:Longint):Longint; inline;
begin	Result:=LSwap(a);   end;
{ network -> host for long (4 bytes) }

function  htons(a:SmallWord):SmallWord; inline;
begin	Result:=WSwap(a);   end;
{ host -> network for small (2 bytes) }

function  ntohs(a:SmallWord):SmallWord; inline;
begin	Result:=WSwap(a);   end;
{ network -> host for small (2 bytes) }

{&Cdecl+}


{ --- resolver & proto/services funcs ---}

{$saves ebx,esi,edi}
function  h_errno:Longint;
{ return last resolv error code.
  only for gethostbyname(), gethostbyaddr() and res_* }

{$saves ebx,esi,edi}
function  gethostbyname(const hostname:PChar):phostent;
{ return pointer to hostent record by name }

{$saves ebx,esi,edi}
function  gethostbyaddr(var hostaddr:Longint;
			addrlen, addrfam:Longint):phostent;
{ return pointer to hostent record by addr }

{$saves ebx,esi,edi}
function  getprotobyname(const protoname:PChar):pprotoent;
{ return pointer to protoent by proto name }

{$saves ebx,esi,edi}
function  getprotobynumber(protonumber:Longint):pprotoent;
{ return pointer to protoent by proto number }

{$saves ebx,esi,edi}
function  getservbyname(const servname,protoname:PChar):pservent;
{ return pointer to servent by service name }

{$saves ebx,esi,edi}
function  getservbyport(port_num:Longint; const protoname:PChar):pservent;
{ return pointer to servent by service port }

{$saves ebx,esi,edi}
function  gethostname(var hostname; namelen:Longint):Longint;
{ return current hostname to buf, max lenght = namelen;
  0 - ok, -1 - err }


{ --- sock* funcs from SO32DLL.DLL --- }


{ * init / misc funcs }

{$saves ebx,esi,edi}
function  sock_init:Longint;
{ init sockets system }

{$saves ebx,esi,edi}
function  getinetversion(var version):Longint;
{ get inet version. version - buffer of ?? size for returned string. }


{ * sockets errors reporting funcs }

{$saves ebx,esi,edi}
function  sock_errno:Longint;
{ last err code for this thread }

{$saves ebx,esi,edi}
procedure psock_errno(const str:PChar);
{ print last err string + str if not NIL }


{ * sockets creation / close funcs }

{$saves ebx,esi,edi}
function  socket(domain,stype,protocol:Longint):Longint;
{ create new socket }

{$saves ebx,esi,edi}
function  soclose(sock:Longint):Longint;
{ close socket }

{$saves ebx,esi,edi}
function  so_cancel(sock:Longint):Longint;
{ cancel socket }

{$saves ebx,esi,edi}
function  shutdown(sock,howto:Longint):Longint;
{ shutdown socket. howto: 0/1/2 }

{$saves ebx,esi,edi}
function  soabort(sock:Longint):Longint;
{ abort socket. no docs found about it :( }


{ * sockets connection funcs }

{$saves ebx,esi,edi}
function  accept(sock:Longint; s_addr:psockaddr;
		 s_addr_len:PLongint):Longint;
{ accept a connection from remote host.
  returns s_addr & s_addr_len if not nil }

{$saves ebx,esi,edi}
function  bind(sock:Longint; var s_addr:sockaddr; s_addr_len:Longint):Longint;
{ bind a local name to the socket }

{$saves ebx,esi,edi}
function  connect(sock:Longint; var s_addr:sockaddr;
		  s_addr_len:Longint):Longint;
{ connect socket to remote host }

{$saves ebx,esi,edi}
function  listen(sock,max_conn:Longint):Longint;
{ listen on socket. max_conn - queue size of listen. }


{ * sockets read/write funcs }

{$saves ebx,esi,edi}
function  recv(sock:Longint; var buf; buf_len,flags:Longint):Longint;
{ read data from socket. ! return N of readed bytes, or 0 (closed) or -1 }

{$saves ebx,esi,edi}
function  send(sock:Longint; var buf; buf_len,flags:Longint):Longint;
{ send data to socket. ! return N of sent bytes. -1 - err }

{$saves ebx,esi,edi}
function  recvfrom(sock:Longint; var buf; buf_len,flags:Longint;
		   var s_addr:sockaddr; var s_addr_len:Longint):Longint;
{ read data from socket. ! return N of readed bytes, or 0 (closed) or -1 }

{$saves ebx,esi,edi}
function  sendto(sock:Longint; var buf; buf_len,flags:Longint;
		 var s_addr:sockaddr; s_addr_len:Longint):Longint;
{ send data to socket. ! return N of sent bytes. -1 - err }

{$saves ebx,esi,edi}
function  readv(sock:Longint; var iov:iovec; iov_count:Longint):LONGINT;
{ read data into iov_count number of buffers iov.
  ! return N of readed bytes, or 0 (closed) or -1 }

{$saves ebx,esi,edi}
function  writev(sock:Longint; var iov:iovec; iov_count:Longint):LONGINT;
{ write data from iov_count number of buffers iov.
  ! return N of writed bytes, or -1 }

{$saves ebx,esi,edi}
function  recvmsg(sock:Longint; var msgbuf:msghdr; flags:Longint):Longint;
{ read data + control info from socket
  ! return N of readed bytes, or 0 (closed) or -1 }

{$saves ebx,esi,edi}
function  sendmsg(sock:Longint; var msgbuf:msghdr; flags:Longint):Longint;
{ send data + control info to socket
  ! return N of sended bytes, or -1 }


{ * select funcs }

{$saves ebx,esi,edi}
function  os2_select(var sockets;
		     N_reads, N_writes, N_exepts, timeout:Longint):Longint;
{ OS/2 select. 0 - timeout. -1 - err. XX - N of sockets worked. }

{$saves ebx,esi,edi}
function  select(nfds:Longint;
		 const readfds,writefds,exceptfds:fd_set;
		 const timeout:timeval):Longint;
{ bsd select here. heavy voodoo.. }


{ * misc info }

{$saves ebx,esi,edi}
function  gethostid:Longint;
{ get host ip addr - addr of primary interface }

{$saves ebx,esi,edi}
function  getpeername(sock:Longint; var s_addr:sockaddr;
		      var s_addr_len:Longint):Longint;
{ get connected to socket hostname }

{$saves ebx,esi,edi}
function  getsockname(sock:Longint; var s_addr:sockaddr;
		      var s_addr_len:Longint):Longint;
{ get local socket name }


{ * options & ioctls }

{$saves ebx,esi,edi}
function  getsockopt(sock,level,optname:Longint;
		     var buf; var buf_len:Longint):Longint;
{ get socket options }

{$saves ebx,esi,edi}
function  setsockopt(sock,level,optname:Longint;
		     const buf; buf_len:Longint):Longint;
{ set socket options }

{$saves ebx,esi,edi}
function  os2_ioctl(sock,cmd:Longint; var data; data_len:Longint):Longint;
{ f@$king ioctl. use sys/ioctl.h }


{ * functions only for 4.1+ ip stacks (bat also found in 4.02w ;)) }

{$saves ebx,esi,edi}
function  addsockettolist(sock:Longint):Longint;

{$saves ebx,esi,edi}
function  removesocketfromlist(sock:Longint):Longint;

implementation

function  LSwap(a:Longint):Longint; assembler;
asm
      mov   eax,a
      xchg  ah,al
      ror   eax,16
      xchg  ah,al
end;

function  WSwap(a:SmallWord):SmallWord; assembler;
asm
      mov   ax,a
      xchg  ah,al
end;

function  inet_addr; external;	       { TCP32DLL@5 }
function  inet_lnaof; external;        { TCP32DLL@6 }
function  inet_netof; external;        { TCP32DLL@7 }
procedure inet_makeaddr; external;     { TCP32DLL@8 }
function  inet_network; external;      { TCP32DLL@9 }
function  inet_ntoa; external;	       { TCP32DLL@10 }
function  gethostbyname; external;     { TCP32DLL@11 }
function  gethostbyaddr; external;     { TCP32DLL@12 }
function  getprotobyname; external;    { TCP32DLL@21 }
function  getprotobynumber; external;  { TCP32DLL@22 }
function  getservbyport; external;     { TCP32DLL@23 }
function  getservbyname; external;     { TCP32DLL@24 }
function  gethostname; external;       { TCP32DLL@44 }
function  h_errno; external;	       { TCP32DLL@51 } { TCP_H_ERRNO in real life }


function  accept; external;		     { SO32DLL@1 }
function  bind; external;		     { SO32DLL@2 }
function  connect; external;		     { SO32DLL@3 }
function  gethostid; external;		     { SO32DLL@4 }
function  getpeername; external;	     { SO32DLL@5 }
function  getsockname; external;	     { SO32DLL@6 }
function  getsockopt; external; 	     { SO32DLL@7 }
function  os2_ioctl; external;		     { SO32DLL@8 }
function  listen; external;		     { SO32DLL@9 }
function  recv; external;		     { SO32DLL@10 }
function  recvfrom; external;		     { SO32DLL@11 }
function  os2_select; external; 	     { SO32DLL@12 }
function  send; external;		     { SO32DLL@13 }
function  sendto; external;		     { SO32DLL@14 }
function  setsockopt; external; 	     { SO32DLL@15 }
function  socket; external;		     { SO32DLL@16 }
function  soclose; external;		     { SO32DLL@17 }
function  so_cancel; external;		     { SO32DLL@18 }
function  soabort; external;		     { SO32DLL@19 }
function  sock_errno; external; 	     { SO32DLL@20 }
function  recvmsg; external;		     { SO32DLL@21 }
function  sendmsg; external;		     { SO32DLL@22 }
function  readv; external;		     { SO32DLL@23 }
function  writev; external;		     { SO32DLL@24 }
function  shutdown; external;		     { SO32DLL@25 }
function  sock_init; external;		     { SO32DLL@26 }
function  addsockettolist; external;	     { SO32DLL@27 }
function  removesocketfromlist; external;    { SO32DLL@28 }
{ entry 29 not used }
procedure psock_errno; external;	     { SO32DLL@30 }
function  getinetversion; external;	     { SO32DLL@31 }
function  select; external;		     { SO32DLL@32 }





end.


