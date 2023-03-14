#include "NetVCOptions.h"
#include "I_Net.h"
#include "I_Socks.h"

void
NetVCOptions::reset()
{
  ip_proto  = USE_TCP;
  ip_family = AF_INET;
  local_ip.invalidate();
  local_port    = 0;
  addr_binding  = ANY_ADDR;
  socks_support = NORMAL_SOCKS;
  socks_version = SOCKS_DEFAULT_VERSION;
  socket_recv_bufsize =
#if defined(RECV_BUF_SIZE)
    RECV_BUF_SIZE;
#else
    0;
#endif
  socket_send_bufsize  = 0;
  sockopt_flags        = 0;
  packet_mark          = 0;
  packet_tos           = 0;
  packet_notsent_lowat = 0;

  etype = ET_NET;

  sni_servername              = nullptr;
  ssl_servername              = nullptr;
  sni_hostname                = nullptr;
  ssl_client_cert_name        = nullptr;
  ssl_client_private_key_name = nullptr;
  outbound_sni_policy         = nullptr;
}

void
NetVCOptions::set_sock_param(int _recv_bufsize, int _send_bufsize, unsigned long _opt_flags, unsigned long _packet_mark,
                             unsigned long _packet_tos, unsigned long _packet_notsent_lowat)
{
  socket_recv_bufsize  = _recv_bufsize;
  socket_send_bufsize  = _send_bufsize;
  sockopt_flags        = _opt_flags;
  packet_mark          = _packet_mark;
  packet_tos           = _packet_tos;
  packet_notsent_lowat = _packet_notsent_lowat;
}
