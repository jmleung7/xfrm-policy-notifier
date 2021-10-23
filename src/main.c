#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/types.h>
#include <netlink/xfrm/sp.h>
#include <netlink/xfrm/selector.h>

int parse_nlmsg(struct nl_msg*, void*);
void parse_sp(struct nlmsghdr*);

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);

    struct nl_sock *sk = nl_socket_alloc();

    nl_socket_disable_seq_check(sk);
    nl_socket_modify_cb(sk, NL_CB_MSG_IN, NL_CB_CUSTOM, parse_nlmsg, NULL);
    nl_connect(sk, NETLINK_XFRM);
    nl_socket_add_memberships(sk, XFRMNLGRP_POLICY, 0);

    while (1)
        nl_recvmsgs_default(sk);

    return 0;
}

int parse_nlmsg(struct nl_msg* msg, void *arg) {
    struct nlmsghdr* nlhdr = nlmsg_hdr(msg);
    int len = nlhdr->nlmsg_len;

    for (nlhdr; NLMSG_OK(nlhdr, len); nlhdr = NLMSG_NEXT(nlhdr, len)) {
        switch (nlhdr->nlmsg_type) {
            case XFRM_MSG_GETPOLICY:
            case XFRM_MSG_NEWPOLICY:
            case XFRM_MSG_DELPOLICY:
            case XFRM_MSG_MIGRATE:
            case XFRM_MSG_FLUSHPOLICY:
                break;
            case XFRM_MSG_UPDPOLICY:
                parse_sp(nlhdr);
                break;
            default:
                break;
        }
    }

    return 0;
}

void parse_sp(struct nlmsghdr* nlh) {
    char src_address[64];
    char dst_address[64];

    struct xfrmnl_sp* sp = xfrmnl_sp_alloc();
    xfrmnl_sp_parse(nlh, &sp);

    struct xfrmnl_sel* sel = xfrmnl_sp_get_sel(sp);
    struct nl_addr* src_nladdr = xfrmnl_sel_get_saddr(sel);
    struct nl_addr* dst_nladdr = xfrmnl_sel_get_daddr(sel);

    if (nl_addr_get_prefixlen(src_nladdr) == 0 || nl_addr_get_prefixlen(dst_nladdr) == 0) {
        return;
    } else {
        if (xfrmnl_sp_get_dir(sp) != XFRM_POLICY_OUT) return;
        nl_addr2str(src_nladdr, src_address, 64);
        nl_addr2str(dst_nladdr, dst_address, 64);

        printf("src [%s](%d/%d) dest [%s](%d/%d) proto %d\n",
                src_address, xfrmnl_sel_get_sport(sel), xfrmnl_sel_get_sportmask(sel),
                dst_address, xfrmnl_sel_get_dport(sel), xfrmnl_sel_get_dportmask(sel),
                xfrmnl_sel_get_proto(sel));
    }

    nl_object_free((struct nl_object*)sp);
}