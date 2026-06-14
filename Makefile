PLUGIN_NAME=		kea-ubnd-ddns
PLUGIN_VERSION=		0.9
PLUGIN_COMMENT=		Kea DHCP to Unbound DNS registration (DDNS bridge)
PLUGIN_DEPENDS=		py313-dnspython
PLUGIN_MAINTAINER=	tk@rgn.ltd
PLUGIN_WWW=		https://github.com/tkreagan/os-kea-ubnd-ddns
PLUGIN_NO_ABI=		yes
PLUGIN_TIER=		3

# Built within an opnsense/plugins tree (category/net/kea-ubnd-ddns/Makefile),
# where Mk/plugins.mk lives two directories up.
.include "../../Mk/plugins.mk"
