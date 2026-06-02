PLUGIN_NAME=		kea-unbound
PLUGIN_VERSION=		0.9
PLUGIN_COMMENT=		Kea DHCP to Unbound DNS registration (DDNS bridge)
PLUGIN_DEPENDS=		py313-dnspython
PLUGIN_MAINTAINER=	tkr@tkr.net
PLUGIN_WWW=		https://github.com/tkreagan/os-kea-unbound

# Built within an opnsense/plugins tree (category/os-kea-unbound/Makefile),
# where Mk/plugins.mk lives two directories up.
.include "../../Mk/plugins.mk"
