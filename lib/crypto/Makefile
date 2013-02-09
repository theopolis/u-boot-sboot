# Copyright 2012 Teddy Reed

include $(TOPDIR)/config.mk

LIB	= $(obj)libcrypto.o

SOBJS	=

COBJS-$(CONFIG_CRYPTO) += padding.o rsa.o

COBJS	= $(COBJS-y)
SRCS 	:= $(SOBJS:.o=.S) $(COBJS:.o=.c)
OBJS	:= $(addprefix $(obj),$(SOBJS) $(COBJS))

$(LIB):	$(obj).depend $(OBJS)
	$(call cmd_link_o_target, $(OBJS))

#########################################################################

# defines $(obj).depend target
include $(SRCTREE)/rules.mk

sinclude $(obj).depend

#########################################################################
