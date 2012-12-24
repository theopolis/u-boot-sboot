# Copyright 2012 Teddy Reed

include $(TOPDIR)/config.mk

LIB	= $(obj)libtlcl.o

SOBJS	=

COBJS-$(CONFIG_TPM) += oiaposap.o tlcl.o

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
