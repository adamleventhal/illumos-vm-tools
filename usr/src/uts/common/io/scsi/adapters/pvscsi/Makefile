#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
#

# Makefile for building standalone version of VMWare PVSCSI driver.
# FIXME: Currently only 32-bit version of the VWware PVSCSI driver is built.
CFLAGS= -D_KERNEL -mno-red-zone -ffreestanding -nodefaultlibs -Wall -g
LDFLAGS= -r -dy -Nmisc/scsi -Ndrv/scsi_vhci

CC=gcc
LD=/usr/ccs/bin/ld

SOURCES=os_vmw_pvscsi.c tests.c
OBJECTS=$(SOURCES:%.c=%.o)
TARGET=os_vmw_pvscsi

.c.o: $(CC) -c $< -o $@

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) $(OBJECTS)