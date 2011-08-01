/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/modctl.h>  /* used by _init, _info, _fini */
#include <sys/cmn_err.h> /* used by all entry points for this driver */
#include <sys/ddi.h>     /* used by all entry points for this driver */
#include <sys/sunddi.h>  /* used by all entry points for this driver */
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/scsi/scsi.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/atomic.h>
#include <sys/list.h>

#pragma pack(1)
#include "vmw_pvscsi.h"
#pragma pack()

typedef struct pv_dma_buf {
        ddi_dma_handle_t dma_handle;
        caddr_t addr; /* Virtual address. */
        uint64_t pa;  /* Physical address. */
        size_t real_length;
        ddi_acc_handle_t acc_handle;
} pv_dma_buf_t;

#define VMW_PVSCSI_TGT_PRIV_SIZE 2

enum {
        VMW_PVSCSI_CMD_CDB_EXT = 0x0001,
        VMW_PVSCSI_CMD_SCB_EXT = 0x0002,
        VMW_PVSCSI_CMD_PRIV_EXT = 0x0004,
        VMW_PVSCSI_CMD_TAG = 0x0008,
        VMW_PVSCSI_CMD_IO_READ = 0x0010,
        VMW_PVSCSI_CMD_IO_WRITE = 0x0020,

        VMW_PVSCSI_CMD_IO = (VMW_PVSCSI_CMD_IO_READ |
                             VMW_PVSCSI_CMD_IO_WRITE),
        VMW_PVSCSI_CMD_EXT = (VMW_PVSCSI_CMD_CDB_EXT |
                              VMW_PVSCSI_CMD_SCB_EXT |
                              VMW_PVSCSI_CMD_PRIV_EXT)
};

struct vmw_pvscsi_cmd;

typedef struct vmw_pvscsi_cmd_ctx {
        pv_dma_buf_t dma_buf;
        struct vmw_pvscsi_cmd *cmd;
        list_node_t list;
} vmw_pvscsi_cmd_ctx_t;

typedef struct vmw_pvscsi_cmd {
        struct scsi_pkt *pkt;
        uchar_t cmd_cdb[SCSI_CDB_SIZE];
        struct scsi_arq_status cmd_scb;
        uint64_t tgt_priv[VMW_PVSCSI_TGT_PRIV_SIZE];
        size_t tgtlen;
        size_t cmdlen;
        size_t statuslen;
        unsigned char tag;
        int flags;
        vmw_pvscsi_cmd_ctx_t *ctx;
        ddi_dma_handle_t cmd_handle;
        struct scsi_pkt cached_pkt;
} vmw_pvscsi_cmd_t;

#define PKT2CMD(pkt) ((vmw_pvscsi_cmd_t *)((pkt)->pkt_ha_private))

#define CMD_CTX_SGLIST_VA(cmd_ctx) ((struct PVSCSISGElement *)(((vmw_pvscsi_cmd_ctx_t *)(cmd_ctx))->dma_buf.addr))
#define CMD_CTX_SGLIST_PA(cmd_ctx) ((caddr_t)(((vmw_pvscsi_cmd_ctx_t *)(cmd_ctx))->dma_buf.pa))

#define CMD_CACHE_ITEM_SIZE (sizeof(vmw_pvscsi_cmd_t))

typedef struct vmw_pvscsi_softstate {
        dev_info_t  *m_dip;
        int         m_instance;
        scsi_hba_tran_t	*m_tran;
        ddi_dma_attr_t m_msg_dma_attr; /* Used for message frames */
        ddi_dma_attr_t ring_dma_attr; /* Used for SG map. */
        ddi_dma_attr_t io_dma_attr; /* Used for I/O that uses buffers. */
        pv_dma_buf_t rings_state_buf;
        pv_dma_buf_t req_ring_buf;
        unsigned int req_pages, req_depth;
        pv_dma_buf_t cmp_ring_buf;
        unsigned int cmp_pages;
        pv_dma_buf_t msg_ring_buf;
        unsigned int msg_pages;
        ddi_acc_handle_t pci_config_handle;
        ddi_acc_handle_t mmio_handle;
        caddr_t mmio_base;
        int use_msg;
        int msi_enable;
        int irq_type;
        int intr_size;
        int intr_cnt;
        int intr_pri;
        ddi_intr_handle_t *intr_htable;
        vmw_pvscsi_cmd_ctx_t *cmd_ctx;
        list_t cmd_ctx_pool;
        kmutex_t mtx;
        struct kmem_cache *cmd_cache;
        int num_luns;
} vmw_pvscsi_softstate_t;

#define REQ_RING(pvs) ((struct PVSCSIRingReqDesc *)(((vmw_pvscsi_softstate_t *)(pvs))->req_ring_buf.addr))
#define CMP_RING(pvs) ((struct PVSCSIRingCmpDesc *)(((vmw_pvscsi_softstate_t *)(pvs))->cmp_ring_buf.addr))
#define MSG_RING(pvs) ((struct PVSCSIRingMsgDesc *)(((vmw_pvscsi_softstate_t *)(pvs))->msg_ring_buf.addr))
#define RINGS_STATE(pvs) ((struct PVSCSIRingsState *)(((vmw_pvscsi_softstate_t *)(pvs))->rings_state_buf.addr))

#define PVSCSI_DEFAULT_NUM_PAGES_PER_RING 8

#define VMW_PVSCSI_SSTATE_SIZE (sizeof(struct vmw_pvscsi_softstate))
#define VMW_PVSCSI_INITIAL_SSTATE_ITEMS 16

#define _DBG(fmt, args...) cmn_err(CE_NOTE, "PVSCSI: " fmt "\n", ##args)
#define _LOG(fmt, args...) cmn_err(CE_NOTE, "PVSCSI: " fmt "\n", ##args)
#define _DBG_FUN() _LOG("%s: START", __FUNCTION__)
#define _ERR_FUN(e) do {_DBG_FUN(); return (e);} while(0)

#define	VMW_PVSCSI_MOD_STRING "VMware PVSCSI HBA Driver"

static int vmw_pvscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int vmw_pvscsi_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int vmw_pvscsi_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
                            int *rval);
static int vmw_pvscsi_power(dev_info_t *dip, int component, int level);
static int vmw_pvscsi_quiesce(dev_info_t *devi);

static struct cb_ops vmw_pvscsi_cb_ops = {
	scsi_hba_open,		/* open */
	scsi_hba_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	vmw_pvscsi_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops vmw_pvscsi_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	vmw_pvscsi_attach,		/* attach */
	vmw_pvscsi_detach,		/* detach */
	nodev,			/* reset */
	&vmw_pvscsi_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	vmw_pvscsi_power,		/* power management */
#ifdef	__sparc
	ddi_quiesce_not_needed
#else
	vmw_pvscsi_quiesce		/* quiesce */
#endif	/* __sparc */
};

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module. This one is a driver */
	VMW_PVSCSI_MOD_STRING, /* Name of the module. */
	&vmw_pvscsi_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

static int vmw_pvscsi_ring_pages = PVSCSI_DEFAULT_NUM_PAGES_PER_RING;
static int vmw_pvscsi_use_msg = 1;

static void *vmw_pvscsi_sstate;

/* TODO: Check DMA attributes. */
/* DMA attributes for pre-allocated rx/tx buffers */
static ddi_dma_attr_t vmw_pvscsi_msg_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	512,			/* granularity */
        0,	/* dma_attr_flags */
};

/* DMA attributes for rings. */
static ddi_dma_attr_t vmw_pvscsi_ring_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
        0,	/* dma_attr_flags */
};

#define VMW_PVSCSI_MAX_IO_SIZE (64 * 1024) /* 64 KB */

/* DMA attributes for buffer I/O */
static ddi_dma_attr_t vmw_pvscsi_io_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffULL,	/* maximum segment length */
	17,			/* maximum number of segments */
	512,			/* granularity */
        0,	/* dma_attr_flags */
};

static ddi_device_acc_attr_t vmw_pvscsi_mmio_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * Notes:
 *	- scsi_hba_init(9F) initializes SCSI HBA modules
 *	- must call scsi_hba_fini(9F) if modload() fails
 */
int _init(void)
{
  int status;

  _DBG("_init(): START");

  status = ddi_soft_state_init(&vmw_pvscsi_sstate, VMW_PVSCSI_SSTATE_SIZE,
                               VMW_PVSCSI_INITIAL_SSTATE_ITEMS);
  if (status != 0) {
    _LOG("ddi_soft_state_init() failed.");
    return (status);
  }

  if ((status = scsi_hba_init(&modlinkage)) != 0) {
    _LOG("scsi_hba_init() failed.");
    ddi_soft_state_fini(&vmw_pvscsi_sstate);
    return (status);
  }

  if ((status = mod_install(&modlinkage)) != 0) {
    _LOG("mod_install() failed.");
    ddi_soft_state_fini(&vmw_pvscsi_sstate);
    scsi_hba_fini(&modlinkage);
  }

  _DBG("_init(): DONE.");
  return (status);
}

int _info(struct modinfo *modinfop)
{
  _DBG("_info(): START");
  return (mod_info(&modlinkage, modinfop));
}

int _fini(void)
{
  int	status;

  _DBG("_fini(): START");
  if ((status = mod_remove(&modlinkage)) == 0) {
    ddi_soft_state_fini(&vmw_pvscsi_sstate);
    scsi_hba_fini(&modlinkage);
  }

  return (status);
}

static uint32_t vmw_pvscsi_reg_read(vmw_pvscsi_softstate_t *pvs, u32 offset)
{
        uint32_t r;

        ASSERT((offset & (sizeof(uint32_t)-1)) == 0);

        r = ddi_get32(pvs->mmio_handle, (uint32_t *)(pvs->mmio_base + offset));
        membar_consumer();
        return r;
}

static void vmw_pvscsi_reg_write(const vmw_pvscsi_softstate_t *pvs,
                                 u32 offset, u32 value)
{
        ASSERT((offset & (sizeof(uint32_t)-1)) == 0);

        ddi_put32(pvs->mmio_handle, (uint32_t *)(pvs->mmio_base + offset), value);
        membar_producer();
}

static void vmw_pvscsi_write_cmd_desc(const vmw_pvscsi_softstate_t *pvs,
                                      u32 cmd, const void *desc, size_t len)
{
	const u32 *ptr = desc;
	size_t i;

	len /= sizeof(*ptr);
	vmw_pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_COMMAND, cmd);
	for (i = 0; i < len; i++) {
		vmw_pvscsi_reg_write(pvs,
                                     PVSCSI_REG_OFFSET_COMMAND_DATA, ptr[i]);
        }
}

static uint32_t vmw_pvscsi_read_intr_status(vmw_pvscsi_softstate_t *pvs)
{
	return vmw_pvscsi_reg_read(pvs, PVSCSI_REG_OFFSET_INTR_STATUS);
}

static void vmw_pvscsi_write_intr_status(const vmw_pvscsi_softstate_t *pvs,
				     uint32_t val)
{
	vmw_pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_STATUS, val);
}

static void vmw_pvscsi_hba_reset(vmw_pvscsi_softstate_t *pvs)
{
        _LOG("Resetting PVSCSI HBA.");
        vmw_pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_ADAPTER_RESET, NULL, 0);
}

static int vmw_pvscsi_iport_attach(dev_info_t *dip)
{
        _DBG_FUN();
        return DDI_SUCCESS;
}

static int
vmw_pvscsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
                    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
        _ERR_FUN(DDI_FAILURE);
}

static void
vmw_pvscsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
                     scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
        _DBG_FUN();
}

static void vmw_pvscsi_submit_nonrw_io(vmw_pvscsi_softstate_t *pvs)
{
        _LOG("* NON-RW I/O");
	vmw_pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_KICK_NON_RW_IO, 0);
}

static void vmw_pvscsi_submit_rw_io(vmw_pvscsi_softstate_t *pvs)
{
        _LOG("* RW I/O");
	vmw_pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_KICK_RW_IO, 0);
}

#define scsi_is_rw(pkt) 0

static void vmw_pvscsi_submit_command(vmw_pvscsi_softstate_t *pvs,
                                      vmw_pvscsi_cmd_t *cmd)
{
	if (scsi_is_rw(pkt)) {
		vmw_pvscsi_submit_rw_io(pvs);
        } else {
                vmw_pvscsi_submit_nonrw_io(pvs);
        }
}

static vmw_pvscsi_cmd_ctx_t *
vmw_pvscsi_acquire_cmd_ctx(vmw_pvscsi_softstate_t *pvs, vmw_pvscsi_cmd_t *cmd)
{
        vmw_pvscsi_cmd_ctx_t *ctx;

        if (list_is_empty(&pvs->cmd_ctx_pool)) {
                return (NULL);
        }

        ctx = (vmw_pvscsi_cmd_ctx_t *)list_remove_head(&pvs->cmd_ctx_pool);
        ASSERT(ctx != NULL);

        ctx->cmd = cmd;
        cmd->ctx = ctx;
        return ctx;
}

static void vmw_pvscsi_release_cmd_ctx(vmw_pvscsi_softstate_t *pvs,
                                       vmw_pvscsi_cmd_t *cmd)
{
        cmd->ctx->cmd = NULL;
        list_insert_tail(&pvs->cmd_ctx_pool, cmd->ctx);
        cmd->ctx = NULL;
}

static void vmw_pvscsi_map_buffers(vmw_pvscsi_softstate_t *pvs,
                                   vmw_pvscsi_cmd_t *cmd, struct PVSCSIRingReqDesc *rdesc)
{
        _LOG("vmw_pvscsi_map_buffers(): Not implemented.");
}

static u64 vmw_pvscsi_map_context(vmw_pvscsi_softstate_t *pvs,
                                  vmw_pvscsi_cmd_ctx_t *io_ctx)
{
	return io_ctx - pvs->cmd_ctx + 1;
}

static int vmw_pvscsi_queue_cmd(vmw_pvscsi_softstate_t *pvs, vmw_pvscsi_cmd_t *cmd,
                                struct scsi_address *ap)
{
        struct PVSCSIRingsState *sdesc;
	struct PVSCSIRingReqDesc *rdesc;
        uint32_t req_entries;
        vmw_pvscsi_cmd_ctx_t *io_ctx = cmd->ctx;

        sdesc = RINGS_STATE(pvs);
        req_entries = sdesc->reqNumEntriesLog2;

        _LOG("req_entries: %d, i1: %d, i2: %d",
             req_entries, sdesc->reqProdIdx, sdesc->cmpConsIdx);
        if ((sdesc->reqProdIdx - sdesc->cmpConsIdx) >= (1 << req_entries)) {
                _LOG("no free I/O slots.");
                return (TRAN_BUSY);
        }

        rdesc = REQ_RING(pvs) + (sdesc->reqProdIdx & MASK(req_entries));
        rdesc->bus = 0; /* TODO: Setup BUS number properly. */
        rdesc->target = 0; /* TODO: Setup target ID properly. */

        bzero(&rdesc->lun, sizeof(rdesc->lun));
        rdesc->lun[1] = 0; /* TODO: Setu[ LUN ID properly. */

        /* TODO: Handle sense buffer properly. */
        rdesc->senseLen = 0;
        rdesc->senseAddr = NULL;

        _LOG("CDB length: %ld", cmd->cmdlen);

        rdesc->vcpuHint = 0;
        rdesc->cdbLen = cmd->cmdlen;
        bcopy(cmd->cmd_cdb, rdesc->cdb, cmd->cmdlen);

        /* Setup tag info. */
        if (cmd->flags & VMW_PVSCSI_CMD_TAG) {
                rdesc->tag = cmd->tag;
        } else {
                rdesc->tag = MSG_SIMPLE_QTAG;
        }

        /* Setup I/O direction and map data buffers. */
        if (cmd->flags & VMW_PVSCSI_CMD_IO) {
                if (cmd->flags & VMW_PVSCSI_CMD_IO_READ) {
                        rdesc->flags = PVSCSI_FLAG_CMD_DIR_TOHOST;
                } else {
                        rdesc->flags = PVSCSI_FLAG_CMD_DIR_TODEVICE;
                }
                vmw_pvscsi_map_buffers(pvs, cmd, rdesc);
        } else {
                rdesc->flags = 0;
        }

        rdesc->context = vmw_pvscsi_map_context(pvs, io_ctx);

        membar_producer();
        sdesc->reqProdIdx++;

        return (TRAN_ACCEPT);
}

static int
vmw_pvscsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
        vmw_pvscsi_softstate_t *pvs = ap->a_hba_tran->tran_hba_private;
        vmw_pvscsi_cmd_t *cmd = PKT2CMD(pkt);
        vmw_pvscsi_cmd_ctx_t *io_ctx;
        int rc;

        _LOG("---> SCSI cmd: 0x%X", pkt->pkt_cdbp[0]);

        if (ddi_in_panic()) {
                return (TRAN_ACCEPT);
        }

        ASSERT(cmd->pkt == pkt);

        mutex_enter(&pvs->mtx);
        if ((io_ctx = vmw_pvscsi_acquire_cmd_ctx(pvs, cmd)) == NULL) {
                rc = TRAN_BUSY;
                goto out_unlock;
        }

        if ((rc = vmw_pvscsi_queue_cmd(pvs, cmd, ap)) != TRAN_ACCEPT) {
                vmw_pvscsi_release_cmd_ctx(pvs, cmd);
                goto out_unlock;
        }

        vmw_pvscsi_submit_command(pvs, cmd);
        rc = TRAN_ACCEPT;

out_unlock:
        mutex_exit(&pvs->mtx);
        return (rc);
}

static int
vmw_pvscsi_reset(struct scsi_address *ap, int level)
{
        _ERR_FUN(0);
}

static int
vmw_pvscsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
        _ERR_FUN(0);
}

static int
vmw_pvscsi_getcap(struct scsi_address *ap, char *cap, int tgtonly)
{
        _ERR_FUN(0);
}

static int
vmw_pvscsi_setcap(struct scsi_address *ap, char *cap, int value, int tgtonly)
{
        _ERR_FUN(0);
}

static void vmw_pvscsi_cmd_ext_free(vmw_pvscsi_cmd_t *cmd)
{
        struct scsi_pkt *pkt = cmd->pkt;

        if (cmd->flags & VMW_PVSCSI_CMD_CDB_EXT) {
                kmem_free(pkt->pkt_cdbp, cmd->cmdlen);
                _LOG("pkt_cdbp freed.");
        }
        if (cmd->flags & VMW_PVSCSI_CMD_SCB_EXT) {
                kmem_free(pkt->pkt_scbp, cmd->statuslen);
                _LOG("pkt_scbp freed.");
        }
        if (cmd->flags & VMW_PVSCSI_CMD_PRIV_EXT) {
                kmem_free(pkt->pkt_private, cmd->tgtlen);
                _LOG("pkt_private freed.");
        }
}

static int
vmw_pvscsi_cmd_ext_alloc(vmw_pvscsi_softstate_t *pvs, vmw_pvscsi_cmd_t *cmd, int kf)
{
        void *buf;
        struct scsi_pkt *pkt = cmd->pkt;

        if (cmd->cmdlen > sizeof (cmd->cmd_cdb)) {
                if((buf = kmem_zalloc(cmd->cmdlen, kf)) == NULL) {
                        return (NULL);
                }
                pkt->pkt_cdbp = buf;
                cmd->flags |= VMW_PVSCSI_CMD_CDB_EXT;
                _LOG("cmdlen extended. %ld", cmd->cmdlen);
        }

        if (cmd->statuslen > sizeof (cmd->cmd_scb)) {
                if((buf = kmem_zalloc(cmd->statuslen, kf)) == NULL) {
                        goto out;
                }
                pkt->pkt_scbp = buf;
                cmd->flags |= VMW_PVSCSI_CMD_SCB_EXT;
                _LOG("statuslen extended. %ld", cmd->statuslen);
        }

        if (cmd->tgtlen > sizeof(cmd->tgt_priv)) {
                if((buf = kmem_zalloc(cmd->tgtlen, kf)) == NULL) {
                        goto out;
                }
                pkt->pkt_private = buf;
                cmd->flags |= VMW_PVSCSI_CMD_PRIV_EXT;
                _LOG("tgtlen extended. %ld", cmd->tgtlen);
        }

        return (DDI_SUCCESS);
out:
        vmw_pvscsi_cmd_ext_free(cmd);
        return (NULL);
}

static struct scsi_pkt *
vmw_pvscsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
                    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
                    int (*callback)(), caddr_t arg)
{
        int kf = (callback == SLEEP_FUNC) ? KM_SLEEP: KM_NOSLEEP;
        vmw_pvscsi_softstate_t *pvs;
        vmw_pvscsi_cmd_t *cmd;
        boolean_t is_new;

        _LOG("pkt: %p, buf: %p", pkt, bp);

        pvs = ap->a_hba_tran->tran_hba_private;
        ASSERT(pvs != NULL);

        if (ap->a_lun >= pvs->num_luns) {
                _LOG("bad LUN: %d (total LUNs: %d)", ap->a_lun, pvs->num_luns);
                return (NULL);
        }

        /* Transform target's address. */
        ap->a_target = 0;
        ap->a_lun = 0;

        /* Allocate a new SCSI packet. */
        if (pkt == NULL) {
                if ((cmd = kmem_cache_alloc(pvs->cmd_cache, kf)) == NULL) {
                        return (NULL);
                }

                pkt = &cmd->cached_pkt;
                pkt->pkt_ha_private = (opaque_t)cmd;
                pkt->pkt_address = *ap;
                pkt->pkt_scbp = (uchar_t *)&cmd->cmd_scb;
		pkt->pkt_cdbp = (uchar_t *)&cmd->cmd_cdb;
                pkt->pkt_private = (opaque_t)&cmd->tgt_priv;

                cmd->tgtlen = tgtlen;
                cmd->statuslen = statuslen;
                cmd->cmdlen = cmdlen;
                cmd->pkt = pkt;
                cmd->ctx = NULL;

                is_new = B_TRUE;

                /* Allocate extended buffers ? */
                if ((cmdlen > sizeof (cmd->cmd_cdb)) ||
		    (statuslen > sizeof (cmd->cmd_scb)) ||
		    (tgtlen > sizeof (cmd->tgt_priv))) {
                        if (vmw_pvscsi_cmd_ext_alloc(pvs, cmd, kf) != DDI_SUCCESS) {
                                goto out;
                        }
                }
        } else {
                cmd = PKT2CMD(pkt);
                is_new = B_FALSE;
        }

        /* Setup data buffer. */
        if ((bp != NULL) && (bp->b_bcount > 0)) {
                /* TODO: add support of buffers.See scsa1394_cmd_buf_dma_alloc() for details. */
                _LOG("I/O buffers are not supported yet !");
                goto out;
        }

        return (pkt);
out:
        if (is_new) {
                vmw_pvscsi_cmd_ext_free(cmd);
                kmem_cache_free(pvs->cmd_cache, cmd);
        }
        return (NULL);
        
}

static void
vmw_pvscsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
        vmw_pvscsi_cmd_t *cmd = PKT2CMD(pkt);
        vmw_pvscsi_softstate_t *pvs = ap->a_hba_tran->tran_hba_private;

        _DBG_FUN();

        if (cmd->ctx) {
                vmw_pvscsi_release_cmd_ctx(pvs, cmd);
        }

        if (cmd->flags & VMW_PVSCSI_CMD_EXT) {
                vmw_pvscsi_cmd_ext_free(cmd);
        }

        /* TODO: free DMA resources for CDB/buffer data, if any. */

        kmem_cache_free(pvs->cmd_cache, cmd);
}

static void
vmw_pvscsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
        _DBG_FUN();
}

static void
vmw_pvscsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
        _DBG_FUN();
}

static int
vmw_pvscsi_reset_notify(struct scsi_address *ap, int flag,
                        void (*callback)(caddr_t), caddr_t arg)
{
        _ERR_FUN(DDI_FAILURE);
}

static int
vmw_pvscsi_get_bus_addr(struct scsi_device *sd, char *name, int len)
{
        _ERR_FUN(0);
}

static int
vmw_pvscsi_get_name(struct scsi_device *sd, char *name, int len)
{
        _ERR_FUN(0);
}

static int
vmw_pvscsi_hba_quiesce(dev_info_t *dip)
{
        _ERR_FUN(-1);
}

static int
vmw_pvscsi_hba_unquiesce(dev_info_t *dip)
{
        _ERR_FUN(-1);
}

static int
vmw_pvscsi_bus_config(dev_info_t *pdip, uint_t flag,
                      ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
        _ERR_FUN(DDI_FAILURE);
}

static int vmw_pvscsi_hba_setup(vmw_pvscsi_softstate_t *pvs)
{
        scsi_hba_tran_t		*hba_tran;
	int			tran_flags;

	hba_tran = pvs->m_tran = scsi_hba_tran_alloc(pvs->m_dip,
                                                     SCSI_HBA_CANSLEEP);
	ASSERT(pvs->m_tran != NULL);

        hba_tran->tran_hba_private = pvs;
        hba_tran->tran_tgt_private = NULL;

        hba_tran->tran_tgt_init		= vmw_pvscsi_tgt_init;
	hba_tran->tran_tgt_free		= vmw_pvscsi_tgt_free;

	hba_tran->tran_start		= vmw_pvscsi_start;
	hba_tran->tran_reset		= vmw_pvscsi_reset;
	hba_tran->tran_abort		= vmw_pvscsi_abort;
	hba_tran->tran_getcap		= vmw_pvscsi_getcap;
	hba_tran->tran_setcap		= vmw_pvscsi_setcap;
	hba_tran->tran_init_pkt		= vmw_pvscsi_init_pkt;
	hba_tran->tran_destroy_pkt	= vmw_pvscsi_destroy_pkt;

	hba_tran->tran_dmafree		= vmw_pvscsi_dmafree;
	hba_tran->tran_sync_pkt		= vmw_pvscsi_sync_pkt;
	hba_tran->tran_reset_notify	= vmw_pvscsi_reset_notify;

	hba_tran->tran_get_bus_addr	= vmw_pvscsi_get_bus_addr;
	hba_tran->tran_get_name		= vmw_pvscsi_get_name;

	hba_tran->tran_quiesce		= vmw_pvscsi_hba_quiesce;
	hba_tran->tran_unquiesce	= vmw_pvscsi_hba_unquiesce;
	hba_tran->tran_bus_reset	= NULL;

	hba_tran->tran_add_eventcall	= NULL;
	hba_tran->tran_get_eventcookie	= NULL;
	hba_tran->tran_post_event	= NULL;
	hba_tran->tran_remove_eventcall	= NULL;

	hba_tran->tran_bus_config	= vmw_pvscsi_bus_config;

	hba_tran->tran_interconnect_type = INTERCONNECT_SAS;

	/*
	 * All children of the HBA are iports. We need tran was cloned.
	 * So we pass the flags to SCSA. SCSI_HBA_TRAN_CLONE will be
	 * inherited to iport's tran vector.
	 */
	tran_flags = (SCSI_HBA_HBA | SCSI_HBA_TRAN_CLONE);

        _LOG("attaching a HBA ...");
	if (scsi_hba_attach_setup(pvs->m_dip, &pvs->m_msg_dma_attr,
                                  hba_tran, tran_flags) != DDI_SUCCESS) {
                _LOG("failed to attach a SCSI HBA !");
		scsi_hba_tran_free(hba_tran);
		pvs->m_tran = NULL;
		return -1;
	}
        _LOG("HBA attached.");
        return 0;
}

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

static int vmw_pvscsi_setup_dma_buffer(size_t length, pv_dma_buf_t *buf,
                                       int consistency, int rw,
                                       vmw_pvscsi_softstate_t *pvs)
{
        /* DMA access attributes for descriptors */
        static ddi_device_acc_attr_t attrs = {
                DDI_DEVICE_ATTR_V0,
                DDI_STRUCTURE_LE_ACC,
                DDI_STRICTORDER_ACC,
                DDI_DEFAULT_ACC,
        };
        ddi_dma_cookie_t cookie;
        uint_t ccount;

        if ((ddi_dma_alloc_handle(pvs->m_dip, &vmw_pvscsi_ring_dma_attr,
                                  DDI_DMA_SLEEP, NULL,
                                  &buf->dma_handle)) != DDI_SUCCESS) {
                _LOG("failed to allocate handle.");
                return DDI_FAILURE;
        }

        if ((ddi_dma_mem_alloc(buf->dma_handle, length, &attrs, consistency, DDI_DMA_SLEEP,
                               NULL, &buf->addr, &buf->real_length, &buf->acc_handle)) != DDI_SUCCESS) {
                _LOG("failed to allocate %ld bytes for DMA buffer.", length);
                ddi_dma_free_handle(&buf->dma_handle);
                return DDI_FAILURE;
        }

        if ((ddi_dma_addr_bind_handle(buf->dma_handle, NULL, buf->addr,
                                      buf->real_length, consistency | rw,
                                      DDI_DMA_SLEEP, NULL, &cookie, &ccount)) != DDI_SUCCESS) {
                _LOG("failed to bind DMA buffer.");
                ddi_dma_free_handle(&buf->dma_handle);
                ddi_dma_mem_free(&buf->acc_handle);
                return DDI_FAILURE;
        }

        /* TODO: Support of multipart SG regions ? */
        ASSERT(ccount == 1);

        buf->pa = cookie.dmac_laddress;
        return DDI_SUCCESS;
}

static void vmw_pvscsi_free_dma_buffer(pv_dma_buf_t *buf)
{
        ddi_dma_free_handle(&buf->dma_handle);
        ddi_dma_mem_free(&buf->acc_handle);
}

static int vmw_pvscsi_setup_sg(vmw_pvscsi_softstate_t *pvs)
{
        int i, j = 0;
        vmw_pvscsi_cmd_ctx_t *ctx;
        size_t size = pvs->req_depth * sizeof(vmw_pvscsi_cmd_ctx_t);

        pvs->cmd_ctx = kmem_alloc(size, KM_SLEEP);
        if (pvs->cmd_ctx == NULL) {
                _LOG("failed to allocate %ld bytes for CMD CTX.", size);
                return (DDI_FAILURE);
        }
        bzero(pvs->cmd_ctx, size);

        ctx = pvs->cmd_ctx;
        for (i = 0; i < pvs->req_depth; ++i, ++ctx) {
                list_insert_tail(&pvs->cmd_ctx_pool, ctx);

                if (vmw_pvscsi_setup_dma_buffer(PAGE_SIZE, &ctx->dma_buf,
                                        DDI_DMA_CONSISTENT, DDI_DMA_RDWR,
                                        pvs) != DDI_SUCCESS) {
                        goto cleanup;
                }
                j++;
        }

        _LOG("CMD CTX entries: %d", j);
        return (DDI_SUCCESS);
cleanup:
        for (; i >= 0; --i, --ctx) {
                list_remove(&pvs->cmd_ctx_pool, ctx);
                vmw_pvscsi_free_dma_buffer(&ctx->dma_buf);
        }
        kmem_free(pvs->cmd_ctx, size);
        return (DDI_FAILURE);
}

static void vmw_pvscsi_free_sg(vmw_pvscsi_softstate_t *pvs)
{
        vmw_pvscsi_cmd_ctx_t *ctx = pvs->cmd_ctx;
        int i;

        /* TODO: Restore proper resource cleanup after implementing SCSI
         * command completion.
         */
        for (i = 0; i < pvs->req_depth; ++i, ++ctx) {
                //list_remove(&pvs->cmd_ctx_pool, ctx);
                vmw_pvscsi_free_dma_buffer(&ctx->dma_buf);
        }

        //kmem_free(pvs->cmd_ctx, pvs->req_pages << PAGE_SHIFT);
}

static int __test_scsi_cb(caddr_t arg)
{
        return 0;
}

static void __test_fn(void *arg)
{
        vmw_pvscsi_softstate_t *pvs = (vmw_pvscsi_softstate_t *)arg;
        struct scsi_pkt *pkt;
        struct scsi_address ap;
        int rc;
        //struct buf *bp;

        _DBG_FUN();
        delay(400);
        _LOG("Got woken up ! Allocating a SCSI packet.");

        /* Setup SCSI address for the target. */
        ap.a_target = 0;
        ap.a_lun = 0;
        ap.a_hba_tran = pvs->m_tran;

        /* Allocate a DMA buffer for the return data. */
        //bp = scsi_alloc_consistent_buf(&ap, (struct buf *)NULL, );

        /* Allocate a packet for SCMD_TEST_UNIT_READY command. */
        _LOG("Allocating a SCSI packet.");
        pkt = scsi_init_pkt(&ap, (struct scsi_pkt *)NULL, NULL,
                            CDB_GROUP0, sizeof (struct scsi_arq_status),
                            0, 0, __test_scsi_cb, NULL);
        if (pkt == NULL) {
                _LOG("failed to allocate SCSI packet !");
                return;
        }

        /* Setup CDB. */
        _LOG("SCSI packet allocated. Setting up CDB.");
        scsi_setup_cdb((union scsi_cdb *)pkt->pkt_cdbp,
                       SCMD_TEST_UNIT_READY, 0, 0, 0);
	pkt->pkt_flags = FLAG_NOINTR|FLAG_NOPARITY;
        _LOG("Executing SCSI command ...");
        rc = scsi_poll(pkt);
        _LOG("scsi_poll(): %d", rc);

        _LOG("Destroying the packet.");
        scsi_destroy_pkt(pkt);
        _LOG("Packet destroyed.");

        //vmw_pvscsi_queue_pkt(NULL, pvs);
}

static void __transport_test(vmw_pvscsi_softstate_t *pvs)
{
        _LOG("Testing SCSI packet delivery ...");
        if (taskq_dispatch(system_taskq, __test_fn, pvs, TS_SLEEP) == NULL) {
                _LOG("failed to launch test action !");
        }
}

static int vmw_pvscsi_allocate_rings(vmw_pvscsi_softstate_t *pvs)
{
        /* Allocate DMA buffer for rings state. */
        if (vmw_pvscsi_setup_dma_buffer(PAGE_SIZE, &pvs->rings_state_buf,
                                        DDI_DMA_CONSISTENT, DDI_DMA_RDWR,
                                        pvs) != DDI_SUCCESS) {
                goto out;
        }

        /* Allocate DMA buffer for request ring. */
        pvs->req_pages = MIN(PVSCSI_MAX_NUM_PAGES_REQ_RING, vmw_pvscsi_ring_pages);
        pvs->req_depth = pvs->req_pages * PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE;

        if (vmw_pvscsi_setup_dma_buffer(pvs->req_pages * PAGE_SIZE, &pvs->req_ring_buf,
                                        DDI_DMA_CONSISTENT, DDI_DMA_RDWR,
                                        pvs) != DDI_SUCCESS) {
                goto free_rings_state;
        }

        /* Allocate completion ring. */
        pvs->cmp_pages = MIN(PVSCSI_MAX_NUM_PAGES_CMP_RING, vmw_pvscsi_ring_pages);
        if (vmw_pvscsi_setup_dma_buffer(pvs->cmp_pages * PAGE_SIZE, &pvs->cmp_ring_buf,
                                        DDI_DMA_CONSISTENT, DDI_DMA_RDWR,
                                        pvs) != DDI_SUCCESS) {
                goto free_req_buf;
        }

        /* Allocate messages ring. */
        pvs->msg_pages = MIN(PVSCSI_MAX_NUM_PAGES_MSG_RING, vmw_pvscsi_ring_pages);
        if (vmw_pvscsi_setup_dma_buffer(pvs->msg_pages * PAGE_SIZE, &pvs->msg_ring_buf,
                                        DDI_DMA_CONSISTENT, DDI_DMA_RDWR,
                                        pvs) != DDI_SUCCESS) {
                goto free_cmp_buf;
        }

        return DDI_SUCCESS;
free_cmp_buf:
        vmw_pvscsi_free_dma_buffer(&pvs->cmp_ring_buf);
free_req_buf:
        vmw_pvscsi_free_dma_buffer(&pvs->req_ring_buf);
free_rings_state:
        vmw_pvscsi_free_dma_buffer(&pvs->rings_state_buf);
out:
        return DDI_FAILURE;
}

static int vmw_pvscsi_setup_rings(vmw_pvscsi_softstate_t *pvs)
{
        struct PVSCSICmdDescSetupRings cmd = { 0 };
	int i;
	u64 base;

        _DBG_FUN();

        cmd.ringsStatePPN   = pvs->rings_state_buf.pa >> PAGE_SHIFT;
	cmd.reqRingNumPages = pvs->req_pages;
	cmd.cmpRingNumPages = pvs->cmp_pages;

        /* Setup Request ring. */
        base = pvs->req_ring_buf.pa;
	for (i = 0; i < pvs->req_pages; i++) {
		cmd.reqRingPPNs[i] = base >> PAGE_SHIFT;
		base += PAGE_SIZE;
	}

        /* Setup Completion ring. */
        base = pvs->cmp_ring_buf.pa;
	for (i = 0; i < pvs->cmp_pages; i++) {
		cmd.cmpRingPPNs[i] = base >> PAGE_SHIFT;
		base += PAGE_SIZE;
	}

        memset(RINGS_STATE(pvs), 0, PAGE_SIZE);
	memset(REQ_RING(pvs), 0, pvs->req_pages * PAGE_SIZE);
	memset(CMP_RING(pvs), 0, pvs->cmp_pages * PAGE_SIZE);

        /* Issue SETUP command. */
        vmw_pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_SETUP_RINGS, &cmd, sizeof(cmd));

        if (pvs->use_msg) {
                struct PVSCSICmdDescSetupMsgRing cmd_msg = { 0 };

		cmd_msg.numPages = pvs->msg_pages;
		base = pvs->msg_ring_buf.pa;

		for (i = 0; i < pvs->msg_pages; i++) {
			cmd_msg.ringPPNs[i] = base >> PAGE_SHIFT;
			base += PAGE_SIZE;
		}
                memset(MSG_RING(pvs), 0, pvs->msg_pages * PAGE_SIZE);

		vmw_pvscsi_write_cmd_desc(pvs, PVSCSI_CMD_SETUP_MSG_RING,
                                          &cmd_msg, sizeof(cmd_msg));
        }

        return DDI_SUCCESS;
}

#define	ARRAY_SIZE(x)  (sizeof(x) / sizeof(x[0]))

static int vmw_pvscsi_setup_io(vmw_pvscsi_softstate_t *pvs)
{
        int offset, rcount, rnumber, type;
        pci_regspec_t *regs;
        off_t regsize;
        unsigned int regs_length;
        int ret = DDI_FAILURE;

        _DBG_FUN();

        if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pvs->m_dip,
                                      DDI_PROP_DONTPASS, "reg", (int **)&regs,
                                      &regs_length) != DDI_PROP_SUCCESS) {
                _LOG("failed to lookup 'reg' property.");
		return (ret);
	}

        rcount = regs_length * sizeof (int) / sizeof (pci_regspec_t);

        for (offset = PCI_CONF_BASE0; offset <= PCI_CONF_BASE5; offset += 4) {
                for (rnumber = 0; rnumber < rcount; ++rnumber) {
                        if (PCI_REG_REG_G(regs[rnumber].pci_phys_hi) == offset) {
                                type = regs[rnumber].pci_phys_hi & PCI_ADDR_MASK;
                                break;
                        }
                }

                if (rnumber >= rcount) {
                        continue;
                }

                if (type != PCI_ADDR_IO) {
                        if(ddi_dev_regsize(pvs->m_dip, rnumber,
                                           &regsize) != DDI_SUCCESS) {
                                _LOG("failed to get size of register %d", rnumber);
                                goto out;
                        }
                        if (regsize == PVSCSI_MEM_SPACE_SIZE) {
                                if (ddi_regs_map_setup(pvs->m_dip, rnumber, &pvs->mmio_base,
                                                       0, 0, &vmw_pvscsi_mmio_attr,
                                                       &pvs->mmio_handle) != DDI_SUCCESS) {
                                        _LOG("failed to map MMIO BAR.");
                                        goto out;
                                }
                                cmn_err(CE_NOTE, "MMIO region (register %d) of 0x%lX bytes initialized.", rnumber, regsize);
                                ret = DDI_SUCCESS;
                                break;
                        }
                }
        }

out:
        ddi_prop_free(regs);
        return (ret);
}

static int vmw_pvscsi_setup_msg_wq(vmw_pvscsi_softstate_t * pvs)
{
        _LOG("vmw_pvscsi_use_msg: %d", vmw_pvscsi_use_msg);
        if (!vmw_pvscsi_use_msg) {
                return 0;
        }

        vmw_pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_COMMAND, PVSCSI_CMD_SETUP_MSG_RING);

        if (vmw_pvscsi_reg_read(pvs, PVSCSI_REG_OFFSET_COMMAND_STATUS) == -1) {
                _LOG("no WQ MSG ring allowed for this HBA.");
		return 0;
        }

        _LOG("WQ MSG feature activated for PVSCSI HBA.");

        /* TODO: Setup warkqueue. */
        return 1;
}

static int vmw_pvscsi_unmask_irq(vmw_pvscsi_softstate_t *pvs)
{
	uint32_t intr_bits;
        int rc, irq_caps;

	intr_bits = PVSCSI_INTR_CMPL_MASK;
	if (pvs->use_msg) {
		intr_bits |= PVSCSI_INTR_MSG_MASK;
        }

        if ((rc = ddi_intr_get_cap(pvs->intr_htable[0], &irq_caps)) != DDI_SUCCESS) {
                _LOG("Failed to obtain IRQ capabilities !");
                return (DDI_FAILURE);
        }

        if (irq_caps & DDI_INTR_FLAG_BLOCK) {
                _LOG("* Unleashing block IRQ: %d", pvs->intr_cnt);
                rc = ddi_intr_block_enable(pvs->intr_htable, pvs->intr_cnt);
        } else {
                int i;

                _LOG("* Unleashing non-block IRQ: %d", pvs->intr_cnt);
                for (i = 0; i < pvs->intr_cnt; i++) {
                        rc = ddi_intr_enable(pvs->intr_htable[i]);
                        if (rc != DDI_SUCCESS) {
                                _LOG("failed to unleash non-block IRQ !");
                                break;
                        }                        
                }
        }

        if (rc != DDI_SUCCESS) {
                /* TODO: Cleanup IRQ resources. */
                _LOG("* IRQ unleash failed !");
        } else {
                vmw_pvscsi_reg_write(pvs, PVSCSI_REG_OFFSET_INTR_MASK, intr_bits);
                _LOG("* HW IRQs unleashed.");
        }

        return (rc);
}

static int vmw_pvscsi_msg_pending(vmw_pvscsi_softstate_t *pvs)
{
	struct PVSCSIRingsState *sdesc = RINGS_STATE(pvs);

	return sdesc->msgProdIdx != sdesc->msgConsIdx;
}


static void vmw_pvscsi_process_irq(vmw_pvscsi_softstate_t *pvs)
{
        /* TODO: Actual IRQ handling is done here. */
}

static uint32_t vmw_pvscsi_irq_handler(caddr_t arg1, caddr_t arg2)
{
        vmw_pvscsi_softstate_t *pvs = (vmw_pvscsi_softstate_t *)arg1;
        uint32_t status;
        boolean_t handled;

        _LOG("PVSCSI IRQ !!!");
        if (pvs->msi_enable) {
                handled = B_TRUE;
        } else {
                status = vmw_pvscsi_read_intr_status(pvs);

                handled = (status & PVSCSI_INTR_ALL_SUPPORTED) != 0;
		if (handled) {
			vmw_pvscsi_write_intr_status(pvs, status);
                }
        }

        if (handled) {
                mutex_enter(&pvs->mtx);
                vmw_pvscsi_process_irq(pvs);
                if (pvs->use_msg && vmw_pvscsi_msg_pending(pvs)) {
                        _LOG("> Queuing work !");
                        /* TODO: Implement work schedule in IRQ handler. */
                }
                mutex_exit(&pvs->mtx);
        }
        return (DDI_INTR_CLAIMED);
}

static int vmw_pvscsi_install_irq_handler(vmw_pvscsi_softstate_t *pvs,
                                          int type)
{
        int rc, nirqs, navail, alloced;

        rc = ddi_intr_get_nintrs(pvs->m_dip, type, &nirqs);
        if ((rc != DDI_SUCCESS) || (nirqs != 1)) {
                _LOG("failed to get number of IRQs of type %d", type);
                return (DDI_FAILURE);
        }

        rc = ddi_intr_get_navail(pvs->m_dip, type, &navail);
	if ((rc != DDI_SUCCESS) || (navail != 1)) {
                _LOG("failed to get number of available IRQs of type %d", type);
		return (DDI_FAILURE);
	}

        pvs->intr_size = nirqs * sizeof (ddi_intr_handle_t);
        pvs->intr_htable = kmem_alloc(pvs->intr_size, KM_SLEEP);

        if (pvs->intr_htable == NULL) {
                _LOG("failed to allocate %d bytes for IRQ hashtable.",
                     pvs->intr_size);
                return (DDI_FAILURE);
        }

        alloced = 0;
        rc = ddi_intr_alloc(pvs->m_dip, pvs->intr_htable, type, 0,
                            nirqs, &alloced, DDI_INTR_ALLOC_NORMAL);

	if ((rc != DDI_SUCCESS) || (alloced != 1)) {
                _LOG("failed to allocate %d IRQs (or improper number of IRQs provided: %d).",
                     nirqs, alloced);
		goto free_htable;
	}

        pvs->intr_cnt = alloced;

        rc = ddi_intr_get_pri(pvs->intr_htable[0], &pvs->intr_pri);
	if (rc != DDI_SUCCESS) {
		_LOG("get interrupt priority failed: %d\n", rc);
                goto free_irqs;
	}

        rc = ddi_intr_add_handler(pvs->intr_htable[0],
                                  vmw_pvscsi_irq_handler, (caddr_t)pvs, NULL);
        if (rc != DDI_SUCCESS) {
                _LOG("failed to add IRQ handler: %d", rc);
                goto free_irqs;
        }

        return (DDI_SUCCESS);
free_irqs:
        ddi_intr_free(pvs->intr_htable[0]);
free_htable:
        kmem_free(pvs->intr_htable, pvs->intr_size);
        return (DDI_FAILURE);
}

static void vmw_pvscsi_free_irq_resources(vmw_pvscsi_softstate_t *pvs)
{
        ddi_intr_remove_handler(pvs->intr_htable[0]);
        ddi_intr_free(pvs->intr_htable[0]);
        kmem_free(pvs->intr_htable, pvs->intr_size);
}

static int vmw_pvscsi_setup_irq(vmw_pvscsi_softstate_t *pvs)
{
        int irq_types, rc;

        if (ddi_intr_get_supported_types(pvs->m_dip, &irq_types) != DDI_SUCCESS) {
                _LOG("failed to acquire supported IRQ types.");
                return (DDI_FAILURE);
        }

        _LOG("INTR mask: 0x%X", irq_types);

        if ((irq_types & DDI_INTR_TYPE_MSI) && pvs->msi_enable) {
                rc = vmw_pvscsi_install_irq_handler(pvs, DDI_INTR_TYPE_MSI);
                if (rc == DDI_SUCCESS) {
                        pvs->irq_type = DDI_INTR_TYPE_MSI;
                        _LOG("installed MSI interrupt handler.");
                } else {
                        _LOG("failed to install MSI IRQ handler.");
                }
        }

        if ((irq_types & DDI_INTR_TYPE_FIXED) && (pvs->irq_type == 0)) {
                rc = vmw_pvscsi_install_irq_handler(pvs, DDI_INTR_TYPE_FIXED);
                if (rc == DDI_SUCCESS) {
                        pvs->irq_type = DDI_INTR_TYPE_FIXED;
                        _LOG("installed FIXED interrupt handler.");
                } else {
                        _LOG("failed to install MSI IRQ handler.");
                }
        }

        return (pvs->irq_type == 0) ? (DDI_FAILURE) : (DDI_SUCCESS);
}

static int cmd_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
        vmw_pvscsi_softstate_t *pvs = cdrarg;
        vmw_pvscsi_cmd_t *cmd = (vmw_pvscsi_cmd_t *)buf;
        int (*callback)(caddr_t)  = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP: DDI_DMA_DONTWAIT;

        _DBG_FUN();
        bzero(buf, CMD_CACHE_ITEM_SIZE);

        /* Allocate a DMA handle for data transfers. */
        if ((ddi_dma_alloc_handle(pvs->m_dip, &pvs->io_dma_attr, callback,
                                  NULL, &cmd->cmd_handle)) != DDI_SUCCESS) {
                return (-1);
        }
        return (0);
}

static void cmd_cache_destructor(void *buf, void *cdrarg)
{
        _DBG_FUN();
}

static int vmw_pvscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
        int instance;
        vmw_pvscsi_softstate_t *pvs;
        char buf[32];

        _DBG_FUN();

        /*
         * If this is an iport node, invoke iport attach.
         */
        if (scsi_hba_iport_unit_address(dip) != NULL) {
                return (vmw_pvscsi_iport_attach(dip));
        }

        switch (cmd) {
          case DDI_ATTACH:
                  break;
          case DDI_RESUME:
                  break;
          default:
                  return (DDI_FAILURE);
        }

        instance = ddi_get_instance(dip);

        /* Allocate softstate information. */
	if (ddi_soft_state_zalloc(vmw_pvscsi_sstate, instance) != DDI_SUCCESS) {
		_LOG("ddi_soft_state_zalloc() failed for instance %d", instance);
		return (DDI_FAILURE);
	}

        if ((pvs = ddi_get_soft_state(vmw_pvscsi_sstate, instance)) == NULL) {
                _LOG("failed to get soft state for instance %d", instance);
                goto fail;
        }

        /* Indicate that we are 'sizeof (scsi_*(9S))' clean, we use  scsi_pkt_size() instead. */
        scsi_size_clean(dip);

        /* Setup HBA instance. */
        pvs->m_instance = instance;
        pvs->m_dip = dip;
        pvs->m_msg_dma_attr = vmw_pvscsi_msg_dma_attr;
        pvs->ring_dma_attr = vmw_pvscsi_ring_dma_attr;
        pvs->io_dma_attr = vmw_pvscsi_io_dma_attr;
        pvs->msi_enable = 1; /* TODO: Setup as a property ? */
        pvs->num_luns = 1; /* TODO: Setup number of LUNs properly. */
        mutex_init(&pvs->mtx, "PVSCSI instance mutex", MUTEX_DRIVER, NULL);
        list_create(&pvs->cmd_ctx_pool, sizeof(vmw_pvscsi_cmd_ctx_t),
                    offsetof(vmw_pvscsi_cmd_ctx_t, list));

        sprintf(buf, "pvscsi%d_cache", instance);
        pvs->cmd_cache = kmem_cache_create(buf, CMD_CACHE_ITEM_SIZE, 8,
                                           cmd_cache_constructor, cmd_cache_destructor,
                                           NULL, (void *)pvs, NULL, 0);
        if (pvs->cmd_cache == NULL) {
                _LOG("failed to create a cache for SCSI commands.");
                goto fail;
        }

        if ((vmw_pvscsi_setup_io(pvs)) != DDI_SUCCESS) {
                _LOG("failed to setup I/O region.");
                goto free_cache;
        }

        vmw_pvscsi_hba_reset(pvs);

        pvs->use_msg = vmw_pvscsi_setup_msg_wq(pvs);

        if ((vmw_pvscsi_allocate_rings(pvs)) != DDI_SUCCESS) {
                _LOG("failed to allocate DMA rings.");
                goto free_io;
        }

        if ((vmw_pvscsi_setup_rings(pvs)) != DDI_SUCCESS) {
                _LOG("failed to configure DMA rings.");
                goto free_rings;
        }

        if (vmw_pvscsi_setup_irq(pvs) != DDI_SUCCESS) {
                goto clear_rings;
        }

        _LOG("-1");
        if (vmw_pvscsi_setup_sg(pvs) != DDI_SUCCESS) {
                goto clear_irq;
        }
        _LOG("-2");

        if (vmw_pvscsi_hba_setup(pvs) != 0) {
                goto clear_sg;
        }

        _LOG("INT status (for testing device accessibility): 0x%X\n", vmw_pvscsi_read_intr_status(pvs));

        _LOG("unmasking IRQs...");
        if (vmw_pvscsi_unmask_irq(pvs) != DDI_SUCCESS) {
                goto clear_hba;
        }

        __transport_test(pvs);
        //vmw_pvscsi_queue_pkt(NULL, pvs);

        _DBG("vmw_pvscsi_attach(): New instance of PVSCSI HBA attached.");
        return (DDI_SUCCESS);
clear_hba:
        /* Rollback HBA initialization here. */
clear_sg:
        vmw_pvscsi_free_sg(pvs);
clear_irq:
        /* TODO: Clear IRQ properly. */
clear_rings:
        /* TODO: clear DMA rings settings. */
        vmw_pvscsi_hba_reset(pvs);
free_rings:
        /* TODO: free DMA rings properly. */
free_io:
        /* TODO: free mapped I/O region here. */
free_cache:
        kmem_cache_destroy(pvs->cmd_cache);
fail:
        ddi_soft_state_free(vmw_pvscsi_sstate, instance);
        return (DDI_FAILURE);
}

static int vmw_pvscsi_do_detach(dev_info_t *dip)
{
        int instance;
        vmw_pvscsi_softstate_t *pvs;

        _DBG_FUN();

        instance = ddi_get_instance(dip);
        if ((pvs = ddi_get_soft_state(vmw_pvscsi_sstate, instance)) == NULL) {
                _LOG("failed to get soft state for instance %d", instance);
                return (DDI_FAILURE);
        }

        vmw_pvscsi_hba_reset(pvs);

        /* Destroy all unused fields. */
        vmw_pvscsi_free_irq_resources(pvs);
        vmw_pvscsi_free_sg(pvs);
        kmem_cache_destroy(pvs->cmd_cache);
        mutex_destroy(&pvs->mtx);

        ddi_soft_state_free(vmw_pvscsi_sstate, instance);

        return (DDI_SUCCESS);
}

static int vmw_pvscsi_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
        _DBG("vmw_pvscsi_detach(): START");switch (cmd) {
	case DDI_DETACH:
		return (vmw_pvscsi_do_detach(devi));
	default:
		return (DDI_FAILURE);
	}
}

static int vmw_pvscsi_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
                            int *rval)
{
  _DBG("vmw_pvscsi_ioctl(): START\n");
  return ENOTSUP;
}

static int vmw_pvscsi_power(dev_info_t *dip, int component, int level)
{
  _DBG("vmw_pvscsi_power(): START\n");
  return DDI_SUCCESS;
}

static int vmw_pvscsi_quiesce(dev_info_t *devi)
{
  _DBG("vmw_pvscsi_quiesce(): START\n");
  return DDI_SUCCESS;
}
