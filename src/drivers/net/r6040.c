/*
 * RDC R6040 Fast Ethernet MAC support
 *
 * Copyright (C) 2004 Sten Wang <sten.wang@rdc.com.tw>
 * Copyright (C) 2007
 *	Daniel Gimpelevich <daniel@gimpelevich.san-francisco.ca.us>
 *	Florian Fainelli <florian@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
*/

#include <ipxe/malloc.h>
//#include <linux/kernel.h>
//#include <linux/module.h>
//#include <linux/moduleparam.h>
//#include <linux/string.h>
#include <ipxe/vsprintf.h>
//#include <linux/timer.h>
#include <unistd.h>
#include <errno.h>
//#include <linux/ioport.h>
//#include <linux/interrupt.h>
#include <ipxe/pci.h>
#include <ipxe/pci_io.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
//#include <linux/init.h>
#include <ipxe/timer.h>
#include <mii.h>
//#include <linux/ethtool.h>
//#include <linux/crc32.h>
//#include <linux/spinlock.h>
//#include <linux/bitops.h>
#include <byteswap.h>
#include <ipxe/io.h>
//#include <linux/irq.h>
//#include <linux/uaccess.h>
//#include <linux/phy.h>
#include <ipxe/crypto.h>

//#include <asm/processor.h>

#undef ERRFILE
#define ERRFILE ERRFILE_r6040

//#define DRV_NAME	"r6040"
//#define DRV_VERSION	"0.28"
//#define DRV_RELDATE	"07Oct2011"

/* PHY CHIP Address */
#define PHY1_ADDR	1	/* For MAC1 */
#define PHY2_ADDR	3	/* For MAC2 */
//#define PHY_MODE	0x3100	/* PHY CHIP Register 0 */
//#define PHY_CAP		0x01E1	/* PHY CHIP Register 4 */

///* Time in jiffies before concluding the transmitter is hung. */
//#define TX_TIMEOUT	(6000 * HZ / 1000)

/* RDC MAC I/O Size */
#define R6040_IO_SIZE	256

///* MAX RDC MAC */
//#define MAX_MAC		2

/* MAC registers */
//#define MCR0		0x00	/* Control register 0 */
//#define  MCR0_PROMISC	0x0020	/* Promiscuous mode */
//#define  MCR0_HASH_EN	0x0100	/* Enable multicast hash table function */
#define MCR1		0x04	/* Control register 1 */
#define  MAC_RST	0x0001	/* Reset the MAC */
#define MBCR		0x08	/* Bus control */
#define MT_ICR		0x0C	/* TX interrupt control */
#define MR_ICR		0x10	/* RX interrupt control */
#define MTPR		0x14	/* TX poll command register */
#define MR_BSR		0x18	/* RX buffer size */
//#define MR_DCR		0x1A	/* RX descriptor control */
#define MLSR		0x1C	/* Last status */
#define MMDIO		0x20	/* MDIO control register */
#define  MDIO_WRITE	0x4000	/* MDIO write */
#define  MDIO_READ	0x2000	/* MDIO read */
#define MMRD		0x24	/* MDIO read data register */
#define MMWD		0x28	/* MDIO write data register */
#define MTD_SA0		0x2C	/* TX descriptor start address 0 */
#define MTD_SA1		0x30	/* TX descriptor start address 1 */
#define MRD_SA0		0x34	/* RX descriptor start address 0 */
#define MRD_SA1		0x38	/* RX descriptor start address 1 */
#define MISR		0x3C	/* Status register */
#define MIER		0x40	/* INT enable register */
#define  MSK_INT	0x0000	/* Mask off interrupts */
#define  RX_FINISH	0x0001  /* RX finished */
#define  RX_NO_DESC	0x0002  /* No RX descriptor available */
#define  RX_FIFO_FULL	0x0004  /* RX FIFO full */
//#define  RX_EARLY	0x0008  /* RX early */
#define  TX_FINISH	0x0010  /* TX finished */
//#define  TX_EARLY	0x0080  /* TX early */
//#define  EVENT_OVRFL	0x0100  /* Event counter overflow */
#define  LINK_CHANGED	0x0200  /* PHY link changed */
//#define ME_CISR		0x44	/* Event counter INT status */
//#define ME_CIER		0x48	/* Event counter INT enable  */
//#define MR_CNT		0x50	/* Successfully received packet counter */
//#define ME_CNT0		0x52	/* Event counter 0 */
//#define ME_CNT1		0x54	/* Event counter 1 */
//#define ME_CNT2		0x56	/* Event counter 2 */
//#define ME_CNT3		0x58	/* Event counter 3 */
//#define MT_CNT		0x5A	/* Successfully transmit packet counter */
//#define ME_CNT4		0x5C	/* Event counter 4 */
//#define MP_CNT		0x5E	/* Pause frame counter register */
//#define MAR0		0x60	/* Hash table 0 */
//#define MAR1		0x62	/* Hash table 1 */
//#define MAR2		0x64	/* Hash table 2 */
//#define MAR3		0x66	/* Hash table 3 */
#define MID_0L		0x68	/* Multicast address MID0 Low */
#define MID_0M		0x6A	/* Multicast address MID0 Medium */
#define MID_0H		0x6C	/* Multicast address MID0 High */
//#define MID_1L		0x70	/* MID1 Low */
//#define MID_1M		0x72	/* MID1 Medium */
//#define MID_1H		0x74	/* MID1 High */
//#define MID_2L		0x78	/* MID2 Low */
//#define MID_2M		0x7A	/* MID2 Medium */
//#define MID_2H		0x7C	/* MID2 High */
//#define MID_3L		0x80	/* MID3 Low */
//#define MID_3M		0x82	/* MID3 Medium */
//#define MID_3H		0x84	/* MID3 High */
#define PHY_CC		0x88	/* PHY status change configuration register */
//#define PHY_ST		0x8A	/* PHY status register */
#define MAC_SM		0xAC	/* MAC status machine */
//#define MAC_ID		0xBE	/* Identifier register */

#define TX_DCNT		0x16	/* TX descriptor count */
#define RX_DCNT		0x16	/* RX descriptor count */
#define MAX_BUF_SIZE	0x600
#define RX_DESC_SIZE	(RX_DCNT * sizeof(struct r6040_descriptor))
#define TX_DESC_SIZE	(TX_DCNT * sizeof(struct r6040_descriptor))
#define MBCR_DEFAULT	0x012A	/* MAC Bus Control Register */
//#define MCAST_MAX	3	/* Max number multicast addresses to filter */

/* Descriptor status */
#define DSC_OWNER_MAC	0x8000	/* MAC is the owner of this descriptor */
//#define DSC_RX_OK	0x4000	/* RX was successful */
#define DSC_RX_ERR	0x0800	/* RX PHY error */
//#define DSC_RX_ERR_DRI	0x0400	/* RX dribble packet */
//#define DSC_RX_ERR_BUF	0x0200	/* RX length exceeds buffer size */
//#define DSC_RX_ERR_LONG	0x0100	/* RX length > maximum packet length */
//#define DSC_RX_ERR_RUNT	0x0080	/* RX packet length < 64 byte */
//#define DSC_RX_ERR_CRC	0x0040	/* RX CRC error */
//#define DSC_RX_BCAST	0x0020	/* RX broadcast (no error) */
//#define DSC_RX_MCAST	0x0010	/* RX multicast (no error) */
//#define DSC_RX_MCH_HIT	0x0008	/* RX multicast hit in hash table (no error) */
//#define DSC_RX_MIDH_HIT	0x0004	/* RX MID table hit (no error) */
//#define DSC_RX_IDX_MID_MASK 3	/* RX mask for the index of matched MIDx */

///* PHY settings */
//#define ICPLUS_PHY_ID	0x0243

/* RX and TX interrupts that we handle */
#define RX_INTS			(RX_FIFO_FULL | RX_NO_DESC | RX_FINISH)
#define TX_INTS			(TX_FINISH)
#define INT_MASK		(RX_INTS | TX_INTS)

struct r6040_descriptor {
	u16	status, len;		/* 0-3 */
	uint32_t	buf;			/* 4-7 */
	uint32_t	ndesc;			/* 8-B */
	u32	rev1;			/* C-F */
	char	*vbufp;			/* 10-13 */
	struct r6040_descriptor *vndescp;	/* 14-17 */
	struct io_buffer *iob_ptr;	/* 18-1B */
	u32	rev2;			/* 1C-1F */
} __attribute__((aligned(32)));

struct r6040_private {
	struct pci_device *pdev;
	struct r6040_descriptor *rx_insert_ptr;
	struct r6040_descriptor *rx_remove_ptr;
	struct r6040_descriptor *tx_insert_ptr;
	struct r6040_descriptor *tx_remove_ptr;
	struct r6040_descriptor *rx_ring;
	struct r6040_descriptor *tx_ring;
	u32 rx_ring_dma;
	u32 tx_ring_dma;
	u16	tx_free_desc, phy_addr;
	u16	mcr0, mcr1;
	struct net_device *dev;
	struct mii_if_info mii_if;
	int napi;
	void *base;
	int ier;
};

static int phy_table[] = { PHY1_ADDR, PHY2_ADDR };

/* Read a word data from PHY Chip */
static int r6040_phy_read(void *ioaddr, int phy_addr, int reg)
{
	int limit = 2048;
	u16 cmd;

	writew(MDIO_READ + reg + (phy_addr << 8), ioaddr + MMDIO);
	/* Wait for the read bit to be cleared */
	while (limit--) {
		cmd = readw(ioaddr + MMDIO);
		if (!(cmd & MDIO_READ))
			break;
	}

	return readw(ioaddr + MMRD);
}

/* Write a word data from PHY Chip */
static void r6040_phy_write(void *ioaddr,
					int phy_addr, int reg, u16 val)
{
	int limit = 2048;
	u16 cmd;

	writew(val, ioaddr + MMWD);
	/* Write the command to the MDIO bus */
	writew(MDIO_WRITE + reg + (phy_addr << 8), ioaddr + MMDIO);
	/* Wait for the write bit to be cleared */
	while (limit--) {
		cmd = readw(ioaddr + MMDIO);
		if (!(cmd & MDIO_WRITE))
			break;
	}
}

static int r6040_mdiobus_read(struct net_device *dev, int phy_addr, int reg)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;

	return r6040_phy_read(ioaddr, phy_addr, reg);
}

static void r6040_mdiobus_write(struct net_device *dev, int phy_addr,
						int reg, int value)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;

	r6040_phy_write(ioaddr, phy_addr, reg, value);

	return;
}

static void r6040_free_txbufs(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	int i;

	for (i = 0; i < TX_DCNT; i++) {
		if (lp->tx_insert_ptr->iob_ptr) {
			free_iob(lp->tx_insert_ptr->iob_ptr);
			lp->tx_insert_ptr->iob_ptr = NULL;
		}
		lp->tx_insert_ptr = lp->tx_insert_ptr->vndescp;
	}
}

static void r6040_free_rxbufs(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	int i;

	for (i = 0; i < RX_DCNT; i++) {
		if (lp->rx_insert_ptr->iob_ptr) {
			free_iob(lp->rx_insert_ptr->iob_ptr);
			lp->rx_insert_ptr->iob_ptr = NULL;
		}
		lp->rx_insert_ptr = lp->rx_insert_ptr->vndescp;
	}
}

static void r6040_init_ring_desc(struct r6040_descriptor *desc_ring,
				 u32 desc_dma, int size)
{
	struct r6040_descriptor *desc = desc_ring;
	u32 mapping = desc_dma;

	while (size-- > 0) {
		mapping += sizeof(*desc);
		desc->ndesc = cpu_to_le32(mapping);
		desc->vndescp = desc + 1;
		desc++;
	}
	desc--;
	desc->ndesc = cpu_to_le32(desc_dma);
	desc->vndescp = desc_ring;
}

static void r6040_init_txbufs(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);

	lp->tx_free_desc = TX_DCNT;

	lp->tx_remove_ptr = lp->tx_insert_ptr = lp->tx_ring;
	r6040_init_ring_desc(lp->tx_ring, lp->tx_ring_dma, TX_DCNT);
}

static int r6040_alloc_rxbufs(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	struct r6040_descriptor *desc;
	struct io_buffer *iob;
	int rc;

	lp->rx_remove_ptr = lp->rx_insert_ptr = lp->rx_ring;
	r6040_init_ring_desc(lp->rx_ring, lp->rx_ring_dma, RX_DCNT);

	/* Allocate iobs for the rx descriptors */
	desc = lp->rx_ring;
	do {
		iob = alloc_iob(MAX_BUF_SIZE);
		if (!iob) {
			DBG("r6040: failed to alloc iob for rx\n");
			rc = -ENOMEM;
			goto err_exit;
		}
		desc->iob_ptr = iob;
		desc->buf = cpu_to_le32(virt_to_bus(desc->iob_ptr->data));
		desc->status = DSC_OWNER_MAC;
		desc = desc->vndescp;
	} while (desc != lp->rx_ring);

	return 0;

err_exit:
	/* Deallocate all previously allocated iobs */
	r6040_free_rxbufs(dev);
	return rc;
}

static void r6040_init_mac_regs(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;
	int limit = 2048;
	u16 cmd;

	/* Mask Off Interrupt */
	writew(MSK_INT, ioaddr + MIER);

	/* Reset RDC MAC */
	writew(MAC_RST, ioaddr + MCR1);
	while (limit--) {
		cmd = readw(ioaddr + MCR1);
		if (cmd & 0x1)
			break;
	}
	/* Reset internal state machine */
	writew(2, ioaddr + MAC_SM);
	writew(0, ioaddr + MAC_SM);
	mdelay(5);

	/* MAC Bus Control Register */
	writew(MBCR_DEFAULT, ioaddr + MBCR);

	/* Buffer Size Register */
	writew(MAX_BUF_SIZE, ioaddr + MR_BSR);

	/* Write TX ring start address */
	writew(lp->tx_ring_dma, ioaddr + MTD_SA0);
	writew(lp->tx_ring_dma >> 16, ioaddr + MTD_SA1);

	/* Write RX ring start address */
	writew(lp->rx_ring_dma, ioaddr + MRD_SA0);
	writew(lp->rx_ring_dma >> 16, ioaddr + MRD_SA1);

	/* Set interrupt waiting time and packet numbers */
	writew(0, ioaddr + MT_ICR);
	writew(0, ioaddr + MR_ICR);

	if(lp->ier) {
		/* Enable interrupts */
		writew(INT_MASK, ioaddr + MIER);
	}

	/* Enable TX and RX */
	writew(lp->mcr0 | 0x0002, ioaddr);

	/* Let TX poll the descriptors
	 * we may got called by r6040_tx_timeout which has left
	 * some unsent tx buffers */
	writew(0x01, ioaddr + MTPR);

	/* Check media */
	mii_check_media(&lp->mii_if, 1, 1);
}

/* Stop RDC MAC and Free the allocated resource */
static void r6040_down(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;
	int limit = 2048;
	u16 *adrp;
	u16 cmd;

	/* Stop MAC */
	writew(MSK_INT, ioaddr + MIER);	/* Mask Off Interrupt */
	writew(MAC_RST, ioaddr + MCR1);	/* Reset RDC MAC */
	while (limit--) {
		cmd = readw(ioaddr + MCR1);
		if (cmd & 0x1)
			break;
	}

	/* Restore MAC Address to MIDx */
	adrp = (u16 *) dev->hw_addr;
	writew(adrp[0], ioaddr + MID_0L);
	writew(adrp[1], ioaddr + MID_0M);
	writew(adrp[2], ioaddr + MID_0H);
}

static void r6040_close(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
//	struct pci_dev *pdev = lp->pdev;

	lp->napi = 0;
//	netif_stop_queue(dev);
	r6040_down(dev);

	/* Free RX buffer */
	r6040_free_rxbufs(dev);

	/* Free TX buffer */
	r6040_free_txbufs(dev);

	/* Free Descriptor memory */
	if (lp->rx_ring) {
		free_dma(lp->rx_ring, RX_DESC_SIZE);
		lp->rx_ring = NULL;
	}

	if (lp->tx_ring) {
		free_dma(lp->tx_ring, TX_DESC_SIZE);
		lp->tx_ring = NULL;
	}

	return;
}

/* Status of PHY CHIP */
static int r6040_phy_mode_chk(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;
	int phy_dat;

	/* PHY Link Status Check */
	phy_dat = r6040_phy_read(ioaddr, lp->phy_addr, 1);
	if (!(phy_dat & 0x4))
		phy_dat = 0x8000;       /* Link Failed, full duplex */

	/* PHY Chip Auto-Negotiation Status */
	phy_dat = r6040_phy_read(ioaddr, lp->phy_addr, 1);
	if (phy_dat & 0x0020) {
		/* Auto Negotiation Mode */
		phy_dat = r6040_phy_read(ioaddr, lp->phy_addr, 5);
		phy_dat &= r6040_phy_read(ioaddr, lp->phy_addr, 4);
		if (phy_dat & 0x140)
			/* Force full duplex */
			phy_dat = 0x8000;
		else
			phy_dat = 0;
	} else {
		/* Force Mode */
		phy_dat = r6040_phy_read(ioaddr, lp->phy_addr, 0);
		if (phy_dat & 0x100)
			phy_dat = 0x8000;
		else
			phy_dat = 0x0000;
	}

	mii_check_media(&lp->mii_if, 0, 1);

	return phy_dat;
}

static void r6040_set_carrier(struct mii_if_info *mii)
{
	if (r6040_phy_mode_chk(mii->dev)) {
		/* autoneg is off: Link is always assumed to be up */
		DBG("Cottsay: Link is assumed to be UP\n");
		if (!netdev_link_ok(mii->dev))
			netdev_link_up(mii->dev);
	} else
		r6040_phy_mode_chk(mii->dev);
}

//static int r6040_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
//{
//	struct r6040_private *lp = netdev_priv(dev);
//	struct mii_ioctl_data *data = if_mii(rq);
//	int rc;
//
//	if (!netif_running(dev))
//		return -EINVAL;
//	rc = generic_mii_ioctl(&lp->mii_if, data, cmd, NULL);
//	r6040_set_carrier(&lp->mii_if);
//	return rc;
//}

//static void r6040_adjust_link(struct net_device *dev __unused)
//{
//	/* TODO: Cottsay - Hack */
//	DBG("Cottsay: Link Change Interrupt");
//	netdev_link_up(dev);
//	struct r6040_private *lp = netdev_priv(dev);
//	struct phy_device *phydev = lp->phydev;
//	int status_changed = 0;
//	void *ioaddr = lp->base;
//
//	assert(!phydev);
//
//	if (lp->old_link != phydev->link) {
//		status_changed = 1;
//		lp->old_link = phydev->link;
//	}
//
//	/* reflect duplex change */
//	if (phydev->link && (lp->old_duplex != phydev->duplex)) {
//		lp->mcr0 |= (phydev->duplex == DUPLEX_FULL ? 0x8000 : 0);
//		writew(lp->mcr0, ioaddr);
//
//		status_changed = 1;
//		lp->old_duplex = phydev->duplex;
//	}
//
//	if (status_changed) {
//		DBG("r6040: %s: link %s", dev->name, phydev->link ?
//			"UP" : "DOWN");
//		if (phydev->link)
//			DBG(" - %d/%s", phydev->speed,
//			DUPLEX_FULL == phydev->duplex ? "full" : "half");
//		DBG("\n");
//	}
//}

static int r6040_rx(struct net_device *dev, int limit)
{
	struct r6040_private *priv = netdev_priv(dev);
	struct r6040_descriptor *descptr = priv->rx_remove_ptr;
	struct io_buffer *iob_ptr, *new_iob;
	int count = 0;
	u16 err;

	/* Limit not reached and the descriptor belongs to the CPU */
	while (count < limit && !(descptr->status & DSC_OWNER_MAC)) {
		/* Read the descriptor status */
		err = descptr->status;
		/* Global error status set */
		if (err & DSC_RX_ERR) {
//			/* RX dribble */
//			if (err & DSC_RX_ERR_DRI)
//				dev->stats.rx_frame_errors++;
//			/* Buffer length exceeded */
//			if (err & DSC_RX_ERR_BUF)
//				dev->stats.rx_length_errors++;
//			/* Packet too long */
//			if (err & DSC_RX_ERR_LONG)
//				dev->stats.rx_length_errors++;
//			/* Packet < 64 bytes */
//			if (err & DSC_RX_ERR_RUNT)
//				dev->stats.rx_length_errors++;
//			/* CRC error */
//			if (err & DSC_RX_ERR_CRC) {
//				dev->stats.rx_crc_errors++;
//			}
			netdev_rx_err(dev, NULL, EIO);
			goto next_descr;
		}

		/* Packet successfully received */
		new_iob = alloc_iob(MAX_BUF_SIZE);
		if (!new_iob) {
//			dev->stats.rx_dropped++;
			goto next_descr;
		}
		iob_ptr = descptr->iob_ptr;

		/* Do not count the CRC */
		iob_put(iob_ptr, descptr->len - 4);
//		iob_ptr->protocol = eth_type_trans(iob_ptr, priv->dev);

		/* Send to upper layer */
		netdev_rx(dev, iob_ptr);
//		dev->stats.rx_packets++;
//		dev->stats.rx_bytes += descptr->len - 4;

		/* put new iob into descriptor */
		descptr->iob_ptr = new_iob;
		descptr->buf = cpu_to_le32(virt_to_bus(descptr->iob_ptr->data));

next_descr:
		/* put the descriptor back to the MAC */
		descptr->status = DSC_OWNER_MAC;
		descptr = descptr->vndescp;
		count++;
	}
	priv->rx_remove_ptr = descptr;

	return count;
}

static void r6040_tx(struct net_device *dev)
{
	struct r6040_private *priv = netdev_priv(dev);
	struct r6040_descriptor *descptr;
	void *ioaddr = priv->base;
	struct io_buffer *iob_ptr;
	u16 err;

	descptr = priv->tx_remove_ptr;
	while (priv->tx_free_desc < TX_DCNT) {
		/* Check for errors */
		err = readw(ioaddr + MLSR);

//		if (err & 0x0200)
//			netdev_rx_err(dev, NULL, EIO);
//		if (err & (0x2000 | 0x4000))
//			netdev_rx_err(dev, NULL, EIO);

		if (descptr->status & DSC_OWNER_MAC)
			break; /* Not complete */
		iob_ptr = descptr->iob_ptr;
		/* Free buffer */
		if( (err & 0x0200) || (err & (0x2000 | 0x4000)))
			netdev_tx_complete_err(dev, iob_ptr, EIO);
		else
			netdev_tx_complete(dev, iob_ptr);
		descptr->iob_ptr = NULL;
		/* To next descriptor */
		descptr = descptr->vndescp;
		priv->tx_free_desc++;
	}
	priv->tx_remove_ptr = descptr;

//	if (priv->tx_free_desc)
//		netif_wake_queue(dev);
}

static int r6040_poll(struct net_device *dev, int budget)
{
	struct r6040_private *priv = netdev_priv(dev);
	void *ioaddr = priv->base;
	int work_done;

	work_done = r6040_rx(dev, budget);

	if (work_done < budget && priv->ier) {
		/* Enable RX interrupt */
		writew(readw(ioaddr + MIER) | RX_INTS, ioaddr + MIER);
	}
	return work_done;
}

/* The RDC interrupt handler. */
static void r6040_interrupt(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;
	u16 misr, status;

	/* Save MIER */
	misr = readw(ioaddr + MIER);
	/* Mask off RDC MAC interrupt */
	writew(MSK_INT, ioaddr + MIER);
	/* Read MISR status and clear */
	status = readw(ioaddr + MISR);

	if (status == 0x0000 || status == 0xffff) {
		/* Restore RDC MAC interrupt */
		writew(misr, ioaddr + MIER);
		return;
	}

	/* Link change interrupt */
	if(status & LINK_CHANGED)
	{
		DBG("Cottsay: Link Changed!\n");
		r6040_set_carrier(&lp->mii_if);
	}

	/* RX interrupt request */
	if (status & RX_INTS) {
//		if (status & RX_NO_DESC) {
//			/* RX descriptor unavailable */
//			dev->stats.rx_dropped++;
//			dev->stats.rx_missed_errors++;
//		}
//		if (status & RX_FIFO_FULL)
//			dev->stats.rx_fifo_errors++;
//
		if (lp->napi) {
			/* Mask off RX interrupt */
			misr &= ~RX_INTS;
			r6040_poll(dev, 64);
		}
	}

	/* TX interrupt request */
	if (status & TX_INTS)
		r6040_tx(dev);

	/* Restore RDC MAC interrupt */
	writew(misr, ioaddr + MIER);
}

static void r6040_poll_controller(struct net_device *dev)
{
//	disable_irq(dev->irq);
	r6040_interrupt(dev);
//	enable_irq(dev->irq);
}

/* Init RDC MAC */
static int r6040_up(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;
	int ret;

	/* Initialise and alloc RX/TX buffers */
	r6040_init_txbufs(dev);
	ret = r6040_alloc_rxbufs(dev);
	if (ret)
		return ret;

	/* improve performance (by RDC guys) */
	r6040_phy_write(ioaddr, 30, 17,
			(r6040_phy_read(ioaddr, 30, 17) | 0x4000));
	r6040_phy_write(ioaddr, 30, 17,
			~((~r6040_phy_read(ioaddr, 30, 17)) | 0x2000));
	r6040_phy_write(ioaddr, 0, 19, 0x0000);
	r6040_phy_write(ioaddr, 0, 30, 0x01F0);

	/* Initialize all MAC registers */
	r6040_init_mac_regs(dev);

	return 0;
}


/* Read/set MAC address routines */
static void r6040_mac_address(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;
	u16 *adrp;

	/* MAC operation register */
	writew(0x01, ioaddr + MCR1); /* Reset MAC */
	writew(2, ioaddr + MAC_SM); /* Reset internal state machine */
	writew(0, ioaddr + MAC_SM);
	mdelay(5);

	/* Restore MAC Address */
	adrp = (u16 *) dev->hw_addr;
	writew(adrp[0], ioaddr + MID_0L);
	writew(adrp[1], ioaddr + MID_0M);
	writew(adrp[2], ioaddr + MID_0H);

	/* Store MAC Address in perm_addr */
	memcpy(dev->ll_addr, dev->hw_addr, ETH_ALEN);
}

static int r6040_open(struct net_device *dev)
{
	struct r6040_private *lp = netdev_priv(dev);
	int ret;

	/* Set MAC address */
	r6040_mac_address(dev);

	/* Allocate Descriptor memory */
	lp->rx_ring = malloc_dma(RX_DESC_SIZE, 32);
	if (!lp->rx_ring) {
		ret = -ENOMEM;
		goto err_free_irq;
	}
	lp->rx_ring_dma = virt_to_bus(lp->rx_ring);

	lp->tx_ring = malloc_dma(TX_DESC_SIZE, 32);
	if (!lp->tx_ring) {
		ret = -ENOMEM;
		goto err_free_rx_ring;
	}
	lp->tx_ring_dma = virt_to_bus(lp->tx_ring);

	ret = r6040_up(dev);
	if (ret)
		goto err_free_tx_ring;

	lp->napi = 1;
//	netif_start_queue(dev);

	return 0;

err_free_tx_ring:
	free_dma(lp->tx_ring, TX_DESC_SIZE);
err_free_rx_ring:
	free_dma(lp->rx_ring, RX_DESC_SIZE);
err_free_irq:
	return ret;
}

static int r6040_start_xmit(struct net_device *dev,
				    struct io_buffer *iob)
{
	struct r6040_private *lp = netdev_priv(dev);
	struct r6040_descriptor *descptr;
	void *ioaddr = lp->base;

	/* TX resource check */
	if (!lp->tx_free_desc) {
//		netif_stop_queue(dev);
		DBG("r6040: no tx descriptor\n");
		return -ENOBUFS;
	}

	/* Set TX descriptor & Transmit it */
	lp->tx_free_desc--;
	descptr = lp->tx_insert_ptr;
	if (iob_len(iob) < MISR)
		descptr->len = MISR;
	else
		descptr->len = iob_len(iob);

	descptr->iob_ptr = iob;
	descptr->buf = cpu_to_le32(virt_to_bus(iob->data));
	descptr->status = DSC_OWNER_MAC;

	/* Trigger the MAC to check the TX descriptor */
	writew(0x01, ioaddr + MTPR);
	lp->tx_insert_ptr = descptr->vndescp;

//	/* If no tx resource, stop */
//	if (!lp->tx_free_desc)
//		netif_stop_queue(dev);

	return 0;
}

static void r6040_irq(struct net_device *dev, int enable)
{
	struct r6040_private *lp = netdev_priv(dev);
	void *ioaddr = lp->base;

	DBG("Cottsay: IRQ is %d", enable);

	if( ( lp->ier = enable ) )
		writew(INT_MASK, ioaddr + MIER); /* Enable interrupts */
	else
		writew(MSK_INT, ioaddr + MIER);	/* Mask Off Interrupt */
}

static struct net_device_operations r6040_netdev_ops = {
	.open		= r6040_open,
	.close		= r6040_close,
	.transmit	= r6040_start_xmit,
	.poll		= r6040_poll_controller,
	.irq		= r6040_irq,
};

static int r6040_init_one(struct pci_device *pdev)
{
	struct net_device *dev;
	struct r6040_private *lp;
	void *ioaddr;
	int err, io_size = R6040_IO_SIZE;
	static int card_idx = -1;
//	int bar = 0;
	u16 *adrp;

	adjust_pci_device(pdev);

//	/* IO Size check */
//	if (pci_resource_len(pdev, bar) < io_size) {
//		DBG("r6040: Insufficient PCI resources, aborting\n");
//		err = -EIO;
//		goto err_out;
//	}

	dev = alloc_etherdev(sizeof(struct r6040_private));
	if (!dev) {
		DBG("r6040: Failed to allocate etherdev\n");
		err = -ENOMEM;
		goto err_out;
	}
	dev->dev = (struct device *)pdev;
	lp = netdev_priv(dev);

	netdev_init(dev, &r6040_netdev_ops);

	ioaddr = ioremap(pdev->membase, io_size);
	if (!ioaddr) {
		DBG("r6040: ioremap failed for device\n");
		err = -EIO;
		goto err_out_free_res;
	}
	/* If PHY status change register is still set to zero it means the
	 * bootloader didn't initialize it */
	if (readw(ioaddr + PHY_CC) == 0)
		writew(0x9f07, ioaddr + PHY_CC);

	/* Init system & device */
	lp->base = ioaddr;

	pci_set_drvdata(pdev, dev);

	/* Set MAC address */
	card_idx++;

	adrp = (u16 *)dev->hw_addr;
	adrp[0] = readw(ioaddr + MID_0L);
	adrp[1] = readw(ioaddr + MID_0M);
	adrp[2] = readw(ioaddr + MID_0H);

	/* Some bootloader/BIOSes do not initialize
	 * MAC address, warn about that */
	if (!(adrp[0] || adrp[1] || adrp[2])) {
		DBG("r6040: MAC address not initialized, "
					"generating random\n");
		get_random_bytes(dev->hw_addr, ETH_ALEN);
		dev->hw_addr[0] &= 0xFE;
		dev->hw_addr[0] |= 0x02;
	}

	/* Link new device into r6040_root_dev */
	lp->pdev = pdev;
	lp->dev = dev;

	/* Init RDC private data */
	lp->mcr0 = 0x1002;
	lp->phy_addr = phy_table[card_idx];

	lp->napi = 0;
	lp->ier = 0;

	lp->mii_if.dev = dev;
	lp->mii_if.mdio_read = r6040_mdiobus_read;
	lp->mii_if.mdio_write = r6040_mdiobus_write;
	lp->mii_if.phy_id = lp->phy_addr;
	lp->mii_if.phy_id_mask = 0x1f;
	lp->mii_if.reg_num_mask = 0x1f;

//	err = r6040_mii_probe(dev);
//	if (err) {
//		DBG("r6040: failed to probe MII bus\n");
//		goto err_out_mdio_unregister;
//	}

	/* Register net device. After this dev->name assign */
	err = register_netdev(dev);
	if (err) {
		DBG("r6040: Failed to register net device\n");
		goto err_out_mdio_unregister;
	}
	return 0;

err_out_mdio_unregister:
//err_out_mdio_irq:
//err_out_mdio:
//err_out_unmap:
	iounmap(ioaddr);
err_out_free_res:
//err_out_free_dev:
	netdev_put(dev);
err_out:
	return err;
}

static void r6040_remove_one(struct pci_device *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);

	unregister_netdev(dev);
	netdev_nullify(dev);
	netdev_put(dev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_device_id r6040_pci_tbl[] = {
	PCI_ROM(0x17f3, 0x6040, "r6040", "RDC R6040", 0),
};

struct pci_driver r6040_driver __pci_driver = {
	.id_count	= sizeof(r6040_pci_tbl) / sizeof(r6040_pci_tbl[0]),
	.ids		= r6040_pci_tbl,
	.probe		= r6040_init_one,
	.remove		= r6040_remove_one,
};
