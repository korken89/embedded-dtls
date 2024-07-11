//! KSZ8863 SMI Ethernet PHY

use core::task::Context;
use embassy_stm32::eth::{StationManagement, PHY};
use embassy_time::{Duration, Timer};
use futures::FutureExt;

#[allow(dead_code)]
mod phy_consts {
    pub const PHY_REG_BCR: u8 = 0x00;
    pub const PHY_REG_BSR: u8 = 0x01;
    pub const PHY_REG_ID1: u8 = 0x02;
    pub const PHY_REG_ID2: u8 = 0x03;
    pub const PHY_REG_ANTX: u8 = 0x04;
    pub const PHY_REG_ANRX: u8 = 0x05;
    pub const PHY_REG_ANEXP: u8 = 0x06;
    pub const PHY_REG_ANNPTX: u8 = 0x07;
    pub const PHY_REG_ANNPRX: u8 = 0x08;
    pub const PHY_REG_CTL: u8 = 0x0D; // Ethernet PHY Register Control
    pub const PHY_REG_ADDAR: u8 = 0x0E; // Ethernet PHY Address or Data

    pub const PHY_REG_WUCSR: u16 = 0x8010;

    pub const PHY_REG_BCR_COLTEST: u16 = 1 << 7;
    pub const PHY_REG_BCR_FD: u16 = 1 << 8;
    pub const PHY_REG_BCR_ANRST: u16 = 1 << 9;
    pub const PHY_REG_BCR_ISOLATE: u16 = 1 << 10;
    pub const PHY_REG_BCR_POWERDN: u16 = 1 << 11;
    pub const PHY_REG_BCR_AN: u16 = 1 << 12;
    pub const PHY_REG_BCR_100M: u16 = 1 << 13;
    pub const PHY_REG_BCR_LOOPBACK: u16 = 1 << 14;
    pub const PHY_REG_BCR_RESET: u16 = 1 << 15;

    pub const PHY_REG_BSR_JABBER: u16 = 1 << 1;
    pub const PHY_REG_BSR_UP: u16 = 1 << 2;
    pub const PHY_REG_BSR_FAULT: u16 = 1 << 4;
    pub const PHY_REG_BSR_ANDONE: u16 = 1 << 5;
}
use self::phy_consts::*;

/// KSZ8863 SMI for `embassy_stm32::eth::Ethernet`
pub struct KSZ8863SMI {
    poll_interval: Duration,
}

impl KSZ8863SMI {
    const UPLINK_PHY_ADDR: u8 = 1;
    #[allow(unused)]
    const DOWNLINK_PHY_ADDR: u8 = 2;
    #[allow(unused)]
    const PHY_ADDRS: &'static [u8] = &[Self::UPLINK_PHY_ADDR, Self::DOWNLINK_PHY_ADDR];

    /// Creates a new PHY driver
    pub fn new() -> Self {
        Self {
            poll_interval: Duration::from_millis(500),
        }
    }
}

unsafe impl PHY for KSZ8863SMI {
    fn phy_reset<S: StationManagement>(&mut self, _sm: &mut S) {
        // Reset is managed via non-standard SMI interface with `KSZ8863Raw`
    }

    fn phy_init<S: StationManagement>(&mut self, _sm: &mut S) {
        // Default configuration enables auto-negotation and in case
        // of failure thereof, it forces 100M and full-duplex.
    }

    fn poll_link<S: StationManagement>(&mut self, sm: &mut S, cx: &mut Context) -> bool {
        let _ = Timer::after(self.poll_interval).poll_unpin(cx);

        let bsr = sm.smi_read(Self::UPLINK_PHY_ADDR, PHY_REG_BSR);

        // No link without autonegotiate
        if bsr & PHY_REG_BSR_ANDONE == 0 {
            return false;
        }
        // No link if link is down
        if bsr & PHY_REG_BSR_UP == 0 {
            return false;
        }

        // Got link
        true
    }
}
