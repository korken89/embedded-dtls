use core::ptr::addr_of_mut;
use core::str::FromStr;
use embassy_net::{DhcpConfig, Stack, StackResources};
use embassy_stm32::eth::{Ethernet, PacketQueue};
use embassy_stm32::peripherals::ETH;
use embassy_stm32::rng::Rng as EmbassyRng;
use embassy_stm32::time::Hertz;
use embassy_stm32::{bind_interrupts, eth, peripherals, rng, Config};
use heapless::String;
use rand_core::RngCore;
use rtic_monotonics::systick::Systick;
use static_cell::StaticCell;

use crate::bsp::ksz8863::KSZ8863SMI;

pub mod ksz8863;

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    RNG => rng::InterruptHandler<peripherals::RNG>;
});

type Device = Ethernet<'static, ETH, KSZ8863SMI>;
pub type NetworkStack = &'static Stack<Device>;
pub type Rng = EmbassyRng<'static, embassy_stm32::peripherals::RNG>;

#[inline(never)]
pub fn ascon_mac(id: &[u8; 12]) -> [u8; 6] {
    use ascon_hash::{AsconXof, ExtendableOutput, Update, XofReader};

    let mut xof = AsconXof::default();
    xof.update(id);
    let mut reader = xof.finalize_xof();
    let mut dst = [0u8; 6];
    reader.read(&mut dst);
    dst
}

#[inline(always)]
pub fn init(c: cortex_m::Peripherals) -> (NetworkStack, Rng) {
    // Update this for clock setup.
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;

        config.rcc.hse = Some(Hse {
            freq: Hertz(8_000_000),
            mode: HseMode::Bypass,
        });
        config.rcc.pll_src = PllSource::HSE;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL168,
            divp: Some(PllPDiv::DIV2), // 8mhz / 4 * 168 / 2 = 168 Mhz.
            divq: None,
            divr: None,
        });
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.sys = Sysclk::PLL1_P;
    }
    let p = embassy_stm32::init(config);

    // Hash UID to make MAC
    let mac_addr = ascon_mac(embassy_stm32::uid::uid());

    defmt::info!(
        "MAC Address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac_addr[0],
        mac_addr[1],
        mac_addr[2],
        mac_addr[3],
        mac_addr[4],
        mac_addr[5]
    );

    static mut PACKETS: PacketQueue<16, 16> = PacketQueue::new();

    // NOTE: Update Pins and Phy for your board.
    let device = Ethernet::new(
        unsafe { &mut *addr_of_mut!(PACKETS) },
        p.ETH,
        Irqs,
        p.PA1,
        p.PA2,
        p.PC1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PB12,
        p.PB13,
        p.PB11,
        KSZ8863SMI::new(),
        mac_addr,
    );

    // Set the hostname of the board to `rpc-<UID in hex>`.
    let config = {
        let mut c = DhcpConfig::default();
        let mut hostname = String::from_str("rpc-").unwrap();
        hostname.push_str(embassy_stm32::uid::uid_hex()).unwrap();
        c.hostname = Some(hostname);
        embassy_net::Config::dhcpv4(c)
    };

    // Generate random seed.
    let mut rng = EmbassyRng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    let _ = rng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    // Initialize the network stack.
    static STACK: StaticCell<Stack<Device>> = StaticCell::new();
    static mut RESOURCES: StackResources<4> = StackResources::new();

    let stack = &*STACK.init(Stack::new(
        device,
        config,
        unsafe { &mut *addr_of_mut!(RESOURCES) },
        seed,
    ));

    // Start the Systick monotonic.
    let systick_token = rtic_monotonics::create_systick_token!();
    Systick::start(c.SYST, 168_000_000, systick_token);
    defmt::info!("init done");

    (stack, rng)
}
