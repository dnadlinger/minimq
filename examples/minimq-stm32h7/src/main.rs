#![no_std]
#![no_main]

#[macro_use]
extern crate log;

use stm32h7xx_hal::{
    ethernet::{self, PHY},
    gpio::Speed,
    prelude::*,
};

use heapless::{consts, String};

use panic_halt as _;
use rtic::cyccnt::{Instant, U32Ext};
use serde::Serialize;

use smoltcp_nal::smoltcp;

use minimq::{
    embedded_nal::{IpAddr, Ipv4Addr},
    MqttClient, QoS,
};

pub struct NetStorage {
    pub ip_addrs: [smoltcp::wire::IpCidr; 1],
    pub sockets: [Option<smoltcp::socket::SocketSetItem<'static>>; 1],
    neighbor_cache: [Option<(smoltcp::wire::IpAddress, smoltcp::iface::Neighbor)>; 8],
    pub tx_storage: [u8; 4096],
    pub rx_storage: [u8; 4096],
}

#[derive(Serialize)]
struct Random {
    random: Option<u32>,
}

static mut NET_STORE: NetStorage = NetStorage {
    // Placeholder for the real IP address, which is initialized at runtime.
    ip_addrs: [smoltcp::wire::IpCidr::Ipv6(
        smoltcp::wire::Ipv6Cidr::SOLICITED_NODE_PREFIX,
    )],
    sockets: [None; 1],
    neighbor_cache: [None; 8],
    rx_storage: [0; 4096],
    tx_storage: [0; 4096],
};

#[link_section = ".sram3.eth"]
static mut DES_RING: ethernet::DesRing = ethernet::DesRing::new();

type NetworkStack =
    smoltcp_nal::NetworkStack<'static, 'static, stm32h7xx_hal::ethernet::EthernetDMA<'static>>;

#[rtic::app(device = stm32h7xx_hal::stm32, peripherals = true, monotonic = rtic::cyccnt::CYCCNT)]
const APP: () = {
    struct Resources {
        client: MqttClient<minimq::consts::U256, NetworkStack>,
        rng: stm32h7xx_hal::rng::Rng,
    }

    #[init]
    fn init(mut c: init::Context) -> init::LateResources {
        // Enable SRAM3 for the descriptor ring.
        c.device.RCC.ahb2enr.modify(|_, w| w.sram3en().set_bit());

        let rcc = c.device.RCC.constrain();
        let pwr = c.device.PWR.constrain();
        let vos = pwr.freeze();

        let ccdr = rcc
            .sysclk(400.mhz())
            .hclk(200.mhz())
            .per_ck(100.mhz())
            .freeze(vos, &c.device.SYSCFG);

        let gpioa = c.device.GPIOA.split(ccdr.peripheral.GPIOA);
        let gpiob = c.device.GPIOB.split(ccdr.peripheral.GPIOB);
        let gpioc = c.device.GPIOC.split(ccdr.peripheral.GPIOC);
        let gpiog = c.device.GPIOG.split(ccdr.peripheral.GPIOG);

        // Configure ethernet IO
        {
            let _rmii_refclk = gpioa.pa1.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_mdio = gpioa.pa2.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_mdc = gpioc.pc1.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_crs_dv = gpioa.pa7.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_rxd0 = gpioc.pc4.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_rxd1 = gpioc.pc5.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_tx_en = gpiog.pg11.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_txd0 = gpiog.pg13.into_alternate_af11().set_speed(Speed::VeryHigh);
            let _rmii_txd1 = gpiob.pb13.into_alternate_af11().set_speed(Speed::VeryHigh);
        }

        // Configure ethernet
        let network_stack = {
            let mac_addr = smoltcp::wire::EthernetAddress([0xAC, 0x6F, 0x7A, 0xDE, 0xD6, 0xC8]);
            let (eth_dma, eth_mac) = unsafe {
                ethernet::new_unchecked(
                    c.device.ETHERNET_MAC,
                    c.device.ETHERNET_MTL,
                    c.device.ETHERNET_DMA,
                    &mut DES_RING,
                    mac_addr,
                    ccdr.peripheral.ETH1MAC,
                    &ccdr.clocks,
                )
            };

            let mut lan8742a = ethernet::phy::LAN8742A::new(eth_mac.set_phy_addr(0));
            lan8742a.phy_reset();
            lan8742a.phy_init();

            unsafe { ethernet::enable_interrupt() }

            let store = unsafe { &mut NET_STORE };

            store.ip_addrs[0] =
                smoltcp::wire::IpCidr::new(smoltcp::wire::IpAddress::v4(10, 0, 0, 2), 24);

            let neighbor_cache = smoltcp::iface::NeighborCache::new(&mut store.neighbor_cache[..]);

            let interface = smoltcp::iface::EthernetInterfaceBuilder::new(eth_dma)
                .ethernet_addr(mac_addr)
                .neighbor_cache(neighbor_cache)
                .ip_addrs(&mut store.ip_addrs[..])
                .finalize();

            let sockets = {
                let mut sockets = smoltcp::socket::SocketSet::new(&mut store.sockets[..]);
                let tcp_socket = {
                    let rx_buffer =
                        smoltcp::socket::TcpSocketBuffer::new(&mut store.rx_storage[..]);
                    let tx_buffer =
                        smoltcp::socket::TcpSocketBuffer::new(&mut store.tx_storage[..]);
                    smoltcp::socket::TcpSocket::new(rx_buffer, tx_buffer)
                };

                sockets.add(tcp_socket);
                sockets
            };

            NetworkStack::new(interface, sockets)
        };

        let client = MqttClient::<consts::U256, _>::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "nucleo",
            network_stack,
        )
        .unwrap();

        // Initialize random number generator
        let rng = c.device.RNG.constrain(ccdr.peripheral.RNG, &ccdr.clocks);

        // Enable the cycle counter.
        c.core.DWT.enable_cycle_counter();

        init::LateResources { client, rng }
    }

    #[idle(resources=[client, rng])]
    fn idle(c: idle::Context) -> ! {
        let mut time: u32 = 0;
        let mut next_ms = Instant::now();

        next_ms += 400_00.cycles();

        loop {
            let tick = Instant::now() > next_ms;

            if tick {
                next_ms += 400_000.cycles();
                time += 1;
            }

            if tick && (time % 1000) == 0 {
                c.resources
                    .client
                    .publish("nucleo", "Hello, World!".as_bytes(), QoS::AtMostOnce, &[])
                    .unwrap();

                let random = Random {
                    random: c.resources.rng.gen().ok(),
                };

                let random: String<consts::U256> = serde_json_core::to_string(&random).unwrap();
                c.resources
                    .client
                    .publish("random", &random.into_bytes(), QoS::AtMostOnce, &[])
                    .unwrap();
            }

            match c
                .resources
                .client
                .poll(|_client, topic, message, _properties| match topic {
                    _ => info!("On '{:?}', received: {:?}", topic, message),
                }) {
                Ok(_) => {}
                // If we got disconnected from the broker
                Err(minimq::Error::Disconnected) => {
                    info!("MQTT client disconnected")
                }
                Err(e) => {
                    panic!("{:#?}", e);
                }
            };

            // Update the TCP stack.
            c.resources.client.network_stack.poll(time);
        }
    }

    #[task(binds=ETH)]
    fn eth(_: eth::Context) {
        unsafe { ethernet::interrupt_handler() }
    }
};
