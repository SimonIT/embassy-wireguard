#![no_std]
pub mod config;
mod wg;

pub use crate::config::Config;
use crate::wg::{MAX_PACKET, consume, create_tunnel, handle_routine_tun_result, send_ip_packet};
use boringtun::noise::errors::WireGuardError;
pub use boringtun::sleepyinstant::{ClockDuration, WallClock};
use core::convert::Infallible;
use core::mem::MaybeUninit;
#[cfg(feature = "defmt")]
use defmt::{debug, error, info, warn};
use embassy_futures::select::{Either3, select3};
use embassy_net::Stack;
use embassy_net::udp::{BindError, RecvError, SendError, UdpSocket};
use embassy_net_driver_channel as ch;
use embassy_net_driver_channel::driver::LinkState;
use smoltcp::socket::udp::PacketMetadata;

/// 1500 (typical Ethernet/WiFi MTU) minus the worst-case overhead of
/// encapsulating a packet over an IPv6 outer transport: 40 (IPv6) + 8 (UDP)
/// + 32 (WireGuard data overhead) = 80. Matches upstream WireGuard's
/// `wg-quick` default tunnel MTU.
pub(crate) const MTU: usize = 1420;

/// Type alias for the embassy-net driver.
pub type Device<'d> = embassy_net_driver_channel::Device<'d, MTU>;

/// Internal state for the embassy-net integration.
pub struct State<const N_RX: usize, const N_TX: usize> {
    ch_state: ch::State<MTU, N_RX, N_TX>,
}

impl<const N_RX: usize, const N_TX: usize> State<N_RX, N_TX> {
    /// Create a new `State`.
    pub const fn new() -> Self {
        Self {
            ch_state: ch::State::new(),
        }
    }
}

/// Background runner for the driver.
///
/// You must call `.run()` in a background task for the driver to operate.
pub struct Runner<'d> {
    ch: ch::Runner<'d, MTU>,
}

/// Error returned by [`Runner::run`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RunError {
    Bind(BindError),
    /// Reading from the serial port failed.
    Read(RecvError),
    /// Writing to the serial got EOF.
    Eof,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WGError {
    SendRoutineError(SendError),
    SendDecapsulationError(SendError),
    SendEncryptedError(SendError),
    EncapsulationError(WireGuardError),
    ConnectionExpired,
    PreparationError(WireGuardError),
    ReceiveError,
    DecapsulationError(WireGuardError),
    Other,
}

impl<'d> Runner<'d> {
    /// You must call this in a background task for the driver to operate.
    ///
    /// If reading/writing to the underlying serial port fails, the link state
    /// is set to Down and the error is returned.
    ///
    /// It is allowed to cancel this function's future (i.e. drop it). This will terminate
    /// the wireguard connection and set the link state to Down.
    ///
    /// After this function returns or is canceled, you can call it again to establish
    /// a new wireguard connection.
    pub async fn run(
        &mut self,
        stack: Stack<'static>,
        config: &Config,
    ) -> Result<Infallible, RunError> {
        stack.wait_config_up().await;

        let (state_chan, mut rx_chan, mut tx_chan) = self.ch.borrow_split();
        state_chan.set_link_state(LinkState::Down);
        let _ondrop = OnDrop::new(|| state_chan.set_link_state(LinkState::Down));

        let mut rx_meta = [PacketMetadata::EMPTY; 1];
        let mut rx_buf = [0; MAX_PACKET];
        let mut tx_meta = [PacketMetadata::EMPTY; 1];
        let mut tx_buf = [0; MAX_PACKET];
        let mut buf = [0; MAX_PACKET];

        let mut socket =
            UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);

        #[cfg(feature = "defmt")]
        debug!("Bind to port {}", config.port);
        if let Err(e) = socket.bind(config.port) {
            #[cfg(feature = "defmt")]
            info!("bind error: {:?}", e);
            return Err(RunError::Bind(e));
        }

        let mut tun = create_tunnel(config);

        loop {
            let routine_fut = async {
                let mut send_buf = [0u8; MAX_PACKET];
                #[cfg(feature = "defmt")]
                debug!("Updating timers");
                let mut res = tun.update_timers(&mut send_buf);
                loop {
                    #[cfg(feature = "defmt")]
                    debug!("Handling routine result");
                    match handle_routine_tun_result(&socket, config, res).await {
                        Ok(_) => {
                            #[cfg(feature = "defmt")]
                            debug!("Successfully handled routine result");
                            state_chan.set_link_state(LinkState::Up);
                            break;
                        }
                        Err(e) => {
                            #[cfg(feature = "defmt")]
                            error!("{:?}", e);
                            if let WGError::ConnectionExpired = e {
                                #[cfg(feature = "defmt")]
                                warn!("Wireguard handshake has expired!");
                                res = tun.format_handshake_initiation(&mut send_buf, false);
                            } else {
                                state_chan.set_link_state(LinkState::Down);
                                break;
                            }
                        }
                    }
                }
            };

            let rx_fut = async {
                let rx_buf = rx_chan.rx_buf().await;
                let rx_data = match socket.recv_from(&mut buf).await {
                    Ok((0, remote_endpoint)) => return Err(RunError::Eof),
                    Ok((n, remote_endpoint)) => &buf[..n],
                    Err(e) => return Err(RunError::Read(e)),
                };
                Ok((rx_buf, rx_data))
            };
            let tx_fut = tx_chan.tx_buf();
            match select3(routine_fut, rx_fut, tx_fut).await {
                Either3::First(_) => {
                    #[cfg(feature = "defmt")]
                    debug!("Routine completed");
                }
                Either3::Second(r) => {
                    #[cfg(feature = "defmt")]
                    debug!("Have received packet to consume");
                    match consume(stack, &mut tun, &socket, config, r?).await {
                        Ok(len) => {
                            #[cfg(feature = "defmt")]
                            debug!("Consume successful");
                            if len > 0 {
                                rx_chan.rx_done(len);
                            }
                        }
                        Err(e) => {
                            #[cfg(feature = "defmt")]
                            error!("{:?}", e);
                        }
                    }
                }
                Either3::Third(pkt) => {
                    #[cfg(feature = "defmt")]
                    debug!("Have to send packet of {} bytes", pkt.len());
                    match send_ip_packet(&mut tun, &socket, config, pkt).await {
                        Ok(_) => {
                            tx_chan.tx_done();
                        }
                        Err(e) => {
                            #[cfg(feature = "defmt")]
                            error!("{:?}", e);
                        }
                    }
                }
            }
        }
    }
}

/// Create a WireGuard embassy-net driver instance.
///
/// This returns two structs:
/// - a `Device` that you must pass to the `embassy-net` stack.
/// - a `Runner`. You must call `.run()` on it in a background task.
pub fn new<const N_RX: usize, const N_TX: usize>(
    state: &'_ mut State<N_RX, N_TX>,
) -> (Device<'_>, Runner<'_>) {
    let (runner, device) = ch::new(&mut state.ch_state, ch::driver::HardwareAddress::Ip);
    (device, Runner { ch: runner })
}

struct OnDrop<F: FnOnce()> {
    f: MaybeUninit<F>,
}

impl<F: FnOnce()> OnDrop<F> {
    fn new(f: F) -> Self {
        Self {
            f: MaybeUninit::new(f),
        }
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}
