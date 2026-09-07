use crate::MTU;
use crate::WGError;
use crate::WGError::{EncapsulationError, Other, SendRoutineError};
use crate::config::{Config, PortProtocol};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
#[cfg(feature = "defmt")]
use defmt::{debug, error, info, trace, warn};
use embassy_net::Stack;
use embassy_net::udp::UdpSocket;
use embassy_time::Timer;
#[cfg(feature = "proto-ipv4")]
use smoltcp::wire::Ipv4Packet;
#[cfg(feature = "proto-ipv6")]
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::{IpProtocol, IpVersion};

/// Fixed per-packet overhead boringtun adds to a data packet (message type,
/// sender index, counter and AEAD auth tag; see `DATA_OVERHEAD_SZ` in
/// `boringtun::noise`).
const WG_DATA_OVERHEAD: usize = 32;

/// Large enough to encapsulate an outgoing full-MTU packet, and to guarantee
/// that decapsulating a received packet can never produce a plaintext IP
/// packet larger than `MTU`.
pub(crate) const MAX_PACKET: usize = MTU + WG_DATA_OVERHEAD;

pub async fn send_ip_packet(
    tun: &mut Tunn,
    socket: &UdpSocket<'_>,
    config: &Config,
    packet: &[u8],
) -> Result<(), WGError> {
    trace_ip_packet("Sending IP packet", packet);
    let mut send_buf = [0u8; MAX_PACKET];
    let encapsulate_result = tun.encapsulate(packet, &mut send_buf);
    match encapsulate_result {
        TunnResult::WriteToNetwork(packet) => {
            let res = socket.send_to(packet, config.endpoint_addr).await;
            #[cfg(feature = "defmt")]
            debug!(
                "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                packet.len()
            );
            res.map_err(WGError::SendEncryptedError)
        }
        TunnResult::Err(e) => {
            #[cfg(feature = "defmt")]
            error!("Failed to encapsulate an IP packet: {:?}", e);
            Err(EncapsulationError(e))
        }
        TunnResult::Done => {
            // Ignored
            #[cfg(feature = "defmt")]
            debug!("Encapsulation resulted in Done, ignoring");
            Ok(())
        }
        other => {
            #[cfg(feature = "defmt")]
            error!(
                "Unexpected WireGuard state during encapsulation: {:?}",
                other
            );
            Err(Other)
        }
    }
}

pub(crate) async fn handle_routine_tun_result(
    socket: &UdpSocket<'_>,
    config: &Config,
    result: TunnResult<'_>,
) -> Result<(), WGError> {
    match result {
        TunnResult::WriteToNetwork(packet) => {
            #[cfg(feature = "defmt")]
            debug!(
                "Sending a routine packet of {} bytes to {}",
                packet.len(),
                config.endpoint_addr
            );
            socket
                .send_to(packet, config.endpoint_addr)
                .await
                .map_err(SendRoutineError)
        }
        TunnResult::Err(WireGuardError::ConnectionExpired) => {
            #[cfg(feature = "defmt")]
            warn!("Wireguard handshake has expired!");

            Err(WGError::ConnectionExpired)
        }
        TunnResult::Err(e) => {
            #[cfg(feature = "defmt")]
            error!(
                "Failed to prepare a routine packet for WireGuard endpoint: {:?}",
                e
            );

            Err(WGError::PreparationError(e))
        }
        TunnResult::Done => {
            // Sleep for a bit
            #[cfg(feature = "defmt")]
            debug!("WireGuard routine task done, sleeping for 1 ms");
            Timer::after_millis(1).await;
            Ok(())
        }
        other => {
            #[cfg(feature = "defmt")]
            warn!("Unexpected WireGuard routine task state: {:?}", other);
            Err(Other)
        }
    }
}

pub async fn consume(
    stack: Stack<'_>,
    tun: &mut Tunn,
    socket: &UdpSocket<'_>,
    config: &Config,
    r: (&mut [u8], &[u8]),
) -> Result<usize, WGError> {
    let (buf, rx_data) = r;
    let mut send_buf = [0u8; MAX_PACKET];

    let decapsulate_result = tun.decapsulate(None, rx_data, &mut send_buf);
    match decapsulate_result {
        TunnResult::WriteToNetwork(packet) => {
            #[cfg(feature = "defmt")]
            debug!(
                "Decapsulation requested sending a packet to {}",
                config.endpoint_addr
            );
            match socket.send_to(packet, config.endpoint_addr).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    #[cfg(feature = "defmt")]
                    error!(
                        "Failed to send a decapsulation-instructed packet to WireGuard endpoint: {:?}",
                        e
                    );
                    Err(WGError::SendDecapsulationError(e))
                }
            }?;
            loop {
                let mut send_buf = [0u8; MAX_PACKET];
                match tun.decapsulate(None, &[], &mut send_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        match socket.send_to(packet, config.endpoint_addr).await {
                            Ok(_) => break Ok(0),
                            Err(e) => {
                                #[cfg(feature = "defmt")]
                                error!(
                                    "Failed to send a decapsulation-instructed packet to WireGuard endpoint: {:?}",
                                    e
                                );
                                Err(WGError::SendDecapsulationError(e))
                            }
                        }?
                    }
                    TunnResult::Err(e) => {
                        #[cfg(feature = "defmt")]
                        error!("Failed to decapsulate a received packet: {:?}", e);
                    }
                    _ => break Ok(0),
                }
            }
        }
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            #[cfg(feature = "defmt")]
            debug!(
                "WireGuard endpoint sent an IP packet of {} bytes",
                packet.len()
            );

            // For debugging purposes: parse packet
            trace_ip_packet("Received IP packet", packet);

            if packet.len() > buf.len() {
                #[cfg(feature = "defmt")]
                error!(
                    "Decapsulated packet of {} bytes does not fit in the {} byte rx buffer, dropping",
                    packet.len(),
                    buf.len()
                );
                return Ok(0);
            }

            if let Some(proto) = route_protocol(config, packet) {
                buf[..packet.len()].copy_from_slice(packet);
                Ok(packet.len())
            } else {
                #[cfg(feature = "defmt")]
                debug!("Dropping decapsulated packet: not routable to the local peer");
                Ok(0)
            }
        }
        TunnResult::Err(e) => {
            #[cfg(feature = "defmt")]
            error!("Failed to decapsulate a received packet: {:?}", e);
            Ok(0)
        }
        _ => Ok(0),
    }
}

pub(crate) fn create_tunnel(config: &Config) -> Tunn {
    Tunn::new(
        config.private_key.clone(),
        config.endpoint_public_key,
        config.preshared_key,
        config.keepalive_seconds,
        0,
        None,
    )
}

/// Determine the inner protocol of the incoming IP packet (TCP/UDP).
pub(crate) fn route_protocol(config: &Config, packet: &[u8]) -> Option<PortProtocol> {
    match IpVersion::of_packet(packet) {
        #[cfg(feature = "proto-ipv4")]
        Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
            .ok()
            // Only care if the packet is destined for this tunnel
            .filter(|packet| packet.dst_addr() == config.source_peer_ip)
            .and_then(|packet| match packet.next_header() {
                IpProtocol::Tcp => Some(PortProtocol::Tcp),
                IpProtocol::Udp => Some(PortProtocol::Udp),
                // Unrecognized protocol, so we cannot determine where to route
                _ => None,
            }),
        #[cfg(feature = "proto-ipv6")]
        Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
            .ok()
            // Only care if the packet is destined for this tunnel
            .filter(|packet| packet.dst_addr() == config.source_peer_ip)
            .and_then(|packet| match packet.next_header() {
                IpProtocol::Tcp => Some(PortProtocol::Tcp),
                IpProtocol::Udp => Some(PortProtocol::Udp),
                // Unrecognized protocol, so we cannot determine where to route
                _ => None,
            }),
        _ => None,
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    #[cfg(feature = "defmt")]
    {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                defmt::Display2Format(&PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet))
            ),
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                defmt::Display2Format(&PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet))
            ),
            _ => {}
        }
    }
}
