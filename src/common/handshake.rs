use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};

use rustls::server::AcceptedAlert;
use rustls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::{Stream, SyncWriteAdapter, TlsState};

pub(crate) trait IoSession {
    type Io;
    type Session;

    fn skip_handshake(&self) -> bool;
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session, &mut bool);
    fn into_io(self) -> Self::Io;
}

pub(crate) enum MidHandshake<IS: IoSession> {
    Handshaking(IS),
    End,
    SendAlert {
        io: IS::Io,
        alert: AcceptedAlert,
        error: io::Error,
    },
    Error {
        io: IS::Io,
        error: io::Error,
    },
    JlsForward {
        io: IS::Io,
        upstream: Option<String>,
        rate_limit: u64,
        clienthello: Vec<u8>,
    },
}

impl<IS, SD> Future for MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    type Output = Result<IS, (io::Error, IS::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match mem::replace(this, Self::End) {
            Self::Handshaking(stream) => stream,
            Self::SendAlert {
                mut io,
                mut alert,
                error,
            } => loop {
                match alert.write(&mut SyncWriteAdapter { io: &mut io, cx }) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        *this = Self::SendAlert { io, error, alert };
                        return Poll::Pending;
                    }
                    Err(_) | Ok(0) => return Poll::Ready(Err((error, io))),
                    Ok(_) => {}
                };
            },
            // Starting the handshake returned an error; fail the future immediately.
            Self::Error { io, error } => return Poll::Ready(Err((error, io))),
            Self::JlsForward {
                io,
                upstream: Some(upstream),
                rate_limit,
                clienthello,
            } => todo!("Implement JlsForward with upstream"),
            Self::JlsForward {
                io,
                upstream: None,
                rate_limit,
                clienthello,
            } => {
                tracing::warn!("JLS authentication failed but no upstream is assigned");
                return Poll::Ready(Err((
                    io::Error::new(io::ErrorKind::Other, "JLS authentication failed"),
                    io,
                )));
            }
            _ => panic!("unexpected polling after handshake"),
        };

        if !stream.skip_handshake() {
            let (state, io, session, need_flush) = stream.get_mut();
            let mut tls_stream = Stream::new(io, session)
                .set_eof(!state.readable())
                .set_need_flush(*need_flush);

            macro_rules! try_poll {
                ( $e:expr ) => {
                    match $e {
                        Poll::Ready(Ok(x)) => x,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                        Poll::Pending => {
                            *need_flush = tls_stream.need_flush;
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                };
            }

            while tls_stream.session.is_handshaking() {
                try_poll!(tls_stream.handshake(cx));
            }

            try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
        }

        Poll::Ready(Ok(stream))
    }
}

// #[derive(Debug)]
// pub(crate) struct JlsRateLimiter {
//     last_cycle: Instant,
//     data_handled: usize, // Data amount handled since last cycle
//     cycle_period: Duration,
//     pub bytes_per_cycle: usize,
// }
// impl JlsRateLimiter {
//     pub(crate) fn new(cycle_period: Duration, bytes_per_cycle: usize) -> Self {
//         Self {
//             last_cycle: Instant::now(),
//             data_handled: 0,
//             cycle_period,
//             bytes_per_cycle,
//         }
//     }
//     pub(crate) fn should_send(&mut self, data_size: usize, now: Instant) -> bool {
//         if now.duration_since(self.last_cycle) >= self.cycle_period {
//             self.data_handled = 0;
//             self.last_cycle = now;
//         }
//         if self.data_handled + data_size > self.bytes_per_cycle {
//             // 128K per cycle
//             return false;
//         }
//         self.data_handled += data_size;
//         true
//     }
//     pub(crate) fn try_send(
//         &mut self,
//         buf: &[u8],
//         trans: Transmit,
//         socket: &dyn AsyncUdpSocket,
//         now: Instant,
//     ) -> bool {
//         if self.should_send(buf.len(), now) {
//             respond(trans, buf, socket);
//             return true;
//         }
//         false
//     }
// }
