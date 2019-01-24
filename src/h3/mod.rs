// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! HTTP/3 client and server.

pub mod frame;
pub mod qpack;

use super::stream;
use super::Result;
use crate::octets;

// extern crate http;
use http::{
    Request,
    Response,
    StatusCode,
    Uri,
};

const H3_CONTROL_STREAM_TYPE_ID: u8 = 0x43;
const H3_PUSH_STREAM_TYPE_ID: u8 = 0x50;
const QPACK_ENCODER_STREAM_TYPE_ID: u8 = 0x48;
const QPACK_DECODER_STREAM_TYPE_ID: u8 = 0x68;

/// An HTTP/3  error.
#[derive(Clone, Debug, PartialEq)]
pub enum H3Error {
    // There is no error, just stream or connection close
    NoError,

    // Setting sent in wrong direction
    WrongSettingDirection,

    // The server attempted to push content that the client will not accept
    PushRefused,

    // Internal error in the H3 stack
    InternalError,

    // The server attempted to push something the client already has
    PushAlreadyInCache,

    // The client no longer needs the requested data
    RequestCancelled,

    // The request stream terminated before completing the request
    IncompleteRequest,

    // Forward connection failure for CONNECT target
    ConnectError,

    // Endpoint detected that the peer is exhibiting behaviour that causes
    // excessive load
    ExcessiveLoad,

    // Operation cannot be served over HTT/3. Retry over HTTP/1.1
    VersionFallback,

    // Frame received on stream where it is not permitted
    WrongStream,

    // Stream ID, Push ID or Placeholder Id greater that current maximum was
    // used
    LimitExceeded,

    // Push ID used in two different stream headers
    DuplicatePush,

    // Unknown unidirection stream type
    UnknownStreamType,

    // Too many unidirectional streams of a type were created
    WrongStreamCount,

    // A required critical stream was closed
    ClosedCriticalStream,

    // Unidirectional stream type opened at peer that is prohibited
    WrongStreamDirection,

    // Inform client that remainder of request is not needed. Used in
    // STOP_SENDING only
    EarlyResponse,

    // No SETTINGS frame at beggining of control stream
    MissingSettings,

    // A frame was received which is not permitted in the current state
    UnexpectedFrame,

    // Server rejected request without performing any application processing
    RequestRejected,

    // Peer violated protocol requirements in a way that doesn't match a more
    // specific code
    GeneralProtocolError,

    // TODO malformed frame where last byte is the frame type
    MalformedFrame,

    // QPACK Header block decompression failure
    QpackDecompressionFailed,

    // QPACK encoder stream error
    QpackEncoderStreamError,

    // QPACK decoder stream error
    QpackDecoderStreamError,
}

impl H3Error {
    pub fn to_wire(&self) -> u16 {
        match self {
            H3Error::NoError => 0x0,
            H3Error::WrongSettingDirection => 0x1,
            H3Error::PushRefused => 0x2,
            H3Error::InternalError => 0x3,
            H3Error::PushAlreadyInCache => 0x4,
            H3Error::RequestCancelled => 0x5,
            H3Error::IncompleteRequest => 0x6,
            H3Error::ConnectError => 0x07,
            H3Error::ExcessiveLoad => 0x08,
            H3Error::VersionFallback => 0x09,
            H3Error::WrongStream => 0xA,
            H3Error::LimitExceeded => 0xB,
            H3Error::DuplicatePush => 0xC,
            H3Error::UnknownStreamType => 0xD,
            H3Error::WrongStreamCount => 0xE,
            H3Error::ClosedCriticalStream => 0xF,
            H3Error::WrongStreamDirection => 0x10,
            H3Error::EarlyResponse => 0x11,
            H3Error::MissingSettings => 0x12,
            H3Error::UnexpectedFrame => 0x13,
            H3Error::RequestRejected => 0x14,
            H3Error::GeneralProtocolError => 0xFF,
            H3Error::MalformedFrame => 0x10,

            H3Error::QpackDecompressionFailed => 0x20, /* TODO spec value is
                                                         * still TBD */
            H3Error::QpackEncoderStreamError => 0x21, /* TODO spec value is
                                                        * still TBD */
            H3Error::QpackDecoderStreamError => 0x22, /* TODO spec value is
                                                       * still TBD */
        }
    }
}

pub struct H3Config {
    pub root_dir: String,
    pub num_placeholders: u64,
    pub max_header_list_size: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl H3Config {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<H3Config> {
        Ok(H3Config {
            root_dir: String::new(),
            num_placeholders: 16,
            max_header_list_size: 0,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        })
    }

    pub fn set_root_dir(&mut self, root_dir: &String) {
        self.root_dir = String::clone(root_dir);
    }

    pub fn set_num_placeholders(&mut self, num_placeholders: u64) {
        self.num_placeholders = num_placeholders;
    }

    pub fn set_max_header_list_size(&mut self, max_header_list_size: u64) {
        self.max_header_list_size = max_header_list_size;
    }

    pub fn set_qpack_max_table_capacity(
        &mut self, qpack_max_table_capacity: u64,
    ) {
        self.qpack_max_table_capacity = qpack_max_table_capacity;
    }

    pub fn set_qpacked_blocked_streams(&mut self, qpack_blocked_streams: u64) {
        self.qpack_blocked_streams = qpack_blocked_streams;
    }
}

/// An HTTP/3 connection.
pub struct H3Connection {
    root_dir: String,
    is_server: bool,

    num_placeholders: u64,
    max_header_list_size: u64,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,

    peer_num_placeholders: std::option::Option<u64>,
    peer_max_header_list_size: std::option::Option<u64>,
    peer_qpack_max_table_capacity: std::option::Option<u64>,
    peer_qpack_blocked_streams: std::option::Option<u64>,

    control_stream_open: bool,
    peer_control_stream_open: bool,

    qpack_encoder: qpack::Encoder,
    qpack_decoder: qpack::Decoder,

    qpack_encoder_stream_open: bool,
    peer_qpack_encoder_stream_open: bool,
    qpack_decoder_stream_open: bool,
    peer_qpack_decoder_stream_open: bool,
}

struct H3Util {}
impl H3Util {
    pub fn req_hdrs_to_qpack(
        encoder: &mut qpack::Encoder, request: &http::Request<()>,
    ) -> Vec<u8> {
        let mut vec = vec![0u8; 65535];

        let mut headers: Vec<qpack::Header> = Vec::new();

        headers.push(qpack::Header::new(":method", request.method().as_str()));
        headers.push(qpack::Header::new(
            ":scheme",
            request.uri().scheme_str().unwrap(),
        ));
        headers.push(qpack::Header::new(
            ":authority",
            request.uri().host().unwrap(),
        ));
        headers.push(qpack::Header::new(
            ":path",
            request.uri().path_and_query().unwrap().as_str(),
        ));

        for (key, value) in request.headers().iter() {
            headers
                .push(qpack::Header::new(key.as_str(), value.to_str().unwrap()));
        }

        let len = encoder.encode(&headers, &mut vec);

        vec.truncate(len.unwrap());
        trace!("Encoded header block len={:?}", len);

        vec
    }

    pub fn resp_hdrs_to_qpack(
        encoder: &mut qpack::Encoder, response: &http::Response<()>,
    ) -> Vec<u8> {
        let mut vec = vec![0u8; 65535];

        let mut headers: Vec<qpack::Header> = Vec::new();

        headers.push(qpack::Header::new(":status", response.status().as_str()));

        for (key, value) in response.headers().iter() {
            headers
                .push(qpack::Header::new(key.as_str(), value.to_str().unwrap()));
        }

        let len = encoder.encode(&headers, &mut vec);

        vec.truncate(len.unwrap());
        trace!("Encoded header block len={:?}", len);

        vec
    }

    pub fn req_hdrs_from_qpack(
        decoder: &mut qpack::Decoder, hdr_block: &mut Vec<u8>,
    ) -> http::Request<()> {
        let mut req: Request<()> = Request::default();

        // TODO make pseudo header parsing more efficient. Right now, we create
        // some variables to hold pseudo headers that may arrive in any order.
        // Some of these are later formatted back into a complete URI
        let mut method = String::new();
        let mut scheme = String::new();
        let mut authority = String::new();
        let mut path = String::new();

        for hdr in decoder.decode(hdr_block).unwrap() {
            // trace!("Header field - {}:{}", hdr.0, hdr.1);

            match hdr.name() {
                ":method" => {
                    method = hdr.value().to_string();
                },
                ":scheme" => {
                    scheme = hdr.value().to_string();
                },
                ":authority" => {
                    authority = hdr.value().to_string();
                },
                ":path" => {
                    path = hdr.value().to_string();
                },
                _ => {
                    req.headers_mut().insert(
                        http::header::HeaderName::from_bytes(
                            hdr.name().as_bytes(),
                        )
                        .unwrap(),
                        http::header::HeaderValue::from_str(hdr.value()).unwrap(),
                    );
                },
            }
        }

        let uri = format!("{}://{}{}", scheme, authority, path);

        *req.method_mut() = method.parse().unwrap();
        *req.version_mut() = http::Version::HTTP_2;
        *req.uri_mut() = uri.parse::<Uri>().unwrap();

        // debug!("Prepared request {:?}", req);

        req
    }

    pub fn resp_hdrs_from_qpack(
        decoder: &mut qpack::Decoder, hdr_block: &mut Vec<u8>,
    ) -> http::Response<()> {
        let mut resp: Response<()> = Response::default();

        // TODO make pseudo header parsing more efficient.
        let mut status = String::new();

        for hdr in decoder.decode(hdr_block).unwrap() {
            // trace!("Header field - {}:{}", hdr.0, hdr.1);

            match hdr.name() {
                ":status" => {
                    status = hdr.value().to_string();
                },
                _ => {
                    resp.headers_mut().insert(
                        http::header::HeaderName::from_bytes(
                            hdr.name().as_bytes(),
                        )
                        .unwrap(),
                        http::header::HeaderValue::from_str(hdr.value()).unwrap(),
                    );
                },
            }
        }

        *resp.status_mut() = StatusCode::from_bytes(status.as_bytes()).unwrap();
        *resp.version_mut() = http::Version::HTTP_2;

        // debug!("Prepared response {:?}", resp);

        resp
    }
}

impl H3Connection {
    #[allow(clippy::new_ret_no_self)]
    fn new(config: &mut H3Config, is_server: bool) -> Result<Box<H3Connection>> {
        let root = String::clone(&config.root_dir); // TODO shouldn't need to clone here

        Ok(Box::new(H3Connection {
            root_dir: root,
            is_server,
            num_placeholders: config.num_placeholders,
            max_header_list_size: config.max_header_list_size,
            qpack_max_table_capacity: config.qpack_max_table_capacity,
            qpack_blocked_streams: config.qpack_blocked_streams,

            peer_num_placeholders: None,
            peer_max_header_list_size: None,
            peer_qpack_max_table_capacity: None,
            peer_qpack_blocked_streams: None,

            control_stream_open: false,
            peer_control_stream_open: false,

            qpack_encoder: qpack::Encoder::new(),
            qpack_decoder: qpack::Decoder::new(),

            qpack_encoder_stream_open: false,
            peer_qpack_encoder_stream_open: false,
            qpack_decoder_stream_open: false,
            peer_qpack_decoder_stream_open: false,
        }))
    }

    fn get_control_stream_id(&mut self) -> u64 {
        // TODO get an available unidirectional stream ID more nicely
        if self.is_server {
            return 0x3;
        } else {
            return 0x2;
        }
    }

    fn is_control_stream(stream_id: u64) -> bool {
        // TODO make this respect stream types and NOT assume types from ID
        return stream_id == 0x2 || stream_id == 0x3;
    }

    fn get_encoder_stream_id(&mut self) -> u64 {
        // TODO get an available unidirectional stream ID more nicely
        if self.is_server {
            return 0x7;
        } else {
            return 0x6;
        }
    }

    fn get_decoder_stream_id(&mut self) -> u64 {
        // TODO get an available unidirectional stream ID more nicely
        if self.is_server {
            return 0xB;
        } else {
            return 0xA;
        }
    }

    pub fn is_established(&mut self) -> bool {
        self.control_stream_open &&
            self.qpack_encoder_stream_open &&
            self.qpack_decoder_stream_open
    }

    pub fn open_control_stream(&mut self, quic_conn: &mut super::Connection) {
        if !self.control_stream_open {
            let mut d = [42; 128];
            let mut b = octets::Octets::with_slice(&mut d);
            b.put_u8(H3_CONTROL_STREAM_TYPE_ID).unwrap();
            let off = b.off();
            let stream_id = self.get_control_stream_id();
            quic_conn
                .stream_send(stream_id, &mut d[..off], false)
                .unwrap();

            self.control_stream_open = true;
        }
    }

    pub fn open_qpack_streams(&mut self, quic_conn: &mut super::Connection) {
        if !self.qpack_encoder_stream_open {
            let mut e: [u8; 128] = [42; 128];
            let mut enc_b = octets::Octets::with_slice(&mut e);
            enc_b.put_u8(QPACK_ENCODER_STREAM_TYPE_ID).unwrap();
            let off = enc_b.off();
            let stream_id = self.get_encoder_stream_id();
            quic_conn
                .stream_send(stream_id, &mut e[..off], false)
                .unwrap();

            // TODO await ACK of stream open?
            self.qpack_encoder_stream_open = true;
        }

        if !self.qpack_decoder_stream_open {
            let mut d = [42; 128];
            let mut dec_b = octets::Octets::with_slice(&mut d);
            dec_b.put_u8(QPACK_DECODER_STREAM_TYPE_ID).unwrap();
            let off = dec_b.off();
            let stream_id = self.get_decoder_stream_id();
            quic_conn
                .stream_send(stream_id, &mut d[..off], false)
                .unwrap();

            // TODO await ACK of stream open?
            self.qpack_decoder_stream_open = true;
        }
    }

    pub fn create_placeholder_tree(&mut self, quic_conn: &mut super::Connection) {
        if self.num_placeholders > 0 {
            debug!("Going to prioritse {} placeholders", self.num_placeholders);
            // TODO make sure slice is large enough to hold
            // *all* PRIORITY frames. Worst case is ~7 bytes per frame.
            let mut d = [42; 255];
            let mut b = octets::Octets::with_slice(&mut d);

            let mut weight = 0;
            for i in 0..self.num_placeholders {
                let frame = frame::H3Frame::Priority {
                    priority_elem: frame::PrioritizedElemType::Placeholder,
                    elem_dependency: frame::ElemDependencyType::RootOfTree,
                    prioritized_element_id: Some(i),
                    element_dependency_id: None,
                    weight,
                };

                frame.to_bytes(&mut b).unwrap();

                weight += 1;
            }

            let off = b.off();
            debug!("Amount of priority bytes to send is {}", off);
            let stream_id = self.get_control_stream_id();

            quic_conn
                .stream_send(stream_id, &mut d[..off], false)
                .unwrap();
        }
    }

    // Send SETTINGS frame based on H3 config
    pub fn send_settings(&mut self, quic_conn: &mut super::Connection) {
        self.open_control_stream(quic_conn);

        let mut d = [42; 128];

        let num_placeholders = if self.is_server { Some(16) } else { None };

        let frame = frame::H3Frame::Settings {
            num_placeholders,
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        };

        let mut b = octets::Octets::with_slice(&mut d);

        frame.to_bytes(&mut b).unwrap();
        let off = b.off();
        let stream_id = self.get_control_stream_id();

        quic_conn
            .stream_send(stream_id, &mut d[..off], false)
            .unwrap();
    }

    // Send a request
    pub fn send_request(
        &mut self, request: http::Request<()>, quic_conn: &mut super::Connection,
    ) {
        let mut d = [42; 65535];

        let req_frame = frame::H3Frame::Headers {
            header_block: H3Util::req_hdrs_to_qpack(
                &mut self.qpack_encoder,
                &request,
            ),
        };

        let mut b = octets::Octets::with_slice(&mut d);
        req_frame.to_bytes(&mut b).unwrap();
        let off = b.off();

        // TODO get an available stream number
        quic_conn.stream_send(0, &mut d[..off], true).unwrap();
    }

    // Send a response
    pub fn send_response(
        &mut self, stream_id: u64, response: http::Response<()>,
        quic_conn: &mut super::Connection,
    ) {
        let mut d = [42; 65535];

        let headers = frame::H3Frame::Headers {
            header_block: H3Util::resp_hdrs_to_qpack(
                &mut self.qpack_encoder,
                &response,
            ),
        };

        let mut b = octets::Octets::with_slice(&mut d);
        headers.to_bytes(&mut b).unwrap();

        // TODO figure out type management of Response object
        // theory is that if there is no type, there can be no body
        // if !response.body().is_empty() {
        // let data = frame::H3Frame::Data {
        // payload: response.body().as_bytes().to_vec()
        // };
        // data.to_bytes(&mut b).unwrap();
        // }

        let off = b.off();

        info!(
            "{} sending response of size {} on stream {}",
            quic_conn.trace_id(),
            off,
            stream_id
        );

        if let Err(e) = quic_conn.stream_send(stream_id, &mut d[..off], true) {
            error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
        }
    }

    pub fn handle_stream(
        &mut self, stream_id: u64, quic_conn: &mut super::Connection,
    ) -> Result<()> {
        let mut buf = [0; 65535];
        let (read, fin) = quic_conn.stream_recv(stream_id, &mut buf)?;
        let mut stream_buf = &mut buf[..read];

        let stream_buf_len = stream_buf.len();
        info!(
            "{} stream {} has {} bytes (fin? {})",
            quic_conn.trace_id(),
            stream_id,
            stream_buf_len,
            fin
        );

        // H3 unidirectional streams have types as first byte
        if !stream::is_bidi(stream_id) {
            let mut o = octets::Octets::with_slice(&mut stream_buf);
            while o.off() < stream_buf_len {
                // trace!("loop de loop");
                // dbg!(&stream_buf);
                if o.off() == 0 {
                    let stream_type = o.get_u8().unwrap();
                    info!(
                        "{} stream {} has type value {}",
                        quic_conn.trace_id(),
                        stream_id,
                        stream_type
                    );
                    match stream_type {
                        H3_CONTROL_STREAM_TYPE_ID => {
                            info!(
                                "{} stream {} is a control stream",
                                quic_conn.trace_id(),
                                stream_id
                            );
                            if self.peer_control_stream_open {
                                // Error, only one control stream allowed
                                let err = H3Error::WrongStreamCount;
                                quic_conn.close(true, err.to_wire(), b"")?;
                            } else {
                                // dbg!(&mut stream_buf);
                            }
                        },
                        H3_PUSH_STREAM_TYPE_ID => {
                            info!(
                                "{} stream {} is a push stream",
                                quic_conn.trace_id(),
                                stream_id
                            );
                        },
                        QPACK_ENCODER_STREAM_TYPE_ID => {
                            info!(
                                "{} stream {} is a QPACK encoder stream",
                                quic_conn.trace_id(),
                                stream_id
                            );
                            if self.peer_qpack_encoder_stream_open {
                                // Error, only one control stream allowed
                                let err = H3Error::WrongStreamCount;
                                quic_conn.close(true, err.to_wire(), b"")?;
                            }
                        },
                        QPACK_DECODER_STREAM_TYPE_ID => {
                            info!(
                                "{} stream {} is a QPACK decoder stream",
                                quic_conn.trace_id(),
                                stream_id
                            );
                            if self.peer_qpack_decoder_stream_open {
                                // Error, only one control stream allowed
                                let err = H3Error::WrongStreamCount;
                                quic_conn.close(true, err.to_wire(), b"")?;
                            }
                        },
                        _ => {
                            info!("{} stream {} is an unknown stream type (val={})!", quic_conn.trace_id(), stream_id, stream_type);
                        },
                    }
                } else if o.off() == 1 {
                    let frame = frame::H3Frame::from_bytes(&mut o).unwrap();
                    debug!(
                        "first received frame on stream {} is {:?}",
                        stream_id, frame
                    );

                    match frame {
                        frame::H3Frame::Settings {
                            num_placeholders,
                            max_header_list_size,
                            qpack_max_table_capacity,
                            qpack_blocked_streams,
                        } =>
                            if self.is_server && num_placeholders.is_some() {
                                let err = H3Error::WrongSettingDirection;
                                quic_conn.close(
                                    true,
                                    err.to_wire(),
                                    b"You sent me a num_placeholders.",
                                )?;
                            } else {
                                self.peer_num_placeholders = num_placeholders;
                                self.peer_max_header_list_size =
                                    max_header_list_size;
                                self.peer_qpack_max_table_capacity =
                                    qpack_max_table_capacity;
                                self.peer_qpack_blocked_streams =
                                    qpack_blocked_streams;
                                self.peer_control_stream_open = true;
                            },
                        _ => {
                            error!("SETTINGS frame must be first on control stream! Received type={:?}", frame);
                            let err = H3Error::MissingSettings;
                            quic_conn.close(
                                true,
                                err.to_wire(),
                                b"Non-settings sent as first frame.",
                            )?;
                        },
                    }
                } else {
                    // after first SETTINGS, most frames are OK
                    let frame = frame::H3Frame::from_bytes(&mut o).unwrap();
                    debug!(
                        "addtional received frame on stream {} is {:?}",
                        stream_id, frame
                    );

                    match frame {
                        frame::H3Frame::Settings { .. } => {
                            debug!("SETTINGS frame must be first on control stream! Received type={:?}", frame);
                            let err = H3Error::UnexpectedFrame;
                            quic_conn.close(
                                true,
                                err.to_wire(),
                                b"You sent me SETTINGS too late.",
                            )?;
                        },
                        frame::H3Frame::Priority { .. } =>
                            debug!("Priority frame received. "),
                        _ => {
                            debug!("Unsupported frame must be first on control stream! Received type={:?}", frame);
                            let err = H3Error::MissingSettings;
                            quic_conn.close(
                                true,
                                err.to_wire(),
                                b"Non-settings sent as first frame.",
                            )?;
                        },
                    }
                }
            }
        } else {
            // TODO stream frame parsing
            if stream_buf.len() > 1 {
                let mut o = octets::Octets::with_slice(&mut stream_buf);
                let frame = frame::H3Frame::from_bytes(&mut o).unwrap();
                debug!("received {:?}", frame);

                match frame {
                    frame::H3Frame::Headers { mut header_block } => {
                        // debug!("received {:?}", frame);
                        // dbg!(&header_block);

                        if self.is_server {
                            let req = H3Util::req_hdrs_from_qpack(
                                &mut self.qpack_decoder,
                                &mut header_block,
                            );

                            info!(
                                "{} got request {:?} on stream {}",
                                quic_conn.trace_id(),
                                req,
                                stream_id
                            );

                            // TODO *actually* parse the request and respond
                            // with something other than 404
                            let resp = Response::builder()
                                .status(404)
                                .version(http::Version::HTTP_2)
                                .header("Server", "quiche-h3")
                                .body(())
                                .unwrap();

                            self.send_response(stream_id, resp, quic_conn);
                        } else {
                            let resp = H3Util::resp_hdrs_from_qpack(
                                &mut self.qpack_decoder,
                                &mut header_block,
                            );
                            info!(
                                "{} got response {:?} on stream {}",
                                quic_conn.trace_id(),
                                resp,
                                stream_id
                            );

                            if fin {
                                info!(
                                    "{} response received, closing..,",
                                    quic_conn.trace_id()
                                );
                                quic_conn.close(true, 0x00, b"kthxbye").unwrap();
                            }
                        }
                    },

                    _ => {
                        debug!("TODO: Frame not implemented/supported on bidi stream! type={:?}", frame);
                    },
                };
            }
        }

        Ok(())
    }
}

/// Creates a new client-side connection.
pub fn connect(config: &mut H3Config) -> Result<Box<H3Connection>> {
    let conn = H3Connection::new(config, false)?;

    Ok(conn)
}

/// Creates a new server-side connection.
pub fn accept(config: &mut H3Config) -> Result<Box<H3Connection>> {
    let conn = H3Connection::new(config, true)?;

    Ok(conn)
}
