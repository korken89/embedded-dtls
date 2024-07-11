#![no_std]

pub use postcard_rpc;

use postcard::experimental::schema::Schema;
use serde::{Deserialize, Serialize};

/// Topics are defined here, that is unsolicited messages.
/// They can go in either direction, Backend -> Device or Backend <- Device, however it's up to the
/// application to descide.
pub mod topics {
    /// A heartbeat message.
    pub mod heartbeat {
        use super::super::*;
        use postcard_rpc::topic;

        // This is how you define a topic.
        topic!(TopicHeartbeat, Heartbeat, "topic/heartbeat");

        /// Heartbeat from devices to backend, here one might also have device health info,
        /// performance counters, etc.
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Schema)]
        pub struct Heartbeat {
            /// Some device info value example.
            pub value: f32,
            /// Another thing, maybe Ethernet performance counters.
            pub sequence_number: u32,
        }
    }

    /// Another topic with some streaming data.
    pub mod some_data {
        use super::super::*;
        use postcard_rpc::topic;

        // This is how you define a topic.
        topic!(TopicSomeData, SomeData, "topic/somedata");

        /// Another unsolicited message.
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Schema)]
        pub struct SomeData {
            /// With some data.
            pub data: u64,
        }
    }
}

/// Endpoints are the core RPC API.
pub mod endpoints {
    /// A sleep command, that is we expect the answer to the command after a specific time.
    pub mod sleep {
        use postcard_rpc::endpoint;

        use super::super::*;

        // This is the definition of an endpoint.
        endpoint!(SleepEndpoint, Sleep, SleepDone, "endpoint/sleep");

        /// Sleep request.
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Schema)]
        pub struct Sleep {
            pub seconds: u32,
            pub micros: u32,
        }

        /// Sleep response.
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Schema)]
        pub struct SleepDone {
            pub slept_for: Sleep,
        }
    }

    /// A command that is expected to answer instantly, Ping/Pong to measure round trip time.
    pub mod pingpong {
        use postcard_rpc::endpoint;

        use super::super::*;

        // This is the definition of an endpoint.
        endpoint!(PingPongEndpoint, Ping, Pong, "endpoint/pingpong");

        /// Ping request.
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        #[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize, Schema)]
        pub struct Ping {}

        /// Pong response.
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        #[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize, Schema)]
        pub struct Pong {}
    }
}

/// When something is not possible to understand that comes over the wire the device can answer
/// with these errors.
pub mod wire_error {
    use postcard_rpc::Key;

    use super::*;

    /// Error path.
    pub const ERROR_PATH: &str = "error";
    /// Key generated for the error path.
    pub const ERROR_KEY: Key = Key::for_path::<FatalError>(ERROR_PATH);

    /// Fatal errors on the embedded device.
    #[derive(Debug, PartialEq, Serialize, Deserialize, Schema)]
    pub enum FatalError {
        /// We're asking for an endpoint the embedded device does not know about.
        UnknownEndpoint,
        /// The internal dispatcher in the embedded device is full of requests and can't enqueue.
        NotEnoughSenders,
        /// Ser(/de) error, malformed packet.
        WireFailure,
    }
}
