// Copyright 2018-2021 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use influxdb::InfluxDbWriteable;
use influxdb::{Client, Query, Timestamp, WriteQuery};
use metrics_lib::{Key, Recorder, SetRecorderError};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;

use crate::error::InternalError;
use crate::threading::lifecycle::ShutdownHandle;

#[derive(InfluxDbWriteable, Clone)]
struct Counter {
    time: DateTime<Utc>,
    key: String,
    value: u64,
}

#[derive(InfluxDbWriteable, Clone)]
struct Gauge {
    time: DateTime<Utc>,
    key: String,
    value: i64,
}

#[derive(InfluxDbWriteable, Clone)]
struct Histogram {
    time: DateTime<Utc>,
    key: String,
    value: u64,
}

enum MetricRequest {
    Counter {
        key: String,
        value: u64,
        time: DateTime<Utc>,
    },
    Gauge {
        key: String,
        value: i64,
        time: DateTime<Utc>,
    },
    Histogram {
        key: String,
        value: u64,
        time: DateTime<Utc>,
    },
    Shutdown,
}

pub struct InfluxRecorder {
    sender: UnboundedSender<MetricRequest>,
    join_handle: JoinHandle<()>,
    rt: Runtime,
}

impl InfluxRecorder {
    // TODO pass values to client
    pub fn new() -> Result<Self, InternalError> {
        let (sender, mut recv) = unbounded_channel();
        let mut rt = Runtime::new().map_err(|err| {
            InternalError::with_message("Unable to start metrics runtime".to_string())
        })?;

        let client =
            Client::new("http://localhost:8086", "metrics").with_auth("admin", "foobar");

        let join_handle = rt.spawn(async move {
            let mut counters: HashMap<String, Counter> = HashMap::new();
            error!("START Loop");
            loop {
                match recv.recv().await {
                    Some(MetricRequest::Counter { key, value, time }) => {
                        let counter = {
                            if let Some(mut counter) = counters.get_mut(&key) {
                                counter.value += 1;
                                counter.time = time;
                                counter.clone()
                            } else {
                                let counter = Counter {
                                    time,
                                    key: key.to_string(),
                                    value,
                                };
                                counters.insert(key.to_string(), counter.clone());
                                counter
                            }
                        };

                        let query = counter.into_query(key);
                        client.query(&query).await;
                    }
                    Some(MetricRequest::Gauge { key, value, time }) => {
                        let gauge = Gauge {
                            time,
                            key: key.to_string(),
                            value,
                        };
                        let query = gauge.into_query(key);
                        client.query(&query).await;
                    }
                    Some(MetricRequest::Histogram { key, value, time }) => {
                        let histogram = Histogram {
                            time,
                            key: key.to_string(),
                            value,
                        };
                        let query = histogram.into_query(key);
                        client.query(&query).await;
                    }
                    Some(MetricRequest::Shutdown) => {
                        info!("Received MetricRequest::Shutdown");
                        break;
                    }
                    _ => unimplemented!(),
                }
            }
        });

        Ok(Self {
            sender,
            join_handle,
            rt,
        })
    }

    pub fn init() -> Result<(), InternalError> {
        let recorder = Self::new()?;
        metrics_lib::set_boxed_recorder(Box::new(recorder))
            .map_err(|err| InternalError::from_source(Box::new(err)))
    }
}

// impl ShutdownHandle for InfluxRecorder {
//     fn signal_shutdown(&mut self) {
//         if let Err(_) = self.sender.send(MetricRequest::Shutdown) {
//             error!("Unable to send shutdown message to InfluxRecorder");
//         }
//     }
//
//     fn wait_for_shutdown(self) -> Result<(), InternalError> {
//         self.join_handle.join().map_err(|err| {
//             InternalError::with_message(format!("Unable to join InfluxRecorder thread: {:?}", err))
//         })
//     }
// }

impl Recorder for InfluxRecorder {
    fn increment_counter(&self, key: Key, value: u64) {
        let name = key.name().to_string();
        self.sender.send(MetricRequest::Counter {
            key: name,
            value,
            time: Utc::now(),
        });
    }

    fn update_gauge(&self, key: Key, value: i64) {
        let name = key.name().to_string();
        self.sender.send(MetricRequest::Gauge {
            key: name,
            value,
            time: Utc::now(),
        });
    }

    fn record_histogram(&self, key: Key, value: u64) {
        let name = key.name().to_string();
        self.sender.send(MetricRequest::Histogram {
            key: name,
            value,
            time: Utc::now(),
        });
    }
}
