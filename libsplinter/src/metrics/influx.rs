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
use std::sync::mpsc::{channel, Sender};
use std::thread;

use chrono::{DateTime, Utc};
use influxdb::InfluxDbWriteable;
use influxdb::{Client, Query, Timestamp, WriteQuery};
use metrics_lib::{Key, Recorder, SetRecorderError};
use tokio::runtime::Runtime;

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
    Counter { key: String, value: u64 },
    Gauge { key: String, value: i64 },
    Histogram { key: String, value: u64 },
    Shutdown,
}

pub struct InfluxRecorder {
    join_handle: thread::JoinHandle<()>,
    sender: Sender<MetricRequest>,
}

impl InfluxRecorder {
    // TODO pass values to client in inner
    pub fn new() -> Result<Self, InternalError> {
        let (sender, recv) = channel();
        let thread_builder = thread::Builder::new().name("MetricReactor".into());
        let mut rt = Runtime::new().map_err(|err| {
            InternalError::with_message("Unable to start metrics runtime".to_string())
        })?;
        let join_handle = thread_builder
            .spawn(move || {
                let client =
                    Client::new("http://localhost:8086", "metrics").with_auth("admin", "foobar");
                let mut counters: HashMap<String, Counter> = HashMap::new();

                loop {
                    match recv.recv() {
                        Ok(MetricRequest::Counter { key, value }) => {
                            let counter = {
                                if let Some(mut counter) = counters.get_mut(&key) {
                                    counter.value += 1;
                                    counter.time = Utc::now();
                                    counter.clone()
                                } else {
                                    let counter = Counter {
                                        time: Utc::now(),
                                        key: key.to_string(),
                                        value,
                                    };
                                    counters.insert(key.to_string(), counter.clone());
                                    counter
                                }
                            };

                            let query = counter.into_query(key);
                            // block on future, cannot call spawn because future does not live
                            // long enough because query takes a reference
                            rt.block_on(client.query(&query));
                        }
                        Ok(MetricRequest::Gauge { key, value }) => {
                            let gauge = Gauge {
                                time: Utc::now(),
                                key: key.to_string(),
                                value,
                            };
                            let query = gauge.into_query(key);
                            // block on future, cannot call spawn because future does not live
                            // long enough because query takes a reference
                            rt.block_on(client.query(&query));
                        }
                        Ok(MetricRequest::Histogram { key, value }) => {
                            let histogram = Histogram {
                                time: Utc::now(),
                                key: key.to_string(),
                                value,
                            };
                            let query = histogram.into_query(key);
                            // block on future, cannot call spawn because future does not live
                            // long enough because query takes a reference
                            rt.block_on(client.query(&query));
                        }
                        Ok(MetricRequest::Shutdown) => {
                            info!("Received MetricRequest::Shutdown");
                            break;
                        }
                        _ => unimplemented!(),
                    }
                }
            })
            .map_err(|err| InternalError::from_source(Box::new(err)))?;

        Ok(Self {
            join_handle,
            sender: sender,
        })
    }

    pub fn init() -> Result<(), InternalError> {
        let recorder = Self::new()?;
        metrics_lib::set_boxed_recorder(Box::new(recorder))
            .map_err(|err| InternalError::from_source(Box::new(err)))
    }
}

impl ShutdownHandle for InfluxRecorder {
    fn signal_shutdown(&mut self) {
        if let Err(_) = self.sender.send(MetricRequest::Shutdown) {
            error!("Unable to send shutdown message to InfluxRecorder");
        }
    }

    fn wait_for_shutdown(self) -> Result<(), InternalError> {
        self.join_handle.join().map_err(|err| {
            InternalError::with_message(format!("Unable to join InfluxRecorder thread: {:?}", err))
        })
    }
}

impl Recorder for InfluxRecorder {
    fn increment_counter(&self, key: Key, value: u64) {
        let name = key.name().to_string();
        if let Err(err) = self
            .sender
            .send(MetricRequest::Counter { key: name, value })
        {
            error!("Unable to submit metric, sender has dropped")
        }
    }

    fn update_gauge(&self, key: Key, value: i64) {
        let name = key.name().to_string();
        if let Err(err) = self.sender.send(MetricRequest::Gauge { key: name, value }) {
            error!("Unable to submit metric, sender has dropped")
        }
    }

    fn record_histogram(&self, key: Key, value: u64) {
        let name = key.name().to_string();
        if let Err(err) = self
            .sender
            .send(MetricRequest::Histogram { key: name, value })
        {
            error!("Unable to submit metric, sender has dropped")
        }
    }
}
