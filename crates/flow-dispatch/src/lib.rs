#![no_std]

//! Bounded, allocation-free inner-flow affinity dispatcher.
//!
//! The first implementation deliberately provides stable affinity only. It
//! does not stripe packets, perform weighted placement, or migrate live flows
//! for load balancing. Those features require separate measurement and tests.

use ghoncha_packet::flow::FlowKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    key: FlowKey,
    worker_id: u16,
    last_seen_ns: u64,
}

/// A transport allocation eligible to receive newly assigned flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Worker {
    pub id: u16,
    pub eligible: bool,
}

/// Why a dispatch operation selected the returned worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchKind {
    NewFlow,
    AffinityHit,
    RemappedAfterWorkerLoss,
}

/// Result of assigning one packet's flow to a worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchDecision {
    pub worker_id: u16,
    pub kind: DispatchKind,
}

/// Errors from bounded flow dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    NoEligibleWorkers,
    FlowTableFull,
}

/// Monotonic counters for diagnosing scheduler utilization and table pressure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchMetrics {
    pub lookups: u64,
    pub affinity_hits: u64,
    pub new_assignments: u64,
    pub remaps: u64,
    pub expired_entries: u64,
    pub table_full: u64,
    pub no_eligible_worker: u64,
}

/// Fixed-capacity flow table. Storage is embedded in the dispatcher.
pub struct FlowDispatcher<const CAPACITY: usize> {
    entries: [Option<Entry>; CAPACITY],
    expiry_cursor: usize,
    metrics: DispatchMetrics,
}

impl<const CAPACITY: usize> FlowDispatcher<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            expiry_cursor: 0,
            metrics: DispatchMetrics {
                lookups: 0,
                affinity_hits: 0,
                new_assignments: 0,
                remaps: 0,
                expired_entries: 0,
                table_full: 0,
                no_eligible_worker: 0,
            },
        }
    }

    /// Assigns a flow to an eligible worker and preserves that assignment.
    ///
    /// The caller must provide a unique worker ID for each entry. Flow expiry
    /// is explicit and budgeted through expire_idle(), never performed as an
    /// unbounded sweep on the packet hot path.
    pub fn dispatch(
        &mut self,
        key: FlowKey,
        now_ns: u64,
        workers: &[Worker],
    ) -> Result<DispatchDecision, DispatchError> {
        self.metrics.lookups = self.metrics.lookups.saturating_add(1);
        if CAPACITY == 0 {
            self.metrics.table_full = self.metrics.table_full.saturating_add(1);
            return Err(DispatchError::FlowTableFull);
        }

        let start = (key.stable_hash() as usize) % CAPACITY;
        let mut found = None;
        let mut vacant = None;

        for offset in 0..CAPACITY {
            let index = (start + offset) % CAPACITY;
            match self.entries[index] {
                Some(entry) if entry.key == key => {
                    found = Some((index, entry));
                    break;
                }
                None if vacant.is_none() => vacant = Some(index),
                _ => {}
            }
        }

        if let Some((index, mut entry)) = found {
            if worker_is_eligible(workers, entry.worker_id) {
                entry.last_seen_ns = entry.last_seen_ns.max(now_ns);
                self.entries[index] = Some(entry);
                self.metrics.affinity_hits = self.metrics.affinity_hits.saturating_add(1);
                return Ok(DispatchDecision {
                    worker_id: entry.worker_id,
                    kind: DispatchKind::AffinityHit,
                });
            }

            let Some(worker_id) = choose_worker(key, workers) else {
                self.metrics.no_eligible_worker = self.metrics.no_eligible_worker.saturating_add(1);
                return Err(DispatchError::NoEligibleWorkers);
            };
            entry.worker_id = worker_id;
            entry.last_seen_ns = now_ns;
            self.entries[index] = Some(entry);
            self.metrics.remaps = self.metrics.remaps.saturating_add(1);
            return Ok(DispatchDecision {
                worker_id,
                kind: DispatchKind::RemappedAfterWorkerLoss,
            });
        }

        let Some(index) = vacant else {
            self.metrics.table_full = self.metrics.table_full.saturating_add(1);
            return Err(DispatchError::FlowTableFull);
        };
        let Some(worker_id) = choose_worker(key, workers) else {
            self.metrics.no_eligible_worker = self.metrics.no_eligible_worker.saturating_add(1);
            return Err(DispatchError::NoEligibleWorkers);
        };

        self.entries[index] = Some(Entry {
            key,
            worker_id,
            last_seen_ns: now_ns,
        });
        self.metrics.new_assignments = self.metrics.new_assignments.saturating_add(1);
        Ok(DispatchDecision {
            worker_id,
            kind: DispatchKind::NewFlow,
        })
    }

    /// Expires at most max_scan table slots, using a persistent scan cursor.
    ///
    /// Call from the shared deadline/event loop. A zero timeout disables expiry.
    pub fn expire_idle(&mut self, now_ns: u64, idle_timeout_ns: u64, max_scan: usize) -> usize {
        if CAPACITY == 0 || idle_timeout_ns == 0 {
            return 0;
        }
        let scan = core::cmp::min(max_scan, CAPACITY);
        let mut expired = 0;

        for _ in 0..scan {
            let index = self.expiry_cursor;
            self.expiry_cursor = (self.expiry_cursor + 1) % CAPACITY;
            if let Some(entry) = self.entries[index] {
                if now_ns >= entry.last_seen_ns && now_ns - entry.last_seen_ns >= idle_timeout_ns {
                    self.entries[index] = None;
                    expired += 1;
                }
            }
        }

        self.metrics.expired_entries = self.metrics.expired_entries.saturating_add(expired as u64);
        expired
    }

    /// Returns the number of currently occupied flow entries.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub const fn metrics(&self) -> DispatchMetrics {
        self.metrics
    }

    /// Counts current flow assignments to one worker for telemetry.
    pub fn assigned_flows(&self, worker_id: u16) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry, Some(value) if value.worker_id == worker_id))
            .count()
    }
}

impl<const CAPACITY: usize> Default for FlowDispatcher<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

fn worker_is_eligible(workers: &[Worker], id: u16) -> bool {
    workers
        .iter()
        .any(|worker| worker.id == id && worker.eligible)
}

fn choose_worker(key: FlowKey, workers: &[Worker]) -> Option<u16> {
    let flow_hash = key.stable_hash();
    let mut selected: Option<(u64, u16)> = None;

    for worker in workers.iter().filter(|worker| worker.eligible) {
        let score = rendezvous_score(flow_hash, worker.id);
        if selected
            .is_none_or(|(best, best_id)| score > best || (score == best && worker.id < best_id))
        {
            selected = Some((score, worker.id));
        }
    }

    selected.map(|(_, id)| id)
}

fn rendezvous_score(flow_hash: u64, worker_id: u16) -> u64 {
    let mut value = flow_hash ^ (u64::from(worker_id) + 0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghoncha_packet::{IpAddress, flow::FlowDiscriminator};

    fn key(port: u16) -> FlowKey {
        FlowKey {
            source: IpAddress::V4([10, 0, 0, 1]),
            destination: IpAddress::V4([10, 0, 0, 2]),
            protocol: 17,
            discriminator: FlowDiscriminator::Ports {
                source: 40000,
                destination: port,
            },
        }
    }

    const WORKERS: [Worker; 3] = [
        Worker {
            id: 10,
            eligible: true,
        },
        Worker {
            id: 20,
            eligible: true,
        },
        Worker {
            id: 30,
            eligible: true,
        },
    ];

    #[test]
    fn repeated_packets_keep_their_worker() {
        let mut dispatcher = FlowDispatcher::<8>::new();
        let first = dispatcher.dispatch(key(53), 10, &WORKERS).unwrap();
        let second = dispatcher.dispatch(key(53), 20, &WORKERS).unwrap();
        assert_eq!(first.kind, DispatchKind::NewFlow);
        assert_eq!(second.kind, DispatchKind::AffinityHit);
        assert_eq!(first.worker_id, second.worker_id);
        assert_eq!(dispatcher.metrics().affinity_hits, 1);
    }

    #[test]
    fn different_flows_can_use_different_workers() {
        let mut dispatcher = FlowDispatcher::<64>::new();
        let mut selected = [false; 3];
        for port in 1..=48 {
            let decision = dispatcher
                .dispatch(key(port), u64::from(port), &WORKERS)
                .unwrap();
            let index = match decision.worker_id {
                10 => 0,
                20 => 1,
                30 => 2,
                _ => panic!("unexpected worker"),
            };
            selected[index] = true;
        }
        assert!(selected.iter().all(|used| *used));
    }

    #[test]
    fn worker_loss_remaps_only_affected_flow() {
        let mut dispatcher = FlowDispatcher::<8>::new();
        let first = dispatcher.dispatch(key(53), 10, &WORKERS).unwrap();
        let reduced = [
            Worker {
                id: 10,
                eligible: false,
            },
            WORKERS[1],
            WORKERS[2],
        ];
        let remapped = dispatcher.dispatch(key(53), 20, &reduced).unwrap();
        assert_eq!(remapped.kind, DispatchKind::RemappedAfterWorkerLoss);
        assert_ne!(first.worker_id, remapped.worker_id);
        assert_eq!(dispatcher.metrics().remaps, 1);
    }

    #[test]
    fn table_is_bounded_until_expiry_runs() {
        let mut dispatcher = FlowDispatcher::<1>::new();
        dispatcher.dispatch(key(1), 1, &WORKERS).unwrap();
        assert_eq!(
            dispatcher.dispatch(key(2), 2, &WORKERS),
            Err(DispatchError::FlowTableFull)
        );
        assert_eq!(dispatcher.expire_idle(100, 10, 1), 1);
        assert!(dispatcher.dispatch(key(2), 101, &WORKERS).is_ok());
    }

    #[test]
    fn no_eligible_worker_is_reported() {
        let mut dispatcher = FlowDispatcher::<2>::new();
        let workers = [Worker {
            id: 1,
            eligible: false,
        }];
        assert_eq!(
            dispatcher.dispatch(key(1), 0, &workers),
            Err(DispatchError::NoEligibleWorkers)
        );
    }

    #[test]
    fn expiry_scan_respects_its_budget() {
        let mut dispatcher = FlowDispatcher::<8>::new();
        for port in 1..=4 {
            dispatcher.dispatch(key(port), 1, &WORKERS).unwrap();
        }
        assert_eq!(dispatcher.expire_idle(100, 10, 2), 2);
        assert_eq!(dispatcher.len(), 2);
    }
}
