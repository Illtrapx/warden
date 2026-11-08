//! How many refusals of one kind are written to the audit log one by one.
//!
//! An enrolled agent can be refused as fast as it can call, so past a few a minute
//! only a count is kept, and written later as one entry. Used for refusals to sign
//! commits and to mint GitHub tokens.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use warden_broker_proto::AgentName;

use crate::audit::{AuditEvent, AuditLog};

/// Refusals recorded one by one per agent per minute; the rest are counted.
const REFUSALS_PER_MINUTE: u32 = 30;

/// One agent's refusals in the current minute.
#[derive(Debug, Default)]
struct RefusalMinute {
    started_at: i64,
    written: u32,
    held: u64,
}

/// The refusals of every agent for one kind of call. Enrolled agents are the only
/// callers that get this far, so this holds an entry per enrolled agent at most. In
/// memory: a restart can at worst lose the count of a minute.
#[derive(Debug, Default)]
pub(super) struct RefusalThrottle {
    agents: Mutex<HashMap<AgentName, RefusalMinute>>,
}

impl RefusalThrottle {
    fn lock(&self) -> MutexGuard<'_, HashMap<AgentName, RefusalMinute>> {
        // Every update is a few steps that cannot panic, and at worst this
        // miscounts: the refusal itself has already been decided.
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count a refusal of `agent` at `now`. Whether to record it in full; if not,
    /// it is held for a refusals-held entry.
    fn note(&self, agent: &AgentName, now: i64) -> bool {
        let mut agents = self.lock();
        let minute = agents.entry(agent.clone()).or_default();
        // A clock set back starts a new minute too.
        if now < minute.started_at || now - minute.started_at >= 60 {
            minute.started_at = now;
            minute.written = 0;
        }
        if minute.written < REFUSALS_PER_MINUTE {
            minute.written += 1;
            true
        } else {
            minute.held = minute.held.saturating_add(1);
            false
        }
    }

    /// Take every count held back.
    fn take_held(&self) -> Vec<(AgentName, u64)> {
        self.lock()
            .iter_mut()
            .filter(|(_, minute)| minute.held > 0)
            .map(|(agent, minute)| (agent.clone(), std::mem::take(&mut minute.held)))
            .collect()
    }

    /// Put back `count`, which could not be written.
    fn restore(&self, agent: &AgentName, count: u64) {
        let mut agents = self.lock();
        let minute = agents.entry(agent.clone()).or_default();
        minute.held = minute.held.saturating_add(count);
    }

    /// Write `event` for a refusal of `agent` at `now` if the minute's allowance is
    /// not used up, and count it otherwise. Cannot change the outcome: the agent is
    /// refused already, so a failure to write is logged, as `what`.
    pub(super) async fn record(
        &self,
        audit: &AuditLog,
        agent: &AgentName,
        now: i64,
        event: AuditEvent,
        what: &str,
    ) {
        if !self.note(agent, now) {
            return;
        }
        if let Err(e) = audit.append(event).await {
            tracing::error!(agent = %agent, error = %e, "could not audit {what}");
        }
    }

    /// Write the counts held back since the last time, as the entries `held` makes;
    /// a count that cannot be written is kept for the next time.
    pub(super) async fn flush(
        &self,
        audit: &AuditLog,
        what: &str,
        held: impl Fn(AgentName, u64) -> AuditEvent,
    ) {
        for (agent, count) in self.take_held() {
            if let Err(e) = audit.append(held(agent.clone(), count)).await {
                tracing::error!(agent = %agent, error = %e, "could not audit {what}");
                self.restore(&agent, count);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{REFUSALS_PER_MINUTE, RefusalThrottle};
    use warden_broker_proto::AgentName;

    fn agent(name: &str) -> AgentName {
        name.parse().unwrap()
    }

    #[test]
    fn refusals_beyond_the_limit_are_counted_not_written() {
        let refusals = RefusalThrottle::default();
        let bot = agent("bot");
        assert!(refusals.note(&bot, 1000));
        for _ in 1..REFUSALS_PER_MINUTE {
            assert!(refusals.note(&bot, 1000));
        }
        assert!(!refusals.note(&bot, 1059));
        assert!(!refusals.note(&bot, 1059));
        assert_eq!(refusals.take_held(), [(bot.clone(), 2)]);
        assert_eq!(refusals.take_held(), []);
        // Another agent has its own allowance, and the next minute starts afresh.
        assert!(refusals.note(&agent("other"), 1059));
        assert!(refusals.note(&bot, 1060));
    }

    #[test]
    fn a_count_that_could_not_be_written_is_kept() {
        let refusals = RefusalThrottle::default();
        let bot = agent("bot");
        refusals.restore(&bot, 5);
        assert_eq!(refusals.take_held(), [(bot, 5)]);
    }

    #[test]
    fn a_clock_set_back_starts_a_new_minute() {
        let refusals = RefusalThrottle::default();
        let bot = agent("bot");
        for _ in 0..REFUSALS_PER_MINUTE {
            assert!(refusals.note(&bot, 1000));
        }
        assert!(!refusals.note(&bot, 1000));
        assert!(refusals.note(&bot, 900));
    }
}
