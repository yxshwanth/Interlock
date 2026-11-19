// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Leg {
    pub lit: bool,
    pub trigger_seq: u64,
    pub detail: String,
    pub lit_at_ns: i64,
    pub events_at_lit: u64,
}

#[derive(Debug, Default)]
pub struct TrifectaLegs {
    pub sensitive_source_touched: Leg,
    pub untrusted_content_present: Leg,
    pub external_sink_invoked: Leg,
}

impl TrifectaLegs {
    pub fn all_lit(&self) -> bool {
        self.sensitive_source_touched.lit
            && self.untrusted_content_present.lit
            && self.external_sink_invoked.lit
    }
}

#[derive(Debug, Default)]
pub struct LegPolicy {
    pub ttl_ns: i64,
    pub decay_after_calls: u32,
}

pub trait Clock {
    fn now_ns(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos() as i64,
            Err(error) => (error.duration().as_nanos() as i64).wrapping_neg(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Session {
    pub legs: TrifectaLegs,
    pub event_count: u64,
    pub last_activity_ns: i64,
    pub timeline: Vec<u64>,
    pub timeline_labels: HashMap<u64, String>,
    pub untrusted_excerpts: Vec<Vec<u8>>,
}

impl Session {
    pub fn touch_session(&mut self, seq: u64, label: &str, policy: &LegPolicy, clock: &impl Clock) {
        let now_ns = clock.now_ns();
        self.last_activity_ns = now_ns;
        self.event_count = self.event_count.wrapping_add(1);
        self.prune_legs(now_ns, policy);
        if seq != 0 {
            self.timeline.push(seq);
            if !label.is_empty() && !label.starts_with(' ') {
                self.timeline_labels.insert(seq, label.to_owned());
            }
        }
    }

    pub fn prune_legs(&mut self, now_ns: i64, policy: &LegPolicy) {
        for leg in [
            &mut self.legs.sensitive_source_touched,
            &mut self.legs.external_sink_invoked,
        ] {
            maybe_decay_leg(leg, self.event_count, now_ns, policy);
        }
        if maybe_decay_leg(
            &mut self.legs.untrusted_content_present,
            self.event_count,
            now_ns,
            policy,
        ) {
            self.untrusted_excerpts.clear();
        }
    }

    pub fn rewind_leg_clocks(&mut self, delta_ns: i64) {
        if delta_ns <= 0 {
            return;
        }
        for leg in [
            &mut self.legs.sensitive_source_touched,
            &mut self.legs.untrusted_content_present,
            &mut self.legs.external_sink_invoked,
        ] {
            if leg.lit {
                leg.lit_at_ns = leg.lit_at_ns.saturating_sub(delta_ns).max(1);
            }
        }
    }
}

fn maybe_decay_leg(leg: &mut Leg, event_count: u64, now_ns: i64, policy: &LegPolicy) -> bool {
    if !leg.lit {
        return false;
    }
    let ttl_expired = policy.ttl_ns > 0
        && leg.lit_at_ns > 0
        && now_ns.wrapping_sub(leg.lit_at_ns) >= policy.ttl_ns;
    let calls_expired = policy.decay_after_calls > 0
        && leg.events_at_lit > 0
        && event_count > leg.events_at_lit
        && event_count - leg.events_at_lit >= u64::from(policy.decay_after_calls);
    if ttl_expired || calls_expired {
        *leg = Leg::default();
    }
    ttl_expired || calls_expired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{classify_trip, Verdict};
    use std::cell::Cell;

    #[derive(Default)]
    struct TestClock(Cell<i64>);

    impl TestClock {
        fn set(&self, now_ns: i64) {
            self.0.set(now_ns);
        }
    }

    impl Clock for TestClock {
        fn now_ns(&self) -> i64 {
            self.0.get()
        }
    }

    fn lit_leg(session: &Session) -> Leg {
        Leg {
            lit: true,
            trigger_seq: 1,
            detail: "ticket".into(),
            lit_at_ns: session.last_activity_ns,
            events_at_lit: session.event_count,
        }
    }

    // Port of TestEngine_LegDecay_NCall.
    #[test]
    fn leg_decay_n_call() {
        let clock = TestClock::default();
        clock.set(10);
        let policy = LegPolicy {
            decay_after_calls: 3,
            ..LegPolicy::default()
        };
        let mut session = Session::default();
        session.touch_session(1, "read_ticket", &policy, &clock);
        session.legs.sensitive_source_touched = lit_leg(&session);
        session.legs.untrusted_content_present = lit_leg(&session);
        session.untrusted_excerpts.push(b"page".to_vec());
        session.legs.external_sink_invoked = Leg {
            events_at_lit: 0,
            ..lit_leg(&session)
        };

        for seq in 2..4 {
            session.touch_session(seq, "fetch_page", &policy, &clock);
            assert!(session.legs.sensitive_source_touched.lit);
            assert_eq!(session.untrusted_excerpts, [b"page".to_vec()]);
        }
        session.touch_session(4, "fetch_page", &policy, &clock);
        assert_eq!(session.legs.sensitive_source_touched, Leg::default());
        assert_eq!(session.legs.untrusted_content_present, Leg::default());
        assert!(session.untrusted_excerpts.is_empty());
        assert!(session.legs.external_sink_invoked.lit);
        assert_eq!(
            classify_trip(&session, true, b"", true, false, 0),
            Some((Verdict::Exfil, 0.95))
        );
    }

    // Port of TestEngine_LegDecay_TTL.
    #[test]
    fn leg_decay_ttl() {
        let clock = TestClock::default();
        clock.set(10);
        let policy = LegPolicy {
            ttl_ns: 1,
            ..LegPolicy::default()
        };
        let mut session = Session::default();
        session.touch_session(1, "read_ticket", &policy, &clock);
        session.legs.sensitive_source_touched = lit_leg(&session);
        session.prune_legs(clock.now_ns(), &policy);
        assert!(session.legs.sensitive_source_touched.lit);
        clock.set(11);
        session.touch_session(2, "fetch_page", &policy, &clock);
        assert_eq!(session.legs.sensitive_source_touched, Leg::default());
        assert_eq!(session.last_activity_ns, 11);
    }

    // Port of TestEngine_LegsAreSticky.
    #[test]
    fn legs_are_sticky() {
        let clock = TestClock::default();
        clock.set(10);
        let policy = LegPolicy::default();
        let mut session = Session::default();
        session.touch_session(1, "read_ticket", &policy, &clock);
        session.legs.sensitive_source_touched = lit_leg(&session);
        clock.set(20);
        session.touch_session(2, "send_message", &policy, &clock);
        assert!(session.legs.sensitive_source_touched.lit);
        assert_eq!(session.legs.sensitive_source_touched.trigger_seq, 1);
    }

    #[test]
    fn rewind_leg_clocks_clamps_lit_legs() {
        let mut session = Session {
            last_activity_ns: 10,
            ..Session::default()
        };
        session.legs.sensitive_source_touched = lit_leg(&session);
        session.legs.external_sink_invoked = lit_leg(&session);
        session.rewind_leg_clocks(-2);
        assert_eq!(session.legs.sensitive_source_touched.lit_at_ns, 10);
        session.rewind_leg_clocks(2);
        assert_eq!(session.legs.sensitive_source_touched.lit_at_ns, 8);
        session.legs.external_sink_invoked.lit_at_ns = 7;
        session.rewind_leg_clocks(8);
        assert_eq!(session.legs.sensitive_source_touched.lit_at_ns, 1);
        assert_eq!(session.legs.external_sink_invoked.lit_at_ns, 1);
        assert_eq!(session.legs.untrusted_content_present, Leg::default());
    }
}
