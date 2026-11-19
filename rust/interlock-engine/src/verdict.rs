// SPDX-License-Identifier: Apache-2.0

use crate::bind::check_content_bind;
use crate::legs::Session;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Exfil,
    Suspicious,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exfil => "EXFIL",
            Self::Suspicious => "SUSPICIOUS",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Prevented,
    Allowed,
    Contained,
    DetectedOnly,
}

impl Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prevented => "prevented",
            Self::Allowed => "allowed_monitor",
            Self::Contained => "contained_by_kill",
            Self::DetectedOnly => "detected_only",
        }
    }
}

pub fn classify_trip(
    session: &Session,
    has_overlap: bool,
    sink_payload: &[u8],
    has_payload_channel: bool,
    container_aborted: bool,
    content_bind_min_len: usize,
) -> Option<(Verdict, f64)> {
    if has_overlap {
        return Some((Verdict::Exfil, 0.95));
    }
    if session.legs.all_lit()
        && (!has_payload_channel
            || check_content_bind(
                &session.untrusted_excerpts,
                sink_payload,
                content_bind_min_len,
            )
            || container_aborted)
    {
        return Some((Verdict::Suspicious, 0.6));
    }
    None
}

pub fn proxy_action(mode: &str, verdict: Verdict) -> (bool, Action) {
    if verdict == Verdict::Exfil && mode != "monitor" {
        (false, Action::Prevented)
    } else {
        (true, Action::Allowed)
    }
}

pub fn variant_b_action(verdict: Verdict) -> (bool, Action) {
    match verdict {
        Verdict::Exfil => (false, Action::Contained),
        Verdict::Suspicious => (true, Action::DetectedOnly),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_trip_cases() {
        let bound = b"ESCALATE-TICKET-ALPHA-9921-NOW".as_slice();
        let unrelated = b"unrelated payload".as_slice();
        let empty = b"".as_slice();
        let exfil = Some((Verdict::Exfil, 0.95));
        let suspicious = Some((Verdict::Suspicious, 0.6));
        for (all_lit, overlap, payload, channel, aborted, expected) in [
            (false, true, empty, true, false, exfil),
            (true, true, bound, true, true, exfil),
            (false, false, bound, true, true, None),
            (true, false, empty, false, false, suspicious),
            (true, false, bound, true, false, suspicious),
            (true, false, unrelated, true, true, suspicious),
            (true, false, unrelated, true, false, None),
            (true, false, empty, true, false, None),
        ] {
            let mut session = Session::default();
            session.legs.sensitive_source_touched.lit = true;
            session.legs.untrusted_content_present.lit = true;
            session.legs.external_sink_invoked.lit = all_lit;
            session.untrusted_excerpts.push(bound.to_vec());
            assert_eq!(
                classify_trip(&session, overlap, payload, channel, aborted, 0),
                expected,
                "all_lit={all_lit}, overlap={overlap}, payload={payload:?}, channel={channel}, aborted={aborted}"
            );
        }
    }

    #[test]
    fn proxy_action_cases() {
        for (mode, verdict, allow, action) in [
            ("block", Verdict::Exfil, false, Action::Prevented),
            ("monitor", Verdict::Exfil, true, Action::Allowed),
            ("", Verdict::Exfil, false, Action::Prevented),
            ("block", Verdict::Suspicious, true, Action::Allowed),
            ("monitor", Verdict::Suspicious, true, Action::Allowed),
        ] {
            assert_eq!(proxy_action(mode, verdict), (allow, action));
        }
    }

    #[test]
    fn variant_b_action_cases() {
        for (verdict, allow, action) in [
            (Verdict::Exfil, false, Action::Contained),
            (Verdict::Suspicious, true, Action::DetectedOnly),
        ] {
            assert_eq!(variant_b_action(verdict), (allow, action));
        }
    }

    #[test]
    fn model_strings() {
        assert_eq!(Verdict::Exfil.as_str(), "EXFIL");
        assert_eq!(Verdict::Suspicious.as_str(), "SUSPICIOUS");
        assert_eq!(Action::Prevented.as_str(), "prevented");
        assert_eq!(Action::Allowed.as_str(), "allowed_monitor");
        assert_eq!(Action::Contained.as_str(), "contained_by_kill");
        assert_eq!(Action::DetectedOnly.as_str(), "detected_only");
    }
}
