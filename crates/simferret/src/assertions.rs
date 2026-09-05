use serde::{Deserialize, Serialize};

use crate::protocol::{Event, EventFrame, RequestPhase};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionReport {
    pub passed: bool,
    pub assertions: Vec<AssertionResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionResult {
    pub name: AssertionName,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionName {
    Safety,
    ControlledOutage,
    BoundedLiveness,
}

impl AssertionReport {
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.passed)
    }
}

pub fn evaluate(
    events: &[EventFrame],
    outage_event_bound: u64,
    liveness_event_bound: u64,
) -> AssertionReport {
    let safety_failure = events.iter().find_map(|frame| match &frame.event {
        Event::RequestSucceeded {
            request_id,
            request_payload,
            response_id,
            response_payload,
            ..
        } if request_id != response_id || request_payload != response_payload => Some(format!(
            "response event {} contains a mismatched request id or payload",
            frame.event_id
        )),
        _ => None,
    });
    let safety = match safety_failure {
        Some(detail) => result(AssertionName::Safety, false, detail),
        None => result(
            AssertionName::Safety,
            true,
            "all successful responses matched their requests",
        ),
    };

    let outage = events.iter().find_map(|attempt| match &attempt.event {
        Event::RequestAttempted {
            request_id,
            phase: RequestPhase::Stopped,
            ..
        } if during_observed_outage(events, attempt.event_id) => {
            events.iter().find_map(|outcome| match &outcome.event {
                Event::RequestUnavailable {
                    request_id: outcome_id,
                    phase: RequestPhase::Stopped,
                } if outcome_id == request_id
                    && outcome.command_id == attempt.command_id
                    && outcome.event_id >= attempt.event_id
                    && outcome.event_id - attempt.event_id <= outage_event_bound =>
                {
                    Some((attempt.event_id, outcome.event_id - attempt.event_id))
                }
                _ => None,
            })
        }
        _ => None,
    });
    let controlled_outage = match outage {
        Some((attempt_id, distance)) => result(
            AssertionName::ControlledOutage,
            true,
            format!("request event {attempt_id} was unavailable after {distance} event(s)"),
        ),
        None => result(
            AssertionName::ControlledOutage,
            false,
            format!(
                "no stopped-phase request became unavailable within {outage_event_bound} event(s)"
            ),
        ),
    };

    let restart_event_id = events.iter().find_map(|frame| match frame.event {
        Event::ServerStarted { .. }
            if events.iter().any(|earlier| {
                earlier.event_id < frame.event_id
                    && matches!(earlier.event, Event::ServerStopped {})
            }) =>
        {
            Some(frame.event_id)
        }
        _ => None,
    });
    let live_response = restart_event_id.and_then(|restart_id| {
        events.iter().find_map(|frame| match &frame.event {
            Event::RequestSucceeded {
                request_id,
                request_payload,
                response_id,
                response_payload,
                phase: RequestPhase::Restarted,
            } if request_id == response_id
                && request_payload == response_payload
                && frame.event_id >= restart_id
                && frame.event_id - restart_id <= liveness_event_bound =>
            {
                Some((frame.event_id, frame.event_id - restart_id))
            }
            _ => None,
        })
    });
    let bounded_liveness = match live_response {
        Some((response_id, distance)) => result(
            AssertionName::BoundedLiveness,
            true,
            format!("response event {response_id} succeeded after {distance} event(s)"),
        ),
        None => result(
            AssertionName::BoundedLiveness,
            false,
            format!(
                "no matching restarted-phase response arrived within {liveness_event_bound} event(s)"
            ),
        ),
    };

    let assertions = vec![safety, controlled_outage, bounded_liveness];
    AssertionReport {
        passed: assertions.iter().all(|assertion| assertion.passed),
        assertions,
    }
}

fn result(name: AssertionName, passed: bool, detail: impl Into<String>) -> AssertionResult {
    AssertionResult {
        name,
        passed,
        detail: detail.into(),
    }
}

fn during_observed_outage(events: &[EventFrame], event_id: u64) -> bool {
    let latest_lifecycle_event = events
        .iter()
        .filter(|frame| frame.event_id < event_id)
        .filter(|frame| {
            matches!(
                frame.event,
                Event::ServerStarted { .. } | Event::ServerStopped {}
            )
        })
        .max_by_key(|frame| frame.event_id);
    matches!(
        latest_lifecycle_event.map(|frame| &frame.event),
        Some(Event::ServerStopped {})
    )
}

#[cfg(test)]
mod tests {
    use crate::protocol::{DiagnosticFields, MAX_FRAME_LENGTH, PROTOCOL_VERSION};

    use super::*;

    fn frame(event_id: u64, event: Event) -> EventFrame {
        EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id,
            command_id: event_id,
            event,
            diagnostics: DiagnosticFields::default(),
        }
    }

    fn passing_events() -> Vec<EventFrame> {
        let mut events = vec![
            frame(
                1,
                Event::ServerStarted {
                    address: "127.0.0.1:1".into(),
                    corrupt_responses: false,
                },
            ),
            frame(2, Event::ServerStopped {}),
            frame(
                3,
                Event::RequestAttempted {
                    request_id: "outage".into(),
                    payload: "payload".into(),
                    phase: RequestPhase::Stopped,
                },
            ),
            frame(
                4,
                Event::RequestUnavailable {
                    request_id: "outage".into(),
                    phase: RequestPhase::Stopped,
                },
            ),
            frame(
                5,
                Event::ServerStarted {
                    address: "127.0.0.1:1".into(),
                    corrupt_responses: false,
                },
            ),
            frame(
                6,
                Event::RequestSucceeded {
                    request_id: "live".into(),
                    request_payload: "ok".into(),
                    response_id: "live".into(),
                    response_payload: "ok".into(),
                    phase: RequestPhase::Restarted,
                },
            ),
        ];
        events[3].command_id = events[2].command_id;
        events
    }

    #[test]
    fn all_three_properties_pass() {
        let report = evaluate(&passing_events(), 1, 1);
        assert!(report.passed);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn stopped_attempt_and_bounded_unavailable_result_are_both_required() {
        let mut events = passing_events();
        events.remove(2);
        let report = evaluate(&events, 1, 1);
        assert!(!report.assertions[1].passed);

        let report = evaluate(&passing_events(), 0, 1);
        assert!(!report.assertions[1].passed);

        let mut events = passing_events();
        events.remove(1);
        let report = evaluate(&events, 1, 1);
        assert!(!report.assertions[1].passed);
    }

    #[test]
    fn corruption_fails_safety_and_produces_nonzero_result() {
        let mut events = passing_events();
        events.push(frame(
            7,
            Event::RequestSucceeded {
                request_id: "bad".into(),
                request_payload: "expected".into(),
                response_id: "bad".into(),
                response_payload: "corrupt".into(),
                phase: RequestPhase::Running,
            },
        ));
        let report = evaluate(&events, 1, 1);
        assert!(!report.assertions[0].passed);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn liveness_requires_restart_and_matching_success_within_bound() {
        let mut no_restart = passing_events();
        no_restart.remove(4);
        assert!(!evaluate(&no_restart, 1, 1).assertions[2].passed);

        let mut unavailable = passing_events();
        unavailable[5].event = Event::RequestUnavailable {
            request_id: "live".into(),
            phase: RequestPhase::Restarted,
        };
        assert!(!evaluate(&unavailable, 1, 1).assertions[2].passed);

        assert!(!evaluate(&passing_events(), 1, 0).assertions[2].passed);
        assert!(evaluate(&passing_events(), 1, 1).assertions[2].passed);
    }

    #[test]
    fn assertion_report_is_representable_for_maximum_escaped_request_ids() {
        let id = "\u{1f}".repeat(crate::protocol::MAX_REQUEST_DATA_LENGTH - 1);
        let mut events = vec![
            frame(
                1,
                Event::RequestSucceeded {
                    request_id: format!("{id}a"),
                    request_payload: String::new(),
                    response_id: format!("{id}a"),
                    response_payload: "corrupted".into(),
                    phase: RequestPhase::Running,
                },
            ),
            frame(2, Event::ServerStopped {}),
            frame(
                3,
                Event::RequestAttempted {
                    request_id: format!("{id}b"),
                    payload: String::new(),
                    phase: RequestPhase::Stopped,
                },
            ),
            frame(
                4,
                Event::RequestUnavailable {
                    request_id: format!("{id}b"),
                    phase: RequestPhase::Stopped,
                },
            ),
            frame(
                5,
                Event::ServerStarted {
                    address: "127.0.0.1:1".into(),
                    corrupt_responses: false,
                },
            ),
            frame(
                6,
                Event::RequestSucceeded {
                    request_id: format!("{id}c"),
                    request_payload: String::new(),
                    response_id: format!("{id}c"),
                    response_payload: String::new(),
                    phase: RequestPhase::Restarted,
                },
            ),
        ];
        events[3].command_id = events[2].command_id;
        let report = evaluate(&events, 1, 1);
        let report_event = frame(7, Event::AssertionsEvaluated { report });
        assert!(serde_json::to_vec(&report_event).unwrap().len() <= MAX_FRAME_LENGTH);
    }
}
