use serde::{Deserialize, Serialize};

use crate::protocol::{Event, EventFrame, RequestError, RequestPhase};

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
    Restoration,
    BoundedRecovery,
}

impl AssertionReport {
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.passed)
    }
}

pub fn evaluate(
    events: &[EventFrame],
    outage_event_bound: u64,
    recovery_event_bound: u64,
) -> AssertionReport {
    let mismatch = events.iter().find_map(|frame| match &frame.event {
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
    let pre_outage = events.iter().find(|frame| {
        matches!(
            &frame.event,
            Event::RequestSucceeded {
                request_id,
                request_payload,
                response_id,
                response_payload,
                phase: RequestPhase::PreOutage,
            } if request_id == response_id && request_payload == response_payload
        )
    });
    let safety = if let Some(detail) = mismatch {
        result(AssertionName::Safety, false, detail)
    } else if let Some(frame) = pre_outage {
        result(
            AssertionName::Safety,
            true,
            format!(
                "matching pre-outage response observed at event {}",
                frame.event_id
            ),
        )
    } else {
        result(
            AssertionName::Safety,
            false,
            "no matching pre-outage response traversed the network",
        )
    };

    let activation_id = events.iter().find_map(|frame| {
        matches!(frame.event, Event::OutageActivated { .. }).then_some(frame.event_id)
    });
    let outage = activation_id.and_then(|activation_id| {
        events.iter().find_map(|attempt| match &attempt.event {
            Event::RequestAttempted {
                request_id,
                phase: RequestPhase::Outage,
                ..
            } if attempt.event_id > activation_id => {
                events.iter().find_map(|outcome| match &outcome.event {
                    Event::RequestUnavailable {
                        request_id: outcome_id,
                        phase: RequestPhase::Outage,
                        error: RequestError::AdministrativeProhibited,
                        errno: Some(libc::EACCES),
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
        })
    });
    let controlled_outage = match outage {
        Some((attempt_id, distance)) => result(
            AssertionName::ControlledOutage,
            true,
            format!(
                "request event {attempt_id} was administratively prohibited after {distance} event(s)"
            ),
        ),
        None => result(
            AssertionName::ControlledOutage,
            false,
            format!(
                "no post-activation request reported EACCES within {outage_event_bound} event(s)"
            ),
        ),
    };

    let restoration_id = events.iter().find_map(|frame| match frame.event {
        Event::NetworkRestored { .. }
            if activation_id.is_some_and(|activation_id| frame.event_id > activation_id) =>
        {
            Some(frame.event_id)
        }
        _ => None,
    });
    let restoration = match restoration_id {
        Some(event_id) => result(
            AssertionName::Restoration,
            true,
            format!("network restoration was confirmed at event {event_id}"),
        ),
        None => result(
            AssertionName::Restoration,
            false,
            "network restoration was not confirmed after outage activation",
        ),
    };

    let recovery = restoration_id.and_then(|restoration_id| {
        events.iter().find_map(|frame| match &frame.event {
            Event::RequestSucceeded {
                request_id,
                request_payload,
                response_id,
                response_payload,
                phase: RequestPhase::Recovery,
            } if request_id == response_id
                && request_payload == response_payload
                && frame.event_id > restoration_id
                && frame.event_id - restoration_id <= recovery_event_bound =>
            {
                Some((frame.event_id, frame.event_id - restoration_id))
            }
            _ => None,
        })
    });
    let bounded_recovery = match recovery {
        Some((event_id, distance)) => result(
            AssertionName::BoundedRecovery,
            true,
            format!(
                "matching recovery response event {event_id} arrived after {distance} event(s)"
            ),
        ),
        None => result(
            AssertionName::BoundedRecovery,
            false,
            format!(
                "no matching post-restoration response arrived within {recovery_event_bound} event(s)"
            ),
        ),
    };

    let assertions = vec![safety, controlled_outage, restoration, bounded_recovery];
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

#[cfg(test)]
mod tests {
    use crate::protocol::{DiagnosticFields, PROTOCOL_VERSION};

    use super::*;

    fn frame(event_id: u64, command_id: u64, event: Event) -> EventFrame {
        EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id,
            command_id,
            event,
            diagnostics: DiagnosticFields::default(),
        }
    }

    fn passing_events() -> Vec<EventFrame> {
        vec![
            frame(
                1,
                1,
                Event::NetworkConfigured {
                    interface: "eth0".into(),
                    guest_cidr: "10.0.2.15/24".into(),
                    gateway: "10.0.2.2".into(),
                },
            ),
            frame(
                2,
                2,
                Event::RequestSucceeded {
                    request_id: "before".into(),
                    request_payload: "ok".into(),
                    response_id: "before".into(),
                    response_payload: "ok".into(),
                    phase: RequestPhase::PreOutage,
                },
            ),
            frame(
                3,
                3,
                Event::OutageActivated {
                    peer_cidr: "10.0.2.2/32".into(),
                    rule: "prohibit 10.0.2.2/32".into(),
                },
            ),
            frame(
                4,
                4,
                Event::RequestAttempted {
                    request_id: "during".into(),
                    payload: "x".into(),
                    phase: RequestPhase::Outage,
                },
            ),
            frame(
                5,
                4,
                Event::RequestUnavailable {
                    request_id: "during".into(),
                    phase: RequestPhase::Outage,
                    error: RequestError::AdministrativeProhibited,
                    errno: Some(libc::EACCES),
                },
            ),
            frame(
                6,
                5,
                Event::NetworkRestored {
                    peer_cidr: "10.0.2.2/32".into(),
                },
            ),
            frame(
                7,
                6,
                Event::RequestSucceeded {
                    request_id: "after".into(),
                    request_payload: "ok".into(),
                    response_id: "after".into(),
                    response_payload: "ok".into(),
                    phase: RequestPhase::Recovery,
                },
            ),
        ]
    }

    #[test]
    fn network_properties_pass_only_for_typed_ordered_events() {
        assert!(evaluate(&passing_events(), 1, 2).passed);
        let mut wrong_error = passing_events();
        if let Event::RequestUnavailable { error, .. } = &mut wrong_error[4].event {
            *error = RequestError::Transport;
        }
        assert!(!evaluate(&wrong_error, 1, 2).assertions[1].passed);
    }

    #[test]
    fn corruption_fails_safety_and_exit_status() {
        let mut events = passing_events();
        if let Event::RequestSucceeded {
            response_payload, ..
        } = &mut events[1].event
        {
            *response_payload = "corrupt".into();
        }
        let report = evaluate(&events, 1, 2);
        assert!(!report.assertions[0].passed);
        assert_eq!(report.exit_code(), 1);
    }
}
