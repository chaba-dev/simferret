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
    let configured = events.iter().find_map(|frame| match &frame.event {
        Event::NetworkConfigured { gateway, .. } => Some((frame.event_id, format!("{gateway}/32"))),
        _ => None,
    });
    let activation = configured.and_then(|(configured_id, expected_peer)| {
        events.iter().find_map(|frame| match &frame.event {
            Event::OutageActivated { peer_cidr, rule }
                if frame.event_id > configured_id
                    && peer_cidr == &expected_peer
                    && rule == &format!("prohibit {expected_peer}") =>
            {
                Some((frame.event_id, peer_cidr))
            }
            _ => None,
        })
    });
    let activation_id = activation.map(|(event_id, _)| event_id);
    let restoration_id = activation.and_then(|(activation_id, activated_peer)| {
        events.iter().find_map(|frame| match &frame.event {
            Event::NetworkRestored { peer_cidr }
                if frame.event_id > activation_id && peer_cidr == activated_peer =>
            {
                Some(frame.event_id)
            }
            _ => None,
        })
    });
    let mismatch = events.iter().find_map(|frame| match &frame.event {
        Event::RequestSucceeded { .. } if matching_success_attempt(events, frame).is_none() => {
            Some(format!(
                "response event {} does not match its request attempt",
                frame.event_id
            ))
        }
        Event::RequestUnavailable {
            error: RequestError::InvalidResponse,
            ..
        } => Some(format!(
            "request event {} received a non-canonical response",
            frame.event_id
        )),
        _ => None,
    });
    let pre_outage = activation_id.and_then(|activation_id| {
        events.iter().find(|outcome| {
            matches!(
                outcome.event,
                Event::RequestSucceeded {
                    phase: RequestPhase::PreOutage,
                    ..
                }
            ) && outcome.event_id < activation_id
                && matching_success_attempt(events, outcome)
                    .is_some_and(|attempt| attempt.event_id < activation_id)
        })
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

    let outage = activation_id
        .zip(restoration_id)
        .and_then(|(activation_id, restoration_id)| {
            events.iter().find_map(|attempt| match &attempt.event {
                Event::RequestAttempted {
                    request_id,
                    phase: RequestPhase::Outage,
                    ..
                } if attempt.event_id > activation_id && attempt.event_id < restoration_id => {
                    events.iter().find_map(|outcome| match &outcome.event {
                        Event::RequestUnavailable {
                            request_id: outcome_id,
                            phase: RequestPhase::Outage,
                            error: RequestError::AdministrativeProhibited,
                            errno: Some(libc::EACCES),
                        } if outcome_id == request_id
                            && outcome.command_id == attempt.command_id
                            && outcome.event_id > attempt.event_id
                            && outcome.event_id < restoration_id
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
        events.iter().find_map(|outcome| match &outcome.event {
            Event::RequestSucceeded {
                phase: RequestPhase::Recovery,
                ..
            } if outcome.event_id > restoration_id
                && outcome.event_id - restoration_id <= recovery_event_bound =>
            {
                matching_success_attempt(events, outcome)
                    .filter(|attempt| attempt.event_id > restoration_id)
                    .map(|_| (outcome.event_id, outcome.event_id - restoration_id))
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

fn matching_success_attempt<'a>(
    events: &'a [EventFrame],
    outcome: &EventFrame,
) -> Option<&'a EventFrame> {
    let Event::RequestSucceeded {
        request_id,
        request_payload,
        response_id,
        response_payload,
        phase,
    } = &outcome.event
    else {
        return None;
    };
    if request_id != response_id || request_payload != response_payload {
        return None;
    }
    events.iter().find(|attempt| {
        matches!(
            &attempt.event,
            Event::RequestAttempted {
                request_id: attempted_id,
                payload,
                phase: attempted_phase,
            } if attempted_id == request_id
                && payload == request_payload
                && attempted_phase == phase
                && attempt.command_id == outcome.command_id
                && attempt.event_id < outcome.event_id
        )
    })
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
                Event::RequestAttempted {
                    request_id: "before".into(),
                    payload: "ok".into(),
                    phase: RequestPhase::PreOutage,
                },
            ),
            frame(
                3,
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
                4,
                3,
                Event::OutageActivated {
                    peer_cidr: "10.0.2.2/32".into(),
                    rule: "prohibit 10.0.2.2/32".into(),
                },
            ),
            frame(
                5,
                4,
                Event::RequestAttempted {
                    request_id: "during".into(),
                    payload: "x".into(),
                    phase: RequestPhase::Outage,
                },
            ),
            frame(
                6,
                4,
                Event::RequestUnavailable {
                    request_id: "during".into(),
                    phase: RequestPhase::Outage,
                    error: RequestError::AdministrativeProhibited,
                    errno: Some(libc::EACCES),
                },
            ),
            frame(
                7,
                5,
                Event::NetworkRestored {
                    peer_cidr: "10.0.2.2/32".into(),
                },
            ),
            frame(
                8,
                6,
                Event::RequestAttempted {
                    request_id: "after".into(),
                    payload: "ok".into(),
                    phase: RequestPhase::Recovery,
                },
            ),
            frame(
                9,
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
        if let Event::RequestUnavailable { error, .. } = &mut wrong_error[5].event {
            *error = RequestError::Transport;
        }
        assert!(!evaluate(&wrong_error, 1, 2).assertions[1].passed);
    }

    #[test]
    fn corruption_fails_safety_and_exit_status() {
        let mut events = passing_events();
        if let Event::RequestSucceeded {
            response_payload, ..
        } = &mut events[2].event
        {
            *response_payload = "corrupt".into();
        }
        let report = evaluate(&events, 1, 2);
        assert!(!report.assertions[0].passed);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn pre_outage_success_must_precede_activation() {
        let mut events = passing_events();
        let mut pre_outage = events.remove(2);
        pre_outage.event_id = 10;
        events.push(pre_outage);
        assert!(!evaluate(&events, 1, 2).assertions[0].passed);
    }

    #[test]
    fn outage_result_must_precede_restoration() {
        let mut events = passing_events();
        events[4].event_id = 6;
        events[5].event_id = 7;
        events[6].event_id = 5;
        assert!(!evaluate(&events, 1, 2).assertions[1].passed);
    }

    #[test]
    fn recovery_requires_a_matching_post_restoration_attempt() {
        let mut events = passing_events();
        events.remove(7);
        assert!(!evaluate(&events, 1, 2).assertions[3].passed);
    }

    #[test]
    fn malformed_response_is_a_safety_failure() {
        let mut events = passing_events();
        events.push(frame(
            10,
            7,
            Event::RequestUnavailable {
                request_id: "malformed".into(),
                phase: RequestPhase::Recovery,
                error: RequestError::InvalidResponse,
                errno: None,
            },
        ));
        assert!(!evaluate(&events, 1, 2).assertions[0].passed);
    }

    #[test]
    fn outcomes_must_follow_and_match_their_request_attempts() {
        let mut wrong_pre_outage_command = passing_events();
        wrong_pre_outage_command[2].command_id = 99;
        assert!(!evaluate(&wrong_pre_outage_command, 1, 2).assertions[0].passed);

        let mut simultaneous_outage_result = passing_events();
        simultaneous_outage_result[5].event_id = simultaneous_outage_result[4].event_id;
        assert!(!evaluate(&simultaneous_outage_result, 1, 2).assertions[1].passed);

        let mut wrong_recovery_payload = passing_events();
        if let Event::RequestAttempted { payload, .. } = &mut wrong_recovery_payload[7].event {
            *payload = "different".into();
        }
        assert!(!evaluate(&wrong_recovery_payload, 1, 2).assertions[3].passed);
    }

    #[test]
    fn every_success_must_match_its_request_attempt() {
        let mut events = passing_events();
        events.push(frame(
            10,
            7,
            Event::RequestAttempted {
                request_id: "extra".into(),
                payload: "expected".into(),
                phase: RequestPhase::Recovery,
            },
        ));
        events.push(frame(
            11,
            7,
            Event::RequestSucceeded {
                request_id: "extra".into(),
                request_payload: "different".into(),
                response_id: "extra".into(),
                response_payload: "different".into(),
                phase: RequestPhase::Recovery,
            },
        ));
        assert!(!evaluate(&events, 1, 2).assertions[0].passed);
    }

    #[test]
    fn transitions_must_match_the_configured_peer_and_rule() {
        let mut wrong_restoration = passing_events();
        wrong_restoration[6].event = Event::NetworkRestored {
            peer_cidr: "10.0.2.99/32".into(),
        };
        assert!(!evaluate(&wrong_restoration, 1, 2).assertions[2].passed);

        let mut wrong_activation = passing_events();
        wrong_activation[3].event = Event::OutageActivated {
            peer_cidr: "10.0.2.99/32".into(),
            rule: "prohibit 10.0.2.99/32".into(),
        };
        assert!(!evaluate(&wrong_activation, 1, 2).assertions[1].passed);

        let mut wrong_rule = passing_events();
        wrong_rule[3].event = Event::OutageActivated {
            peer_cidr: "10.0.2.2/32".into(),
            rule: "blackhole 10.0.2.2/32".into(),
        };
        let report = evaluate(&wrong_rule, 1, 2);
        assert!(!report.assertions[1].passed);
        assert!(!report.passed);
    }
}
