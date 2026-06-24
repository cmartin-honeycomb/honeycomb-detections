# Honeycomb Detections (Okta)

Honeycomb query specs ported from the Panther Okta detection rules in the
[panther-analysis](https://github.com/cmartin-honeycomb/panther-analysis) repo
(`rules/okta_rules/`), targeting the `okta` dataset in the `okta` Honeycomb
environment (team "Honeycomb Security"). Each detection links back to its
original `.py`/`.yml` source upstream.

Each spec is a JSON file containing a Honeycomb query spec (`query_spec`) plus
metadata and validation notes. To operationalize a detection, run its
`query_spec` as a Honeycomb **Trigger** on the rule's frequency and alert when
`COUNT > 0` (or an appropriate threshold). The Panther `title` / `alert_context`
fields are surfaced as `breakdowns` so the alert carries context.

## Inclusion criterion: portability, not current volume

A detection is included if its **logic can be expressed** against fields that
exist in the Honeycomb schema. Whether the triggering events exist in the tenant
*right now* is recorded in the `status` column, not used to exclude anything.
Rare, currently-zero events (org-wide MFA disable, admin impersonation, token
reuse, IdP creation) are often the highest-value detections precisely because
they are rare and significant - so they ship pre-staged and ready to fire.

### Status legend

| status | meaning |
| --- | --- |
| `validated` | Spec executed against live data and returns matching events. |
| `present` | Triggering event type confirmed present in the tenant. |
| `present_base` | Base event type present; a narrowing sub-filter (specific target/reason) is expected to be rarer and was not separately counted. |
| `dormant` | Portable; zero triggering events in the last 90 days. Will fire when one occurs. |
| `*_degraded` | Portable, but some Panther context/logic depends on a field that is not ingested (noted per file). The core trigger still works. |
| `needs_config` | Template; requires an environment-specific value before deploying. |

## Detections

| Detection | Original | Status | 90d hits | Comments |
| --- | --- | --- | --- | --- |
| [okta_login_signal](./okta_login_signal.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_login_signal.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_login_signal.yml) | present | ~16k | Signal/building block, not a standalone alert. Ports 1:1. |
| [okta_sso_to_aws](./okta_sso_to_aws.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_sso_to_aws.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_sso_to_aws.yml) | validated | 2,510 | Calculated field ORs the positionally-flattened `okta.target.N.displayName` to reproduce the Panther `deep_walk` membership test. |
| [okta_user_mfa_reset](./okta_user_mfa_reset.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_user_mfa_reset.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_user_mfa_reset.yml) | validated | 56 | UDM `MFA_RESET` resolved via [okta_data_model.py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/data_models/okta_data_model.py): factor deactivate/suspend with reason starting `User reset`. |
| [okta_rate_limits](./okta_rate_limits.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_rate_limits.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_rate_limits.yml) | present | 46 | Matches `*limit*violation*` events. Panther's `warning`/`exceeded` variants never actually match (rule requires `violation` in eventType). |
| [okta_admin_role_assigned](./okta_admin_role_assigned.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_admin_role_assigned.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_admin_role_assigned.yml) | validated | 16 | `debugContext.debugData.privilegeGranted` not ingested; reconstructed by regex-matching the granted role in `okta.target.N.displayName`. 16/18 match (the 2 misses are custom "Admin" roles the regex also excludes). |
| [okta_app_unauthorized_access_attempt](./okta_app_unauthorized_access_attempt.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_app_unauthorized_access_attempt.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_app_unauthorized_access_attempt.yml) | present | 459 | `target[0].alternateId` not ingested; degraded to `okta.target.0.displayName`. |
| [okta_org2org_creation_modification](./okta_org2org_creation_modification.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_org2org_creation_modification.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_org2org_creation_modification.yml) | present_base | base 192 | `application.lifecycle.*` present; Org2Org-target subset rarer. Calculated field CONTAINS "Org2Org" across target display names. Org2Org is a persistence/lateral-movement vector. |
| [okta_password_extraction_via_scim](./okta_password_extraction_via_scim.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_password_extraction_via_scim.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_password_extraction_via_scim.yml) | present_base | base 177 | `application.lifecycle.update` present; narrowed by `okta.outcome.reason` containing "Pushing user passwords". |
| [okta_phishing_attempt_blocked_by_fastpass](./okta_phishing_attempt_blocked_by_fastpass.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_phishing_attempt_blocked_by_fastpass.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_phishing_attempt_blocked_by_fastpass.yml) | dormant | 0 | Spec validated; no FastPass phishing blocks occurred. Quiet by design for a rare security signal. |
| [okta_admin_disabled_mfa](./okta_admin_disabled_mfa.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_admin_disabled_mfa.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_admin_disabled_mfa.yml) | dormant | 0 | Org-wide MFA disable (`system.mfa.factor.deactivate`), via [okta_data_model.py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/data_models/okta_data_model.py). Rare, high-severity. Distinct from `user.mfa.factor.deactivate` (53 events). |
| [okta_group_admin_role_assigned](./okta_group_admin_role_assigned.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_group_admin_role_assigned.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_group_admin_role_assigned.yml) | dormant | 0 | `group.privilege.grant`. Group-level admin grant, high-impact. Target degraded to display name. |
| [okta_user_mfa_factor_suspend](./okta_user_mfa_factor_suspend.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_user_mfa_factor_suspend.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_user_mfa_factor_suspend.yml) | dormant | 0 | `user.mfa.factor.suspend` + SUCCESS. Target degraded to display name. |
| [okta_idp_signin](./okta_idp_signin.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_idp_signin.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_idp_signin.yml) | dormant | 0 | `user.authentication.auth_via_IDP`. No external IdP federation seen (or not ingested). |
| [okta_idp_create_modify](./okta_idp_create_modify.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_idp_create_modify.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_idp_create_modify.yml) | dormant | 0 | `system.idp.lifecycle.*`. Adding/altering a federation trust - rare and critical. Severity split by action via breakdown. |
| [okta_account_support_access](./okta_account_support_access.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_account_support_access.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_account_support_access.yml) | dormant | 0 | `user.session.impersonation.{grant,initiate}`. Okta Support impersonation - rare, sensitive. |
| [okta_app_refresh_access_token_reuse](./okta_app_refresh_access_token_reuse.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_app_refresh_access_token_reuse.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_app_refresh_access_token_reuse.yml) | dormant | 0 | `app.oauth2.*.token.detect_reuse`. Strong token-theft indicator. |
| [okta_password_accessed](./okta_password_accessed.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_password_accessed.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_password_accessed.yml) | dormant | 0 | `application.user_membership.show_password`. UPGRADED: `okta.target.N.alternateId`/`okta.target.N.type` now ingested, so the actor-not-among-target-Users comparison is reproduced faithfully (was degraded to firing on every event). |
| [okta_threatinsight_security_threat_detected](./okta_threatinsight_security_threat_detected.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_threatinsight_security_threat_detected.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_threatinsight_security_threat_detected.yml) | dormant_degraded | 0 | `security.threat.detected`. Per-threat severity needs `debugData.threatDetections` (not ingested); treat all matches as elevated. |
| [okta_user_reported_suspicious_activity](./okta_user_reported_suspicious_activity.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_user_reported_suspicious_activity.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_user_reported_suspicious_activity.yml) | dormant_degraded | 0 | `user.account.report_suspicious_activity_by_enduser`. Flagged-activity detail needs `debugData.suspiciousActivityEventType` (not ingested); core signal still fires. |
| [okta_support_reset](./okta_support_reset.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_support_reset.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_support_reset.yml) | dormant | 0 | Okta-support-initiated reset signature (system@okta.com, no client context). No occurrences in 90d. |
| [okta_login_without_push_marker](./okta_login_without_push_marker.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_login_without_push_marker.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_login_without_push_marker.yml) | needs_config | n/a | Template: replace placeholder Push marker (`PS_mxzqarw`) with the org's real value before deploying, or it matches nearly all traffic. |
| [okta_anonymizing_vpn_login](./okta_anonymizing_vpn_login.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_anonymizing_vpn_login.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_anonymizing_vpn_login.yml) | validated_degraded | 493 | NEWLY PORTABLE: `okta.security.is_proxy` now ingested. Core rule (`user.session.start` + `isProxy`) ports 1:1. Noisy - volume is mostly legitimate corporate VPN/CDN; tune with `okta.debug.risk` or ASN excludes. Apple Private Relay severity demotion needs `ipinfo_privacy` (not ingested). |
| [okta_new_behavior_accessing_admin_console](./okta_new_behavior_accessing_admin_console.json) | [py](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_new_behavior_accessing_admin_console.py) / [yml](https://github.com/cmartin-honeycomb/panther-analysis/blob/develop/rules/okta_rules/okta_new_behavior_accessing_admin_console.yml) | dormant | 0 | NEWLY PORTABLE: behavior heuristics now ingested. `policy.evaluate_sign_on` to Okta Admin Console with `New Device=POSITIVE` + `New IP=POSITIVE`. On this event type the signal lives in `okta.debug.logOnlySecurityData` (JSON), not the flat `okta.debug.behaviors` - the calc field checks both, matching the Panther fallback. |
| [okta_login_from_blocked_country](./okta_login_from_blocked_country.json) | Honeycomb-native (no Panther equivalent) | needs_config | n/a | Template: replace the `geo.country` deny-list with the org's high-risk/sanctioned countries before deploying. Confirm exact display-name spellings against live data. `in` operator validated on `geo.country`. Pair with `okta_anonymizing_vpn_login` - VPN/proxy egress can mask the apparent country. |

## Notes

- 90d counts are measured against the live tenant; `time_range` in each spec is
  set to `1h` as a Trigger default and should be tuned to the run frequency.
- Several specs depend on Honeycomb's positional `okta.target.N.*` flattening of
  the Okta target array (`sso_to_aws`, `admin_role_assigned`,
  `org2org_creation_modification`, and the `target.0.displayName` degrades). If
  the Okta -> Honeycomb ingestion ever changes how the target array is flattened,
  these target-index expressions are the ones to revisit.
- `dormant` / `*_degraded` detections at zero volume are not errors - they are
  staged coverage. Where status is `*_degraded`, the missing field
  (`debugContext.debugData.*`, `target[].alternateId`) is a candidate to add to
  the ingestion pipeline to restore full fidelity.

## Not ported (logic not expressible as a single Honeycomb query)

These require state, enrichment, or precomputed fields a stateless Honeycomb
query cannot provide, and are intentionally excluded:

- `okta_potentially_stolen_session` - the building-block fields are now ingested (`okta.debug.dtHash`, `okta.session.id`, `okta.client.id`, `net.peer.as.number`), but a faithful port still needs cross-event session state (compare a session fingerprint against a previously stored one) and fuzzy user-agent matching (`SequenceMatcher` ratio < 0.95), neither of which a single stateless query expresses. A heuristic variant - group by `okta.session.id` + `okta.debug.dtHash` and flag `COUNT_DISTINCT(net.peer.ip) > 1` within a window - is now possible but is not equivalent to the Panther logic.
- `okta_ad_agent_auth_zscore_anomaly`, `okta_ad_agent_token_abuse_behavioral`, `okta_skeleton_key_bypass_behavioral`, `okta_swa_bulk_access_behavioral`, `okta_swa_offhours_access_behavioral` - behavioral/ML detections that consume precomputed z-score/anomaly fields from lookup tables.

### Previously not ported, now ported (2026-06-24 schema update)

A schema update added several previously-missing fields. As a result:

- `okta_anonymizing_vpn_login` - now ported (`okta.security.is_proxy` present). Degraded: Apple Private Relay severity demotion still needs `ipinfo_privacy`.
- `okta_new_behavior_accessing_admin_console` - now ported (behavior heuristics present via `okta.debug.logOnlySecurityData`).
- `okta_password_accessed` - upgraded from degraded to faithful (`okta.target.N.alternateId` + `okta.target.N.type` present).

### Still blocked after the update

- `okta_admin_role_assigned` - `debugContext.debugData.privilegeGranted` still not ingested (regex reconstruction retained).
- `okta_app_unauthorized_access_attempt` - `okta.target.0.alternateId` now exists in the schema but is NOT populated for `app.generic.unauth_app_access_attempt` events (0/459), so the title remains degraded to `okta.target.0.displayName`.
- `okta_threatinsight_security_threat_detected` - `debugData.threatDetections` still not ingested.
- `okta_user_reported_suspicious_activity` - `debugData.suspiciousActivityEventType` still not ingested.
