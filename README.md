# plugin-oci-monitoring-mon-webhook
webhook for OCI Monitoring (Operation Suites)

# Data Model

## OCI Monitoring Raw Data

Webhook notification: 

~~~

 {
  "dedupeKey": "6b28ce05-7021-4407-b9c0-xxxxxxx",
  "title": "Notifications",
  "body": "outside 1-10 Alram",
  "type": "OK_TO_FIRING",
  "severity": "CRITICAL",
  "timestampEpochMillis": 1761563100000,
  "timestamp": "2025-10-27T11:05:00Z",
  "alarmMetaData": [
    {
      "id": "ocid1.alarm.oc1.ap-seoul-1.aaaaaaaazxxxxxx",
      "status": "FIRING",
      "severity": "CRITICAL",
      "namespace": "oci_autonomous_database",
      "query": "DatabaseAvailability[5m]{deploymentType = \"Shared\", AutonomousDBType = \"ATP\", region = \"ap-seoul-1\"}.rate() not in (1, 10)",
      "totalMetricsFiring": 1,
      "dimensions": [
        {
          "AutonomousDBType": "ATP",
          "deploymentType": "Shared",
          "resourceId": "OCID1.AUTONOMOUSDATABASE.OC1.AP-SEOUL-1.ANUWGLJRExxxxxx",
          "resourceName": "ARAMCODEVAUTONOMOUS",
          "region": "ap-seoul-1",
          "displayName": "DatabaseAvailability"
        }
      ],
      "alarmUrl": "https://cloud.oracle.com/monitoring/alarms/ocid1.alarm.oc1.ap-seoul-1.aaaaaaaazxxxxxx?region=ap-seoul-1",
      "alarmSummary": "This is aramco_dev_autonomous_database_alarm_1. (DatabaseAvailability)",
      "metricValues": [
        {
          "DatabaseAvailability[5m]{deploymentType = \"Shared\", AutonomousDBType = \"ATP\", region = \"ap-seoul-1\"}.rate()": "0.00"
        }
      ]
    }
  ],
  "notificationType": "Grouped messages across metric streams",
  "version": 1.5
}

~~~

## Event key criteria
Hash key of ```raw_data.dedupeKey```.

## Severity matching information
|OCI Monitoring  ```severity```| SpaceONE Event  ```severity```|
|---|---|
|CRITICAL|CRITICAL|
|ERROR|ERROR|
|WARNING|WARNING|
|INFO|INFO|


## SpaceONE Event Model
| Field		| Type | Description	| Example	|
| ---      | ---     | ---           | ---           |
| event_key | str | raw_data.dedupeKey | 1234 |
| event_type |  str  | raw_data.type | OK_TO_FIRING	|
| title | str	| raw_data.title | Test Incident	|
| description | str | raw_data.body	| Test Incident		|
| severity | str  | raw_data.severity | CRITICAL	|
| resource | dict | Not used		| N/A	|
| raw_data | dict | OCI Monitoring Raw Data | {"title": "Database Size Alert", "dashboardId": 1, ... } |
| addtional_info | dict | raw_data.alarmMetaData.alarmUrl | {"alarm_url" "https://...." } |
| occured_at | datetime | webhook received time | "2021-08-23T06:47:32.753Z" |
| alert_id | str | mapped alert_id	| alert-3243434343 |
| webhook_id | str  | webhook_id	| webhook-34324234234234 |
| project_id | str	| project_id	| project-12312323232    |
| domain_id | str	| domain_id	| domain-12121212121	|
| created_at | datetime | created time | "2021-08-23T06:47:32.753Z"	|

## cURL Requests examples
This topic provides examples of calls to the SpaceONE OCI monitoring webhook using cURL.

Here's a cURL command that works for getting the response from webhook, you can test the following on your local machine.
```
curl -X POST https://your_spaceone_monitoring_webhook_url -d '{
  "dashboardId": xx,
  "evalMatches": [
    {
      "value": xxx,
      "metric": "xxx",
      "tags": {}
    }
  ],
  "ruleUrl": "xxx",
  "imageUrl": "xxx",
  "message": "xxx",
  "orgId": xx,
  "panelId": xx,
  "ruleId": xx,
  "ruleName": "xxx",
  "ruleUrl": "xxx",
  "state": "xxx",
  "tags": {
    "xxx": "xxx"
  },
  "title": "xxx"
}
```

Followings are examples which works for testing your own webhook.

```
curl -X POST https://{your_spaceone_monitoring_oci_webhook_url} -d '{
  "dashboardId": 1,
  "evalMatches": [
    {
      "value": 1,
      "metric": "Count",
      "tags": {}
    }
  ],
  "ruleUrl": "https://grafana.stargate.cloudeco.io/d/6eRS6XR7k/spaceone-dev-cluster-alerts-dashboard-20210621-backup?tab=alert&viewPanel=14&orgId=1",
  "imageUrl": "https://grafana.com/assets/img/blog/mixed_styles.png",
  "message": "Notification Message",
  "orgId": 1,
  "panelId": 2,
  "ruleId": 1,
  "ruleName": "Panel Title alert",
  "ruleUrl": "http://localhost:3000/d/hZ7BuVbWz/test-dashboard?fullscreen\u0026edit\u0026tab=alert\u0026panelId=2\u0026orgId=1",
  "state": "alerting",
  "tags": {
    "tag name": "tag value"
  },
  "title": "[Alerting] Panel Title alert"
}'
```

```
curl -X POST https://monitoring-webhook.dev.spaceone.dev/monitoring/v1/webhook/webhook-1eea0a98d2aa/ed270cc6ea8bb6037313ddbc1e6ee0b3/events -d '{
  "tags": {},
  "orgId": 0.0,
  "state": "alerting",
  "message": "Someone is testing the alert notification within Grafana.",
  "ruleUrl": "https://grafana.stargate.cloudeco.io/",
  "dashboardId": 1.0,
  "title": "[Alerting] Test notification",
  "panelId": 1.0,
  "ruleId": 3.2760766009712717e+18,
  "ruleName": "Test notification",
  "evalMatches": [
      {
          "metric": "High value",
          "tags": null,
          "value": 100.0
      },
      {
          "metric": "Higher Value",
          "value": 200.0,
          "tags": null
      }
  ]
}'
```
