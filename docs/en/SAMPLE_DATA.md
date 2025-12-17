# OCI Alert Fromat

## Alarm
~~~
{
  "dedupeKey": "6b28ce05-7021-4407-b9c0-c5d7896b7361",
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
