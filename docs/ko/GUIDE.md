## 개요

클라우드포레는 Oracle Cloud Infrastructure(OCI) Monitoring과 연동하기 위해 OCI Webhook을 제공하고 있습니다.  
본 가이드는 OCI Monitoring에서 보내는 알람을 클라우드포레로 수신하기 위한 설정 방법을 안내 합니다. 설정 방법은 아래와 같은 순서로 수행합니다.

OCI는 알람 발생 시 외부 시스템과 연동하기 위해 Notification Service를 제공하며,   
이 서비스에 클라우드포레의 Webhook URL을 설정하여 OCI에서 발생하는 알람을 클라우드포레로 전송 가능합니다.

<br>
<br>

## 1. OCI Webhook 생성

클라우드포레에서 OCI Webhook을 생성하면 Webhook URL을 획득할 수 있습니다.

다음 단계를 통해 알아보도록 하겠습니다.

(1) 클라우드포레의 특정 프로젝트에서 [얼럿]을 클릭 합니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[웹훅] 버튼을 클릭하면 현재 생성된 웹훅 목록을 볼 수 있습니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[ + 추가] 버튼을 클릭하여 새로운 OCI Webhook을 생성합니다.

(2) 모달이 열리면 [이름]을 기입하고 [OCI Monitoring Webhook]을 선택 후 [확인] 버튼을 클릭 합니다.

(3) 생성된 OCI Webhook을 확인할 수 있습니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`Webhook URL`은 OCI Notification Service와 연동을 위해 사용됩니다.

<br>
<br>

## 2. OCI Notification Topic 설정

이제 OCI 콘솔에서 Notification Topic을 설정하겠습니다.  
여기서는 이전 단계에서 생성한 Webhook의 URL이 사용될 예정입니다.

(1) OCI 콘솔 로그인 > [Developer Services] > [Application Integration] > [Notifications] > [Create Topic] 버튼을 클릭합니다.

(2) Topic 정보를 입력합니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Name]과 [Description]을 기입하고 [Create] 버튼을 클릭해 Topic을 생성합니다.

(3) 생성된 Topic에서 [Create Subscription] 버튼을 클릭합니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Protocol]은 `HTTPS (Custom URL)`, [URL]은 [1. OCI Webhook 생성] 에서 획득한 Webhook URL을 입력합니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Create] 버튼을 클릭해 Subscription을 생성합니다.

<br>
<br>

## 3. OCI Alarm에 Notification 추가

실제 OCI Alarm에 생성한 Notification Topic을 추가해 보겠습니다.  
사용자 환경에 맞게 사용하고 있는 Alarm에 생성한 Notification Topic을 추가하면 됩니다.

아래는 예시로 1개의 특정 Alarm에 Notification을 추가해보도록 하겠습니다.

(1) OCI 콘솔에서 [Observability & Management] > [Monitoring] > [Alarm Definitions]로 이동합니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;설정할 Alarm을 선택하거나 [Create Alarm] 버튼을 클릭하여 새 Alarm을 생성합니다.

(2) Alarm 설정에서 [Notifications] 섹션을 찾습니다.  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Destination Service]는 `Notifications Service`를 선택하고,  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Topic]에는 이전 단계에서 생성한 Topic을 선택합니다.

(3) [Save alarm] 버튼을 클릭하여 설정을 저장합니다.

이제, 모든 설정은 끝났습니다. **클라우드포레에서 OCI Monitoring의 알람을 수신할 수 있습니다.**

### 추가 정보

- OCI Alarm이 발생하면 Notification Service를 통해 클라우드포레로 알람 데이터가 전송됩니다.
- 알람 데이터에는 `dedupeKey`, `alarmMetaData`, `severity`, `timestamp` 등의 정보가 포함됩니다.
- 클라우드포레는 이 데이터를 파싱하여 SpaceONE 이벤트 모델로 변환합니다.