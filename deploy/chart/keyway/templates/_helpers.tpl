{{- define "keyway.fullname" -}}
{{- if contains "keyway" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-keyway" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "keyway.dashboard.fullname" -}}
{{- printf "%s-dashboard" (include "keyway.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "keyway.labels" -}}
app.kubernetes.io/name: keyway
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "keyway.selectorLabels" -}}
app.kubernetes.io/name: keyway
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "keyway.dashboard.selectorLabels" -}}
app.kubernetes.io/name: keyway-dashboard
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
