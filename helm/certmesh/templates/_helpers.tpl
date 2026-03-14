{{/*
Expand the name of the chart.
*/}}
{{- define "certmesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Applies companyPrefix or resourcePrefix (companyPrefix takes precedence).
*/}}
{{- define "certmesh.fullname" -}}
{{- $prefix := default (default "" .Values.companyPrefix) .Values.resourcePrefix }}
{{- if .Values.fullnameOverride }}
{{- $name := .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- if $prefix }}{{- printf "%s%s" $prefix $name | trunc 63 | trimSuffix "-" }}{{- else }}{{- $name }}{{- end }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- $base := .Release.Name | trunc 63 | trimSuffix "-" }}
{{- if $prefix }}{{- printf "%s%s" $prefix $base | trunc 63 | trimSuffix "-" }}{{- else }}{{- $base }}{{- end }}
{{- else }}
{{- $base := printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- if $prefix }}{{- printf "%s%s" $prefix $base | trunc 63 | trimSuffix "-" }}{{- else }}{{- $base }}{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "certmesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "certmesh.labels" -}}
helm.sh/chart: {{ include "certmesh.chart" . }}
{{ include "certmesh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "certmesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certmesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "certmesh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "certmesh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference
*/}}
{{- define "certmesh.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Default namespace.
Uses companyPrefix + namespace if both are set.
Falls back to Release.Namespace if namespace is empty.
*/}}
{{- define "certmesh.namespace" -}}
{{- if .Values.namespace }}
{{- $prefix := default "" .Values.companyPrefix }}
{{- printf "%s%s" $prefix .Values.namespace | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}
