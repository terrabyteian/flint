{{/* The chart name, overridable with nameOverride. */}}
{{- define "flint.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The fully qualified name of the release's resources: the release name, with
the chart name appended unless the release name already contains it.
*/}}
{{- define "flint.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "flint.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "flint.selectorLabels" -}}
app.kubernetes.io/name: {{ include "flint.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "flint.labels" -}}
helm.sh/chart: {{ include "flint.chart" . }}
{{ include "flint.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "flint.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "flint.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "flint.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* The name of the secret holding flint's TLS certificate. */}}
{{- define "flint.tlsSecretName" -}}
{{- if .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else }}
{{- default (printf "%s-tls" (include "flint.fullname" .)) .Values.tls.certManager.secretName }}
{{- end }}
{{- end }}

{{/* Fails on contradictory values; included by the StatefulSet. */}}
{{- define "flint.validate" -}}
{{- with .Values.tls }}
{{- if and .enabled .existingSecret .certManager.enabled }}
{{- fail "tls: set either tls.existingSecret or tls.certManager.enabled, not both" }}
{{- end }}
{{- if and .enabled (not .existingSecret) (not .certManager.enabled) }}
{{- fail "tls.enabled needs a certificate: set tls.existingSecret or enable tls.certManager" }}
{{- end }}
{{- if and .certManager.enabled (not .enabled) }}
{{- fail "tls.certManager.enabled needs tls.enabled" }}
{{- end }}
{{- if and .certManager.enabled (not .certManager.issuerRef.name) }}
{{- fail "tls.certManager.issuerRef.name is required" }}
{{- end }}
{{- end }}
{{- range $field := list "listen" "dataDir" "tls" }}
{{- if hasKey $.Values.config $field }}
{{- fail (printf "config.%s is set by the chart; use containerPort, persistence, and tls instead" $field) }}
{{- end }}
{{- end }}
{{- end }}

{{/* flint's JSON configuration: the config value plus the fields the chart owns. */}}
{{- define "flint.config" -}}
{{- $config := deepCopy .Values.config }}
{{- $_ := set $config "listen" (printf ":%d" (int .Values.containerPort)) }}
{{- $_ = set $config "dataDir" "/var/lib/flint" }}
{{- if .Values.tls.enabled }}
{{- $_ = set $config "tls" (dict "certFile" "/etc/flint/tls/tls.crt" "keyFile" "/etc/flint/tls/tls.key") }}
{{- end }}
{{- toPrettyJson $config }}
{{- end }}
