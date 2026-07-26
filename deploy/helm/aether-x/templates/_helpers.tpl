{{/*
Common name.
*/}}
{{- define "aetherx.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully-qualified app name (release-aware).
*/}}
{{- define "aetherx.fullname" -}}
{{- if .Values.global.fullnameOverride -}}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.global.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "aetherx.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "aetherx.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aether-x
{{- end -}}

{{/*
Selector labels (name + instance). Per-component disambiguation is added by the
caller via app.kubernetes.io/component.
*/}}
{{- define "aetherx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aetherx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Image reference with optional global registry prefix.
Call: include "aetherx.imageRef" (dict "root" . "image" .Values.X.image)
*/}}
{{- define "aetherx.imageRef" -}}
{{- $root := .root -}}
{{- $image := .image -}}
{{- if $root.Values.global.imageRegistry -}}
{{- printf "%s/%s:%s" $root.Values.global.imageRegistry $image.repository $image.tag -}}
{{- else -}}
{{- printf "%s:%s" $image.repository $image.tag -}}
{{- end -}}
{{- end -}}

{{/*
Render a values sub-map to YAML safely.
*/}}
{{- define "aetherx.render" -}}
{{- toYaml . -}}
{{- end -}}
