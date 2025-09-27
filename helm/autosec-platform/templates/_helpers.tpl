{{/*
Expand the name of the chart.
*/}}
{{- define "autosec-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "autosec-platform.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "autosec-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "autosec-platform.labels" -}}
helm.sh/chart: {{ include "autosec-platform.chart" . }}
{{ include "autosec-platform.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "autosec-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "autosec-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "autosec-platform.serviceAccountName" -}}
{{- if .Values.security.serviceAccount.create }}
{{- default (include "autosec-platform.fullname" .) .Values.security.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.security.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the database URL for PostgreSQL
*/}}
{{- define "autosec-platform.postgresql.url" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "autosec-platform.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalDatabase.url }}
{{- end }}
{{- end }}

{{/*
Create the MongoDB URL
*/}}
{{- define "autosec-platform.mongodb.url" -}}
{{- if .Values.mongodb.enabled }}
{{- printf "mongodb://%s:%s@%s-mongodb:27017/%s" .Values.mongodb.auth.username .Values.mongodb.auth.password (include "autosec-platform.fullname" .) .Values.mongodb.auth.database }}
{{- else }}
{{- .Values.externalMongodb.url }}
{{- end }}
{{- end }}

{{/*
Create the Redis URL
*/}}
{{- define "autosec-platform.redis.url" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://:%s@%s-redis-master:6379" .Values.redis.auth.password (include "autosec-platform.fullname" .) }}
{{- else }}
{{- .Values.externalRedis.url }}
{{- end }}
{{- end }}

{{/*
Create the RabbitMQ URL
*/}}
{{- define "autosec-platform.rabbitmq.url" -}}
{{- if .Values.rabbitmq.enabled }}
{{- printf "amqp://%s:%s@%s-rabbitmq:5672" .Values.rabbitmq.auth.username .Values.rabbitmq.auth.password (include "autosec-platform.fullname" .) }}
{{- else }}
{{- .Values.externalRabbitmq.url }}
{{- end }}
{{- end }}