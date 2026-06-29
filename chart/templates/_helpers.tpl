{{- define "secret-cert-controller.name" -}}
{{ .Release.Name }}-secret-sync
{{- end }}

{{- define "secret-cert-controller.fullname" -}}
{{ .Release.Name }}-secret-sync
{{- end }}
